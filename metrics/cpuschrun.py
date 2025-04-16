#!/usr/bin/python3
#
# cpuschrun.py - Combined CPU metrics analyzer using BCC/eBPF
#
# This script uses eBPF to track various CPU and scheduler metrics, providing:
# - Run queue latency statistics and distributions
# - CPU usage by process and scheduling metrics
# - Process priority scoring and analysis
# - Detailed runtime and wait time metrics
#
# USAGE: cpuschrun.py [-h] [-t TIME] [-p PID] [-i INTERVAL] [-c COUNT] [-P] 
#                      [-I] [-m] [-s] [-r]
#
# Dependencies: BCC (BPF Compiler Collection), Python 3, root privileges, Linux kernel with tracepoints.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal
from operator import itemgetter

# Signal handler for clean exit
running = True
def signal_handler(signum, frame):
    global running
    running = False
signal.signal(signal.SIGINT, signal_handler)

examples = """examples:
    cpuschrun              # show combined CPU metrics
    cpuschrun -p 185      # analyze specific PID
    cpuschrun -i 1 -c 10  # 1s summaries, 10 times
    cpuschrun -P          # per-process breakout
    cpuschrun -I          # include idle tasks
    cpuschrun -s          # show priority scoring
    cpuschrun -r          # show run queue analysis
    cpuschrun -m          # use milliseconds
"""

# Parse command line arguments
parser = argparse.ArgumentParser(
    description="Analyze CPU usage patterns and scheduling behavior",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-t", "--time", choices=["us", "ms", "s"],
    default="us", help="time units (us, ms, s)")
parser.add_argument("-T", "--timestamp", action="store_true",  # Add timestamp argument
    help="include timestamp on output")
parser.add_argument("-p", "--pid", type=int,
    help="trace this PID only")
parser.add_argument("-i", "--interval", type=int, default=99999999,
    help="output interval (seconds)")
parser.add_argument("-c", "--count", type=int, default=99999999,
    help="number of outputs")
parser.add_argument("-P", "--per-process", action="store_true",
    help="show per-process metrics")
parser.add_argument("-I", "--idle", action="store_true",
    help="include idle process")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-s", "--scoring", action="store_true", 
    help="show priority scoring")
parser.add_argument("-r", "--runqueue", action="store_true",
    help="include run queue analysis")

args = parser.parse_args()

# Debug logging control
DEBUG = 0  # Set to 0 to disable debug prints

def debug_print(msg):
    """Helper function for debug logging"""
    if DEBUG:
        print(f"[DEBUG] {msg}")

debug_print("Initializing BPF program")

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

/*
 * ENHANCED DATA STRUCTURES
 * ----------------------
 * We combine and extend the data structures from both tools:
 * - Process state tracking (running, queued, idle)
 * - Timing information for different states
 * - Priority scoring metrics
 */

// Key for process tracking
struct proc_key {
    u32 pid;        // Process ID
    u32 tgid;       // Thread group ID
    u32 cpu;        // CPU ID
};

// Comprehensive metrics per process
struct proc_metrics {
    u64 run_time;        // Time spent running
    u64 queue_time;      // Time spent in run queue
    u64 sleep_time;      // Time spent sleeping
    u32 run_count;       // Number of runs
    u32 queue_count;     // Number of times queued
    u32 priority;        // Process priority
};

// BPF maps for various metrics
BPF_HASH(start, struct proc_key, u64);
BPF_HASH(metrics, u32, struct proc_metrics);
BPF_HISTOGRAM(run_dist);     // Run time distribution
BPF_HISTOGRAM(queue_dist);   // Queue time distribution

// Process state tracking
static inline void update_metrics(struct proc_key *key, u64 delta, u32 state) {
    
    struct proc_metrics *m, zero = {};  // Declare a pointer 'm' to a 'proc_metrics' structure and initialize a 'zero' struct with all fields set to 0.

    m = metrics.lookup_or_try_init(&key->pid, &zero);  
    // Attempt to look up an entry in the 'metrics' map using 'key->pid' as the key.
    // If the entry does not exist, initialize it with the 'zero' struct and return a pointer to it.
    // 'metrics' is likely a BPF map, and 'lookup_or_try_init' is a helper function for this operation.

    if (m == NULL)  
        return;  
    // Check if the lookup or initialization failed (e.g., due to memory constraints or invalid input).
    // If it failed, exit the function early to avoid further processing.

    if (state == 0) {        // Running
        m->run_time += delta;
        m->run_count++;
    } else if (state == 1) { // Queued
        m->queue_time += delta;
        m->queue_count++;
    }

    // Priority score calculation:
    // - Higher for processes with good CPU utilization
    // - Lower for processes spending more time in queue
    if (m->run_time + m->queue_time > 0) {
        m->priority = (m->run_time * 100) / (m->run_time + m->queue_time);
    }
}

/*
 * TRACING ATTACHMENTS
 * -----------------
 * We combine tracing from both tools:
 * 1. Scheduler events (context switches)
 * 2. Run queue events (enqueue/dequeue)
 * 3. Priority changes
 */

// Trace scheduler switches

// Additional BPF functions for tracking...

// Add kernel-side debug print support
#ifdef DEBUG
#define bpf_debug(fmt, ...) bpf_trace_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)
#endif

"""

bpf_text += """
// Tracing hooks for scheduler events
RAW_TRACEPOINT_PROBE(sched_switch)
{
    bpf_debug("sched_switch event received\\n");
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u64 ts = bpf_ktime_get_ns();
    struct proc_key key = {};
    
    // Handle previous task
    key.pid = prev->pid;
    key.tgid = prev->tgid;
    key.cpu = bpf_get_smp_processor_id();
    
    // Calculate time spent running - keep in nanoseconds
    u64 *tsp = start.lookup(&key);
    if (tsp != 0) {
        u64 delta = ts - *tsp;
        update_metrics(&key, delta, 0);  // Store raw nanoseconds
        
        // Only convert to microseconds for histogram display
        u64 delta_us = delta / 1000;
        run_dist.increment(bpf_log2l(delta_us));
        
        start.delete(&key);
    }
    
    // Look up queue entry time for next task
    key.pid = next->pid;
    key.tgid = next->tgid;
    tsp = start.lookup(&key);
    if (tsp != 0) {
        // Calculate queue time before task starts running
        u64 delta = ts - *tsp;
        update_metrics(&key, delta, 1);  // Store raw nanoseconds
        
        // Only convert to microseconds for histogram display
        u64 delta_us = delta / 1000;
        queue_dist.increment(bpf_log2l(delta_us));
        
        start.delete(&key);
    }
    
    // Start timing for next task's run time
    start.update(&key, &ts);
}

RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    bpf_debug("sched_wakeup event received\\n");
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    u64 ts = bpf_ktime_get_ns();
    struct proc_key key = {
        .pid = p->pid,
        .tgid = p->tgid,
        .cpu = bpf_get_smp_processor_id()
    };
    
    // Start measuring queue time
    start.update(&key, &ts);
}
"""

# Python functions for output processing with detailed comments
def print_process_metrics(metrics, args):
    """
    Print detailed per-process metrics including CPU usage and priority scores
    
    Args:
        metrics: BPF hash map containing process statistics
        args: Command line arguments for customizing output
    """
    debug_print("Processing metrics for display")
    
    # Convert raw data to process metrics
    processes = []
    for k, m in metrics.items():
        try:
            # Convert binary PID to integer
            # k is a binary string containing a 32-bit integer
            pid = int.from_bytes(k, byteorder='little')
            debug_print(f"Processing PID: {pid}")

            # Skip idle process unless specifically requested
            if pid == 0 and not args.idle:
                continue
                
            # Get process name from /proc filesystem
            try:
                comm = open(f"/proc/{pid}/comm").read().strip()
            except:
                comm = "?"
                debug_print(f"Could not get comm for PID {pid}")
                
            # Convert BPF ctypes to Python types
            run_time = int(m.run_time)
            queue_time = int(m.queue_time)
            priority = int(m.priority)
                
            # Calculate CPU utilization percentage
            cpu_pct = 0
            total_time = run_time + queue_time
            if total_time > 0:
                cpu_pct = (run_time * 100.0) / total_time
                
            # Store process metrics in list for sorting
            processes.append({
                'pid': pid,
                'comm': comm,
                'cpu_pct': cpu_pct,
                'run_time': run_time,
                'queue_time': queue_time,
                'priority': priority
            })
        except Exception as e:
            debug_print(f"Error processing PID data: {e}")
            debug_print(f"Raw key: {k}, Raw metrics: {m}")
            continue

    debug_print(f"Found {len(processes)} valid processes to display")
    
    # Sort processes by priority score (highest first)
    processes.sort(key=lambda x: x['priority'], reverse=True)

    # Print formatted header
    print("\n%-6s %-15s %7s %10s %10s %10s" %
        ("PID", "COMM", "CPU%", "RUN(ms)", "WAIT(ms)", "PRIO"))
    print("%-6s %-15s %7s %10s %10s %10s" %
        ("------", "---------------", "-------", 
        "----------", "----------", "----------"))

    # Print each process's metrics
    try:
        for p in processes:
            # Times stored in nanoseconds, display in milliseconds
            run_ms = p['run_time'] / 1000000.0
            queue_ms = p['queue_time'] / 1000000.0
            if queue_ms == 0:
                continue

            print("%-6d %-15s %7.2f %10.4f %10.4f %10d" % (
                p['pid'],
                p['comm'][:15],
                p['cpu_pct'],
                run_ms,      # Convert ns to ms for display
                queue_ms,    # Convert ns to ms for display
                p['priority']
            ))
    except TypeError as e:
        debug_print(f"Type conversion error: {e}")
        debug_print(f"Problem process: {p}")

def print_histograms(b, args):
    """
    Print latency distribution histograms
    
    Display format:
    - Time values always in microseconds
    - Power-of-2 histogram buckets
    - Shows process names if available
    """
    try:
        # Get histogram tables from BPF program
        run_dist = b.get_table("run_dist")
        queue_dist = b.get_table("queue_dist")
        
        # Print timestamp if requested
        if args.timestamp:
            print("%-8s\n" % strftime("%H:%M:%S"), end="")
        
        # Helper function to get process names
        def pid_to_comm(pid):
            try:
                comm = open(f"/proc/{pid}/comm").read().strip()
                return f"{pid} {comm}"
            except:
                return str(pid)
            
        print("\nCPU Runtime Distribution (microseconds):")
        if len(run_dist.items()) > 0:
            run_dist.print_log2_hist("usecs", section_print_fn=pid_to_comm)
        else:
            print("No data collected")
            
        if args.runqueue:
            print("\nRun Queue Latency Distribution (microseconds):")
            if len(queue_dist.items()) > 0:
                queue_dist.print_log2_hist("usecs", section_print_fn=pid_to_comm)
            else:
                print("No data collected")
                
        debug_print(f"Histograms updated - Run entries: {len(run_dist.items())}, Queue entries: {len(queue_dist.items())}")
        
        # Clear histograms for next interval
        run_dist.clear()
        queue_dist.clear()
        
    except Exception as e:
        debug_print(f"Error in print_histograms: {e}")

def monitor_cpu(b, args):
    debug_print(f"Starting monitoring with interval={args.interval}, count={args.count}")
    """
    Main monitoring loop
    
    Args:
        b: BPF program instance
        args: Command line arguments
        
    This function:
    1. Collects metrics at specified intervals
    2. Handles graceful shutdown on Ctrl+C
    3. Manages output formatting and display
    """
    interval = int(args.interval)
    countdown = args.count
    metrics = b.get_table("metrics")
    


    while countdown > 0 and running:  # Check global running flag
        try:
            debug_print(f"Sleeping for {interval} seconds. Countdown={countdown}")
            sleep(interval)
            
            # Print per-process metrics if requested
            if args.per_process:
                debug_print("Processing per-process metrics")
                print_process_metrics(metrics, args)
            
            debug_print("Updating histograms")
            print_histograms(b, args)
            
            debug_print("Clearing metrics for next interval")
            metrics.clear()
            countdown -= 1
            
        except KeyboardInterrupt:
            debug_print("Received interrupt, preparing final output")
            # Force one last output before exiting
            print("Breaking")
            if args.per_process:
                print_process_metrics(metrics, args)
            print_histograms(b, args)
            

if __name__ == '__main__':
    debug_print("Initializing BPF program")
    
    # Validate time unit selection
    if args.time not in ["us", "ms", "s"]:
        debug_print(f"Invalid time unit: {args.time}, defaulting to 'us'")
        args.time = "us"
    
    debug_print(f"Using time unit: {args.time}")
    
    max_pid = int(open("/proc/sys/kernel/pid_max").read())

    # Initialize BPF program with proper time unit configuration
    b = BPF(text=bpf_text, cflags=["-DMAX_PID=%d" % max_pid])
    debug_print("BPF program loaded successfully")
    
    debug_print("Starting CPU metrics collection")
    print("Tracing CPU metrics... Hit Ctrl-C to end.")
    monitor_cpu(b, args)
    debug_print("Program terminated")


"""
(base) sriram@noble-numbat:~/IITGN/CN/Project$ sudo ./cpuschrun.py -P -i 2 -T

Tracing CPU metrics... Hit Ctrl-C to end.

PID    COMM               CPU%    RUN(ms)   WAIT(ms)       PRIO
------ --------------- ------- ---------- ---------- ----------
10605  chrome            99.11     5.5112     0.0493         99
3287   Thread<10>        99.83    25.8550     0.0433         99
3278   Thread<01>        99.95    27.2278     0.0144         99
3289   Thread<12>        99.84    25.8635     0.0404         99
3277   Thread<00>        99.82    25.8844     0.0470         99
3292   Thread<15>        99.91    26.9685     0.0233         99
3281   Thread<04>        99.85    26.9164     0.0416         99
3283   Thread<06>        99.87    26.9012     0.0364         99
3280   Thread<03>        99.86    27.1470     0.0393         99
3286   Thread<09>        99.88    26.8855     0.0321         99
11447  chrome            99.38     0.8680     0.0054         99
3285   Thread<08>        99.88    25.8972     0.0321         99
18460  cachetop-bpfcc    99.76     2.4764     0.0061         99
10074  chrome            99.74    19.5082     0.0500         99
34669  ?                 99.82     3.4852     0.0062         99
3279   Thread<02>        99.93    27.1430     0.0189         99
3293   code              98.10    24.4374     0.4744         98
34668  ?                 98.88     3.3469     0.0380         98
3827   chrome            98.13     0.2965     0.0056         98
3829   chrome            98.59     1.7983     0.0258         98
3275   code              98.95     2.1688     0.0230         98
3844   ThreadPoolForeg   98.24     2.0966     0.0377         98
4066   chrome            98.58     1.4982     0.0215         98
487    systemd-journal   98.89     0.6619     0.0074         98
3846   Chrome_ChildIOT   98.99     5.3193     0.0545         98
36832  ?                 97.35     0.2753     0.0075         97
3259   code              97.72    31.2589     0.7301         97
11473  chrome            97.84     0.7704     0.0170         97
19713  code              97.84     0.3748     0.0083         97
3301   VizCompositorTh   97.10    18.2122     0.5443         97
1915   gnome-shell       97.33    33.2210     0.9111         97
11172  chrome            97.27     0.1886     0.0053         97
19190  chrome            97.19     0.1879     0.0054         97
3321   code              97.52     1.8300     0.0466         97
4164   chrome            96.75     0.2016     0.0068         96
10658  chrome            96.71     0.2311     0.0079         96
3331   code              96.23     0.2738     0.0107         96
1129   wpa_supplicant    96.04     0.3224     0.0133         96
3288   Thread<11>        96.05     4.2364     0.1742         96
973    systemd-oomd      96.27     0.4735     0.0183         96
3290   Thread<13>        96.40     4.1761     0.1559         96
36824  ?                 96.39     3.0761     0.1152         96
3284   Thread<07>        96.14     4.2513     0.1708         96
3831   ThreadPoolSingl   96.00     0.2084     0.0087         96
3291   Thread<14>        96.22     4.1498     0.1628         96
36823  ?                 95.00     0.1552     0.0082         95
3786   chrome            95.75     0.1876     0.0083         95
34673  ?                 95.04     0.3743     0.0195         95
3790   ThreadPoolForeg   95.90     1.6659     0.0713         95
34674  chrome            95.65     0.9972     0.0454         95
3282   Thread<05>        95.59     4.2186     0.1948         95
3168   code              95.84    12.1794     0.5281         95
3765   chrome            94.57     6.3835     0.3667         94
32050  kworker/u98:1-f   94.79     3.7406     0.2058         94
3371   code              94.87     6.5360     0.3534         94
1181   rs:main Q:Reg     94.72     0.1050     0.0059         94
34681  chrome            94.68     1.7824     0.1002         94
34139  kworker/u96:3-m   94.51     3.6288     0.2109         94
34887  chrome            94.26     0.4131     0.0252         94
11225  chrome            94.49     0.1559     0.0091         94
18413  gnome-terminal-   94.98     1.3591     0.0719         94
11158  chrome            93.44     0.1900     0.0133         93
2677   Xwayland:cs0      93.82     0.2174     0.0143         93
19820  code              93.60     0.4160     0.0284         93
34025  kworker/u98:2-e   93.86     3.8243     0.2503         93
3795   Chrome_IOThread   92.79     2.3586     0.1832         92
1970   gnome-shel:cs0    92.54     0.2194     0.0177         92
3325   Chrome_ChildIOT   92.14     0.2735     0.0233         92
3262   ThreadPoolForeg   92.61     0.3114     0.0249         92
34670  ?                 92.91     0.1136     0.0087         92
1070   gmain             91.03     0.0666     0.0066         91
3332   code              91.93     0.4646     0.0408         91
2670   Xwayland          91.65     5.7973     0.5279         91
34672  ?                 91.69     0.0542     0.0049         91
4154   chrome            91.87     0.6964     0.0616         91
34689  Chrome_ChildIOT   91.41     0.0454     0.0043         91
9993   chrome            91.75     0.3572     0.0321         91
3268   Compositor        91.50    15.2130     1.4139         91
21004  chrome            91.45     0.2195     0.0205         91
9997   Chrome_ChildIOT   91.35     0.1205     0.0114         91
1179   in:imuxsock       90.32     0.0670     0.0072         90
19835  code              90.21     0.2298     0.0249         90
3294   ANGLE-Submit      89.50     0.0694     0.0081         89
4071   Chrome_ChildIOT   89.76     0.1242     0.0142         89
3304   ThreadPoolForeg   89.07     0.0629     0.0077         89
2721   mutter-x11-fram   88.15     1.5170     0.2039         88
4215   WebCrypto         88.13     0.1182     0.0159         88
3261   ThreadPoolForeg   88.92     0.8623     0.1074         88
3796   MemoryInfra       88.65     0.1383     0.0177         88
3302   ThreadPoolForeg   88.51     0.1038     0.0135         88
1953   JS Helper         88.43     0.1974     0.0258         88
34671  ?                 88.12     0.0488     0.0066         88
18458  sudo              88.04     0.3495     0.0475         88
248    kworker/0:1H-kb   88.17     0.0573     0.0077         88
67     migration/8       88.55     0.0554     0.0072         88
3300   Chrome_ChildIOT   87.63     2.6747     0.3776         87
19717  Chrome_ChildIOT   87.99     0.1170     0.0160         87
3364   code              87.88     0.0442     0.0061         87
11110  chrome            87.75     0.1157     0.0162         87
10126  ServiceWorker t   86.98     0.0888     0.0133         86
1968   KMS thread        86.77     3.9526     0.6027         86
3176   Chrome_IOThread   86.33     1.6877     0.2673         86
3267   code              86.73     0.0717     0.0110         86
3363   code              86.16     0.0478     0.0077         86
10609  Chrome_ChildIOT   85.85     0.5412     0.0892         85
1988   gnome-shell       85.23     3.5022     0.6071         85
2344   gvfs-afc-volume   85.10     0.0665     0.0116         85
3575   code              85.62     0.2410     0.0405         85
19858  code              85.35     0.1228     0.0211         85
79     migration/10      85.10     0.0331     0.0058         85
3263   Chrome_ChildIOT   85.13     3.5884     0.6266         85
3791   ThreadPoolForeg   85.48     0.1935     0.0329         85
50     ksoftirqd/5       84.97     0.0194     0.0034         84
10078  Chrome_ChildIOT   84.72     0.3626     0.0654         84
5014   GUsbEventThread   84.74     0.0348     0.0063         84
1954   JS Helper         84.75     0.1030     0.0185         84
3186   code              83.33     0.0405     0.0081         83
1946   JS Helper         83.46     0.1177     0.0233         83
435    jbd2/nvme0n1p7-   83.77     0.4023     0.0780         83
1947   JS Helper         83.98     0.0645     0.0123         83
43     migration/4       83.31     0.0387     0.0078         83
1987   gnome-shel:gl0    81.75     0.0853     0.0190         81
3788   HangWatcher       81.62     0.1136     0.0256         81
378    irq/57-ASCF1200   81.45     5.1086     1.1636         81
85     migration/11      80.68     0.0259     0.0062         80
3185   code              79.04     0.0171     0.0045         79
3366   code              79.55     0.0336     0.0086         79
808    napi/phy0-8193    79.02     0.6770     0.1798         79
3184   code              79.50     0.0257     0.0066         79
2503   gmain             79.91     0.0765     0.0192         79
3183   code              78.71     0.0297     0.0080         78
36812  sudo              78.13     0.0890     0.0249         78
3355   code              78.91     0.1258     0.0336         78
810    napi/phy0-8195    77.65     0.5501     0.1584         77
73     migration/9       77.23     0.0470     0.0139         77
104    migration/14      76.58     0.0377     0.0115         76
2684   Xwayland:gdrv0    76.42     0.0212     0.0065         76
11233  HangWatcher       76.59     0.0499     0.0153         76
3386   code              75.77     1.7248     0.5515         75
22097  kworker/4:0-mm_   75.01     0.1283     0.0428         75
146    migration/21      74.62     0.0602     0.0205         74
1950   JS Helper         74.36     0.0439     0.0151         74
3365   code              74.37     0.0264     0.0091         74
35292  kworker/u98:3-e   74.78     0.1859     0.0627         74
3367   code              74.78     0.1231     0.0415         74
189    kworker/12:1H-k   74.79     0.1073     0.0361         74
28203  kworker/8:1-mm_   74.87     0.0417     0.0140         74
3231   code              74.25     0.1382     0.0479         74
22476  kworker/23:1-mm   74.92     0.1292     0.0432         74
809    napi/phy0-8194    73.31     0.0603     0.0220         73
19834  code              73.81     0.1046     0.0371         73
1951   JS Helper         72.17     0.0395     0.0152         72
86     ksoftirqd/11      71.32     0.0269     0.0108         71
98     migration/13      70.53     0.0273     0.0114         70
10687  HangWatcher       69.70     0.0482     0.0209         69
16397  kworker/21:5-mm   69.64     0.0132     0.0058         69
1948   JS Helper         68.87     0.0440     0.0199         68
4304   HangWatcher       68.64     0.0460     0.0210         68
824    mt76-tx phy0      66.23     0.2989     0.1524         66
32286  kworker/u97:2-e   63.10     0.0716     0.0419         63
1949   JS Helper         62.69     0.0326     0.0194         62
3407   code              61.41     0.1229     0.0772         61
19857  code              61.95     0.1164     0.0715         61
13041  kworker/7:2-mm_   60.93     0.0106     0.0068         60
204    kworker/5:1-eve   58.88     0.1380     0.0964         58
111    ksoftirqd/15      58.36     0.0172     0.0122         58
17     rcu_preempt       58.19     0.7439     0.5346         58
55     migration/6       55.72     0.0081     0.0065         55
201    kworker/15:1-ev   54.25     0.0421     0.0355         54
23093  kworker/17:3-mm   53.92     0.0308     0.0263         53
29473  kworker/3:2-mm_   53.57     0.1740     0.1508         53
49     migration/5       53.57     0.0090     0.0078         53
6853   kworker/9:2-mm_   51.93     0.0725     0.0672         51
61     migration/7       51.66     0.0079     0.0074         51
134    migration/19      50.83     0.0058     0.0056         50
116    migration/16      50.89     0.0060     0.0058         50
122    migration/17      49.28     0.0062     0.0063         49
14319  kworker/12:3-mm   49.95     0.0836     0.0838         49
37     migration/3       49.63     0.0087     0.0088         49
158    migration/23      49.11     0.0061     0.0063         49
25     migration/1       48.07     0.0120     0.0130         48
31     migration/2       48.33     0.0121     0.0129         48
128    migration/18      48.13     0.0060     0.0065         48
208    kworker/20:1-mm   47.91     0.0345     0.0375         47
140    migration/20      46.46     0.0063     0.0072         46
152    migration/22      46.11     0.0061     0.0071         46
172    kcompactd0        45.26     0.0661     0.0799         45
202    kworker/6:1-eve   45.45     0.0678     0.0813         45
198    kworker/1:1-eve   44.29     0.1246     0.1566         44
91     migration/12      44.95     0.0094     0.0116         44
110    migration/15      43.84     0.0091     0.0116         43
13619  kworker/10:0-mm   42.58     0.0809     0.1091         42
14417  kworker/19:2-mm   42.46     0.0621     0.0842         42
20     migration/0       41.80     0.0123     0.0172         41
22432  kworker/2:0-mm_   39.44     0.0604     0.0928         39
199    kworker/13:1-ev   38.41     0.0170     0.0272         38
23221  kworker/16:4-mm   32.87     0.1172     0.2394         32
23691  kworker/0:0-mm_   32.60     0.1028     0.2125         32
211    kworker/22:1-mm   12.91     0.4501     3.0359         12
528    kworker/18:2-mm    7.60     0.0564     0.6855          7
508    kworker/11:2-ev    5.10     0.1068     1.9865          5
68     ksoftirqd/8        2.83     0.0301     1.0332          2
36814  cpuschrun.py       0.00     0.0000     0.0055          0
19:43:10

CPU Runtime Distribution (microseconds):
     usecs               : count     distribution
         0 -> 1          : 75       |***                                     |
         2 -> 3          : 494      |********************                    |
         4 -> 7          : 791      |********************************        |
         8 -> 15         : 423      |*****************                       |
        16 -> 31         : 965      |****************************************|
        32 -> 63         : 834      |**********************************      |
        64 -> 127        : 541      |**********************                  |
       128 -> 255        : 511      |*********************                   |
       256 -> 511        : 468      |*******************                     |
       512 -> 1023       : 267      |***********                             |
      1024 -> 2047       : 354      |**************                          |
      2048 -> 4095       : 552      |**********************                  |
      4096 -> 8191       : 177      |*******                                 |
      8192 -> 16383      : 89       |***                                     |
     16384 -> 32767      : 76       |***                                     |
     32768 -> 65535      : 68       |**                                      |
     65536 -> 131071     : 78       |***                                     |
    131072 -> 262143     : 52       |**                                      |
    262144 -> 524287     : 28       |*                                       |
    524288 -> 1048575    : 9        |                                        |

   """