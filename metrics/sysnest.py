#! /usr/bin/python3
#
# sysnest.py - Summarize syscall counts and latencies, grouped by process or syscall
#
# This script uses eBPF to track system call entry and exit events, providing:
# - Per-process system call statistics (counts and latencies)
# - Per-syscall statistics with process breakdowns
# - Flexible grouping by either process or syscall
# - Real-time monitoring with configurable update intervals
#
# USAGE: sysnest.py [-h] [-p PID] [-t TID] [-c PPID] [-i INTERVAL] [-d DURATION]
#                   [-T TOP] [-D DETAILS_TOP] [-m] [--syscall SYSCALL]
#                   [--group-by {process,syscall}]
#
# Dependencies: BCC (BPF Compiler Collection), Python 3, root privileges, Linux kernel with tracepoints.

from time import sleep, strftime
import argparse
import errno
import itertools
import sys
import signal
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
from collections import defaultdict
import ctypes as ct

if sys.version_info.major < 3:
    izip_longest = itertools.izip_longest
else:
    izip_longest = itertools.zip_longest

# Signal handler
def signal_ignore(signal, frame):
    print()

# Argument Parsing
parser = argparse.ArgumentParser(
    description="Summarize syscall counts and latencies, grouped hierarchically.")
# Filters
parser.add_argument("-p", "--pid", type=int, help="trace only this pid")
parser.add_argument("-t", "--tid", type=int, help="trace only this tid")
parser.add_argument("-c", "--ppid", type=int, help="trace only child of this pid")
parser.add_argument("--syscall", type=str, help="trace this syscall only")
# Behavior
parser.add_argument("-i", "--interval", type=int, help="print summary interval (seconds)")
parser.add_argument("-d", "--duration", type=int, help="total duration of trace (seconds)")
parser.add_argument("-T", "--top", type=int, default=10,
    help="print only the top N main items (processes or syscalls)")
parser.add_argument("-D", "--details-top", type=int, default=5,
    help="print only the top N detailed items per main item (syscalls per process or processes per syscall)")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="display latency in milliseconds (default: microseconds)")
parser.add_argument("--group-by", choices=["process", "syscall"], default="syscall",
    help="how to group the output (default: syscall)")
# Internal
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()
if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

# Process syscall filter if specified
syscall_nr_filter = -1
if args.syscall is not None:
    syscall = bytes(args.syscall, 'utf-8')
    # Handle potential architecture variations (e.g., x86_64 vs aarch64)
    found = False
    for key, value in syscalls.items():
        if syscall == value:
            syscall_nr_filter = key
            found = True
            break
    if not found:
        print(f"Error: syscall '{args.syscall}' not found for this architecture. Exiting.")
        sys.exit(1)

# BPF Program
# We always store both pid and syscall_nr in the key now.
# Grouping/aggregation happens in Python.
bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h> // For PT_REGS_PARM1 etc.

// Key for the data map: combines PID and syscall number
struct key_t {
    u32 pid;
    u32 syscall_nr;
};

// Data stored per key: count and total latency
struct data_t {
    u64 count;
    u64 total_ns;
};

// Hash map to store start times of syscalls (keyed by pid_tgid)
BPF_HASH(start, u64, u64);
// Hash map to store syscall data (keyed by {pid, syscall_nr})
BPF_HASH(data, struct key_t, struct data_t);

// Helper to get syscall number
static __always_inline int get_syscall_nr(struct pt_regs *ctx) {
#if defined(__s390x__)
    // s390x passes syscall number in pt_regs->gprs[2]
    return (int)PT_REGS_PARM1(ctx);
#elif defined(__aarch64__)
    // aarch64 passes syscall number in pt_regs->syscallno
    return (int)ctx->syscallno;
#else
    // x86_64 passes syscall number in pt_regs->orig_ax
    return (int)PT_REGS_PARM1(ctx); // orig_ax is the first arg for tracepoint
#endif
}

// Probe for syscall entry
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    int syscall_nr = args->id; // Use tracepoint argument for syscall number

    // --- Filtering ---
#ifdef FILTER_SYSCALL_NR
    if (syscall_nr != FILTER_SYSCALL_NR) return 0;
#endif
#ifdef FILTER_PID
    if (pid != FILTER_PID) return 0;
#endif
#ifdef FILTER_TID
    if (tid != FILTER_TID) return 0;
#endif
#ifdef FILTER_PPID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // Reading real_parent requires proper kernel headers and can be unstable.
    // Consider safety checks or alternative methods if issues arise.
    // Using BPF_CORE_READ or task->parent might be alternatives depending on kernel version.
    // For simplicity, keeping original logic, but be aware of potential issues.
    u32 ppid = 0;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    if (ppid != FILTER_PPID) return 0;
#endif
    // --- End Filtering ---

    // Record start time
    u64 t = bpf_ktime_get_ns();
    start.update(&pid_tgid, &t);
    return 0;
}

// Probe for syscall exit
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    int syscall_nr = args->id; // Use tracepoint argument for syscall number

    // --- Filtering (repeat filters for exit) ---
#ifdef FILTER_SYSCALL_NR
    if (syscall_nr != FILTER_SYSCALL_NR) return 0;
#endif
#ifdef FILTER_PID
    if (pid != FILTER_PID) return 0;
#endif
#ifdef FILTER_TID
    if (tid != FILTER_TID) return 0;
#endif
#ifdef FILTER_PPID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
     if (ppid != FILTER_PPID) return 0;
#endif
   // --- End Filtering ---

    // Get start time and calculate duration
    u64 *start_ns = start.lookup(&pid_tgid);
    if (!start_ns) return 0; // Should not happen if enter was traced

    u64 duration_ns = bpf_ktime_get_ns() - *start_ns;
    start.delete(&pid_tgid); // Clean up start entry

    // Prepare key for the data map
    struct key_t key = {};
    key.pid = pid;
    key.syscall_nr = syscall_nr;

    // Update statistics
    struct data_t zero = {};
    struct data_t *val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        lock_xadd(&val->count, 1);
        lock_xadd(&val->total_ns, duration_ns);
    }

    return 0;
}
"""

# Apply filters via preprocessor defines
if args.pid:
    bpf_text = ("#define FILTER_PID %d\n" % args.pid) + bpf_text
elif args.tid:
    bpf_text = ("#define FILTER_TID %d\n" % args.tid) + bpf_text
elif args.ppid:
    bpf_text = ("#define FILTER_PPID %d\n" % args.ppid) + bpf_text
# Apply syscall filter (handle -1 case which means no filter)
if syscall_nr_filter != -1:
     bpf_text = ("#define FILTER_SYSCALL_NR %d\n" % syscall_nr_filter) + bpf_text

if args.ebpf:
    print(bpf_text)
    exit()

# Load BPF program
b = BPF(text=bpf_text)

# Define time column header based on units
time_colname = "TIME (ms)" if args.milliseconds else "TIME (us)"
time_divisor = 1e6 if args.milliseconds else 1e3
time_format = "%.6f" if args.milliseconds else "%.3f"

# Cache for process command names
comm_cache = {}
def get_comm(pid):
    # Simple cache to avoid frequent /proc reads for the same PID within an interval
    if pid not in comm_cache:
        try:
            # Limit read size for safety
            comm = open(f"/proc/{pid}/comm", "rb").read(100).strip()
            comm_cache[pid] = comm
        except FileNotFoundError:
             comm_cache[pid] = b"[gone]" # Process might have exited
        except Exception:
            comm_cache[pid] = b"[unknown]"
            # Add a small delay or limit retries if [unknown] happens frequently
    return comm_cache[pid]

# Check BPF batch ops capability
# This needs to be done after the BPF object 'b' is created,
# but before print_stats uses the variable.
# Let's redefine it just before print_stats for clarity,
# although defining it once after 'b = BPF(...)' is sufficient.

try:
    htab_batch_ops = True if BPF.kernel_struct_has_field(b'bpf_map_ops',
            b'map_lookup_and_delete_batch') == 1 else False
except Exception:
    # Handle cases where the check itself might fail (e.g., older BCC)
    print("Warning: Could not check for BPF batch operations support. Assuming disabled.", file=sys.stderr)
    htab_batch_ops = False

# --- Main Printing Function ---
def print_stats():
    bpf_data_map = b["data"]
    # Choose map reading method
    if htab_batch_ops:
        # Use items_lookup_and_delete_batch if available
        map_items = list(bpf_data_map.items_lookup_and_delete_batch())
        # Fallback if batch delete isn't supported or returns None (check API details)
        if map_items is None:
             map_items = list(bpf_data_map.items())
             bpf_data_map.clear() # Clear manually if batch delete failed/not used
    else:
        # items() can be slow on large maps without batch ops
        map_items = list(bpf_data_map.items())
        # Clear manually if not using batch delete
        bpf_data_map.clear()

    # Clear the comm cache at the start of each interval print
    comm_cache.clear()

    if not map_items:
        print("[%s] No data captured in this interval." % strftime("%H:%M:%S"))
        sys.stdout.flush()
        return

    # --- Data Aggregation ---
    if args.group_by == "process":
        # Aggregate: { pid -> { 'total_ns': x, 'total_count': y, 'syscalls': { syscall_nr -> {'ns': n, 'count': c} } } }
        agg_data = defaultdict(lambda: {'total_ns': 0, 'total_count': 0, 'syscalls': defaultdict(lambda: {'ns': 0, 'count': 0})})
        for key, value in map_items:
            # key is ct.Structure: key.pid, key.syscall_nr
            # value is ct.Structure: value.count, value.total_ns
            if key.pid == 0: continue # Skip PID 0 (idle/kernel?)
            proc_entry = agg_data[key.pid]
            proc_entry['total_ns'] += value.total_ns
            proc_entry['total_count'] += value.count
            syscall_entry = proc_entry['syscalls'][key.syscall_nr]
            syscall_entry['ns'] += value.total_ns
            syscall_entry['count'] += value.count

        # --- Printing (Process-Centric) ---
        print("[%s]" % strftime("%H:%M:%S"))
        # Sort processes by total latency
        sorted_pids = sorted(agg_data.keys(), key=lambda p: agg_data[p]['total_ns'], reverse=True)

        header_format = "%-6s %-15s %10s %16s"
        # Use %s for the syscall name (byte string)
        detail_format = b"  %-20s %10d " + (b"%16.6f" if args.milliseconds else b"%16.3f")
        # Use %s for the comm name (byte string)
        total_format  = b"%-6d %-15s %10d " + (b"%16.6f" if args.milliseconds else b"%16.3f")

        print(header_format % ("PID", "COMM", "TOT COUNT", time_colname)) # Header is standard str
        print("-" * (6 + 1 + 15 + 1 + 10 + 1 + 16 + 1)) # Adjust width

        for i, pid in enumerate(sorted_pids):
            if i >= args.top: break
            proc_entry = agg_data[pid]
            comm = get_comm(pid) # Returns bytes

            # Print process total line
            printb(total_format % (
                pid, comm, proc_entry['total_count'], proc_entry['total_ns'] / time_divisor
            ))

            # Sort syscalls within this process by latency
            sorted_syscalls = sorted(proc_entry['syscalls'].keys(),
                                     key=lambda s: proc_entry['syscalls'][s]['ns'], reverse=True)

            # Print top N syscall details for this process
            for j, syscall_nr in enumerate(sorted_syscalls):
                 if j >= args.details_top: break
                 syscall_entry = proc_entry['syscalls'][syscall_nr]
                 syscall_n = syscall_name(syscall_nr) # Returns bytes
                 printb(detail_format % (
                     syscall_n, syscall_entry['count'], syscall_entry['ns'] / time_divisor
                 ))
            # Add a blank line between processes only if details were printed
            if args.details_top > 0 and len(proc_entry['syscalls']) > 0 :
                 print()


    elif args.group_by == "syscall":
        # Aggregate: { syscall_nr -> { 'total_ns': x, 'total_count': y, 'pids': { pid -> {'ns': n, 'count': c} } } }
        agg_data = defaultdict(lambda: {'total_ns': 0, 'total_count': 0, 'pids': defaultdict(lambda: {'ns': 0, 'count': 0})})
        for key, value in map_items:
            # key is ct.Structure: key.pid, key.syscall_nr
            # value is ct.Structure: value.count, value.total_ns
            syscall_entry = agg_data[key.syscall_nr]
            syscall_entry['total_ns'] += value.total_ns
            syscall_entry['total_count'] += value.count
            # Don't add PID 0 details, but count its contribution to the total
            if key.pid != 0:
                pid_entry = syscall_entry['pids'][key.pid]
                pid_entry['ns'] += value.total_ns
                pid_entry['count'] += value.count

        # --- Printing (Syscall-Centric) ---
        print("[%s]" % strftime("%H:%M:%S"))
        # Sort syscalls by total latency
        sorted_syscalls = sorted(agg_data.keys(), key=lambda s: agg_data[s]['total_ns'], reverse=True)

        header_format = "%-20s %10s %16s"
         # Use %s for the comm name (byte string) in details
        detail_format = b"  %-6d %-15s %10d " + (b"%16.6f" if args.milliseconds else b"%16.3f")
        # Use %s for the syscall name (byte string) in totals - THIS WAS THE FIX
        total_format  = b"%-20s %10d " + (b"%16.6f" if args.milliseconds else b"%16.3f")

        print(header_format % ("SYSCALL", "TOT COUNT", time_colname)) # Header is standard str
        print("-" * (20 + 1 + 10 + 1 + 16 + 1)) # Adjust width

        for i, syscall_nr in enumerate(sorted_syscalls):
            # Simple check for invalid syscall numbers sometimes seen
            if syscall_nr == -1 or syscall_nr > 1000: # Adjust max syscall reasonable number if needed
                continue
            if i >= args.top: break

            syscall_entry = agg_data[syscall_nr]
            try:
                syscall_n = syscall_name(syscall_nr) # Returns bytes
            except ValueError:
                syscall_n = b"[invalid#%d]" % syscall_nr # Handle cases where number is out of range

            # Print syscall total line
            printb(total_format % (
                syscall_n, syscall_entry['total_count'], syscall_entry['total_ns'] / time_divisor
            ))

            # Sort PIDs within this syscall by latency
            sorted_pids = sorted(syscall_entry['pids'].keys(),
                                 key=lambda p: syscall_entry['pids'][p]['ns'], reverse=True)

            # Print top N process details for this syscall
            for j, pid in enumerate(sorted_pids):
                 if j >= args.details_top: break
                 pid_entry = syscall_entry['pids'][pid]
                 comm = get_comm(pid) # Returns bytes
                 printb(detail_format % (
                     pid, comm, pid_entry['count'], pid_entry['ns'] / time_divisor
                 ))
            # Add a blank line between syscalls only if details were printed
            if args.details_top > 0 and len(syscall_entry['pids']) > 0 :
                 print()

    sys.stdout.flush() # Ensure output is displayed immediately


# --- Main Loop ---
if args.syscall is not None:
    print(f"Tracing syscall '{args.syscall}' ({syscall_nr_filter})... Ctrl-C to quit.")
else:
    print(f"Tracing syscalls, grouping by {args.group_by}, printing top {args.top} items ({args.details_top} details)... Ctrl-C to quit.")

exiting = False if args.interval else True
seconds = 0
while True:
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = True
        # Handle Ctrl+C gracefully (don't print stack trace)
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = True

    print_stats()

    if exiting:
        print("Detaching...")
        # No explicit detach needed for BPF object typically, Python GC handles it.
        exit()

"""
(base) sriram@noble-numbat:~/IITGN/CN/Project$ sudo ./sysnest.py 

Tracing syscalls, grouping by syscall, printing top 10 items (5 details)... Ctrl-C to quit.
^C[19:46:56]
SYSCALL               TOT COUNT        TIME (us)
-------------------------------------------------
futex                     17692    152950184.187
  3259   code                  1373     27008272.369
  3168   code                   102     17105445.908
  3765   chrome                 280     11639894.321
  1915   gnome-shell            226     10071312.531
  2670   Xwayland                33     10022512.840

poll                       1666     89891062.824
  1915   gnome-shell            529     22175637.700
  3275   code                   308     10037664.255
  5007   fwupd                    7      8004181.836
  3168   code                   342      5344269.886
  3765   chrome                 213      5082561.191

epoll_wait                 1845     79570736.422
  3321   code                    35     10314113.773
  3168   code                   122      9867379.356
  3765   chrome                 294      5500899.303
  3259   code                   455      5355479.975
  3371   code                   128      5323606.784

epoll_pwait                 217     10903548.345
  19858  code                     6      4897009.848
  3613   code                     3      3003096.589
  3575   code                     3      3003005.608
  3371   code                   130          272.262
  3321   code                    19           57.469

clock_nanosleep               3      7368064.140
  37370  sysnest.py               1      5367841.573
  37421  [gone]                   1      1000129.954
  37390  [gone]                   1      1000092.613

ppoll                        82      5367928.006
  37368  sudo                     5      5367702.179
  18458  sudo                    77          225.827

pselect6                      5      5006274.343
  2339   gvfs-afc-volume          5      5006274.343

select                        5      4239494.248
  3168   code                     5      4239494.248

wait4                       114      4097611.957
  37411  [gone]                   2      1026689.830
  37380  [gone]                   2      1025721.676
  37412  [gone]                  48      1002496.908
  37381  [gone]                  48      1002422.630
  37409  [gone]                   2        20722.802

sched_yield              207041        69110.931
  3275   code                207041        69110.931
"""