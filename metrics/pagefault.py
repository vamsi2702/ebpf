#!/usr/bin/env python3
#
# pagefault.py - Monitor and analyze page fault activity by process
#
# This script uses eBPF tracepoints to track page faults, providing:
# - Per-process minor and major page fault rates
# - Real-time monitoring with periodic updates
# - Top process analysis by page fault frequency
# - Distinction between minor (memory-resident) and major (disk) page faults
#
# USAGE: pagefault.py
#
# Dependencies: BCC (BPF Compiler Collection), Python 3, root privileges, Linux kernel with tracepoints.

from bcc import BPF
from time import sleep, strftime
import signal
import sys

# eBPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct val_t {
    u64 minor;
    u64 major;
};

BPF_HASH(page_faults, struct key_t, struct val_t);

// Trace page faults
TRACEPOINT_PROBE(exceptions, page_fault_user) {
    struct key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    key.pid = pid_tgid >> 32;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    struct val_t *valp, zero = {};
    valp = page_faults.lookup_or_try_init(&key, &zero);
    if (valp) {
        // Check if it's a major fault (bit 1 of error_code is set)
        if (args->error_code & 0x1) {
            valp->major++;
        } else {
            valp->minor++;
        }
    }
    
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Storage for previous readings
prev_values = {}
interval = 1  # seconds

# Print header
print("Monitoring page fault rates. Press Ctrl+C to stop.")
print("%-8s %-16s %-6s %-10s %-10s %-10s" % 
      ("TIME", "COMM", "PID", "MINOR/s", "MAJOR/s", "TOTAL/s"))

# Handle Ctrl+C
def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main loop to print stats
try:
    while True:
        sleep(interval)
        
        # Get current time
        current_time = strftime("%H:%M:%S")
        
        # Collect and process data
        page_faults = b["page_faults"]
        
        # Prepare data for sorting
        data = []
        
        for k, v in page_faults.items():
            pid = k.pid
            comm = k.comm.decode('utf-8', 'replace')
            minor = v.minor
            major = v.major
            
            # Get previous values
            prev = prev_values.get(pid, (0, 0))
            minor_delta = minor - prev[0]
            major_delta = major - prev[1]
            
            # Store current values for next time
            prev_values[pid] = (minor, major)
            
            # Only include processes with page faults in this interval
            if minor_delta > 0 or major_delta > 0:
                data.append((pid, comm, minor_delta, major_delta))
        
        # Sort by total page faults (minor + major)
        data.sort(key=lambda x: x[2] + x[3], reverse=True)
        
        # Print top processes (limit to 10 to avoid flooding)
        for i, (pid, comm, minor_delta, major_delta) in enumerate(data[:10]):
            total_delta = minor_delta + major_delta
            print("%-8s %-16s %-6d %10.1f %10.1f %10.1f" % 
                  (current_time, comm[:16], pid, 
                   minor_delta / interval, 
                   major_delta / interval,
                   total_delta / interval))
        
        if data:
            print("")
except KeyboardInterrupt:
    signal_handler(0, 0)
except Exception as e:
    print(f"Error: {e}")


"""
Monitoring page fault rates. Press Ctrl+C to stop.
TIME     COMM             PID    MINOR/s    MAJOR/s    TOTAL/s   
19:45:24 code             3275       2073.0        0.0     2073.0
19:45:24 code             3371         30.0      464.0      494.0
19:45:24 ps               37091       413.0       36.0      449.0
19:45:24 cpuUsage.sh      37093       118.0      260.0      378.0
19:45:24 Chrome_ChildIOT  3829        233.0        4.0      237.0
19:45:24 chrome           3765        147.0        2.0      149.0
19:45:24 sed              37094        95.0       10.0      105.0
19:45:24 sleep            37102        63.0        6.0       69.0
19:45:24 cat              37097        61.0        6.0       67.0
19:45:24 cat              37096        60.0        6.0       66.0

19:45:25 code             3275       2072.0        0.0     2072.0
19:45:25 cpuUsage.sh      37093       122.0      762.0      884.0
19:45:25 ps               37091       413.0       36.0      449.0
19:45:25 chrome           3765        147.0        2.0      149.0
19:45:25 code             3259        117.0        1.0      118.0
19:45:25 cpuUsage.sh      37117        37.0       38.0       75.0
19:45:25 cpuUsage.sh      37107        37.0       38.0       75.0
19:45:25 cpuUsage.sh      37111        37.0       38.0       75.0
19:45:25 cpuUsage.sh      37113        37.0       38.0       75.0
19:45:25 cpuUsage.sh      37109        37.0       38.0       75.0

"""