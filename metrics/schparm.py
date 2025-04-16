#!/usr/bin/env python3
#
# schparm.py - Monitor and report on scheduler parameters of processes
#
# This script uses eBPF to track scheduler events and process lifecycle, providing:
# - Process scheduling parameters (priority, policy, nice values)
# - Runtime metrics and context switch statistics
# - Parent-child process relationships
# - Per-CPU tracking of scheduling events
# 
# USAGE: schparm.py
#
# Dependencies: BCC (BPF Compiler Collection), Python 3, root privileges, Linux kernel with tracepoints.

from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import os
import signal
import sys

# eBPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

struct sched_data_t {
    u32 pid;
    u32 ppid;
    u32 cpu;
    char comm[TASK_COMM_LEN];
    s32 prio;           // scheduling priority
    s32 nice;           // nice value
    u32 policy;         // scheduling policy
    u64 runtime;        // runtime in nanoseconds
    u32 voluntary_ctx;  // voluntary context switches
    u32 nonvol_ctx;     // non-voluntary context switches
};

BPF_PERF_OUTPUT(sched_events);
BPF_HASH(start_time, u32, u64);
BPF_HASH(vol_switches, u32, u32);
BPF_HASH(nonvol_switches, u32, u32);

// Trace when a process is scheduled in
TRACEPOINT_PROBE(sched, sched_switch) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    
    // Record the timestamp when scheduled out
    // Access prev_pid and prev_state directly from args
    u32 prev_pid = args->prev_pid;
    u32 prev_state = args->prev_state;
    
    if (prev_pid != 0) {
        start_time.update(&prev_pid, &ts);
        
        // Update context switch counters
        if (prev_state == TASK_RUNNING) {
            // Non-voluntary context switch (still runnable but preempted)
            u32 *nonvol = nonvol_switches.lookup(&prev_pid);
            u32 val = nonvol ? *nonvol + 1 : 1;
            nonvol_switches.update(&prev_pid, &val);
        } else {
            // Voluntary context switch (blocked)
            u32 *vol = vol_switches.lookup(&prev_pid);
            u32 val = vol ? *vol + 1 : 1;
            vol_switches.update(&prev_pid, &val);
        }
    }
    
    return 0;
}

// Get scheduling parameters when a process exits
int trace_sched_process_exit(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    
    struct sched_data_t data = {};
    data.pid = pid;
    data.ppid = task->real_parent->tgid;
    data.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get scheduling parameters
    data.prio = task->prio;
    data.nice = task->static_prio - 120; // Convert to nice value
    data.policy = task->policy;
    
    // Runtime stats
    u64 *start_ts = start_time.lookup(&pid);
    if (start_ts) {
        data.runtime = bpf_ktime_get_ns() - *start_ts;
        start_time.delete(&pid);
    }
    
    // Context switches
    u32 *vol = vol_switches.lookup(&pid);
    if (vol) {
        data.voluntary_ctx = *vol;
        vol_switches.delete(&pid);
    }
    
    u32 *nonvol = nonvol_switches.lookup(&pid);
    if (nonvol) {
        data.nonvol_ctx = *nonvol;
        nonvol_switches.delete(&pid);
    }
    
    sched_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Define policy names
POLICY_NAMES = {
    0: "NORMAL",
    1: "FIFO",
    2: "RR",
    3: "BATCH",
    5: "IDLE",
    6: "DEADLINE"
}

# Initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="do_exit", fn_name="trace_sched_process_exit")

# Output struct definition
class SchedData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("cpu", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("prio", ct.c_int),
        ("nice", ct.c_int),
        ("policy", ct.c_uint),
        ("runtime", ct.c_ulonglong),
        ("voluntary_ctx", ct.c_uint),
        ("nonvol_ctx", ct.c_uint),
    ]

# Process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(SchedData)).contents
    policy_name = POLICY_NAMES.get(event.policy, "UNKNOWN")
    
    print("%-20s %-6d %-6d %-4d %-6d %-6d %-10s %-12.2f %-6d %-6d" % (
        event.comm.decode('utf-8', 'replace'),
        event.pid,
        event.ppid,
        event.cpu,
        event.prio,
        event.nice,
        policy_name,
        event.runtime / 1000000.0,  # ns to ms
        event.voluntary_ctx,
        event.nonvol_ctx
    ))

# Print header
print("Monitoring process scheduling parameters. Press Ctrl+C to stop.")
print("%-20s %-6s %-6s %-4s %-6s %-6s %-10s %-12s %-6s %-6s" % (
    "COMM", "PID", "PPID", "CPU", "PRIO", "NICE", "POLICY", "RUNTIME(ms)", "VOL", "NONVOL"))

# Register event handler
b["sched_events"].open_perf_buffer(print_event)

# Handle Ctrl+C
def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main loop
try:
    while True:
        b.perf_buffer_poll(timeout=1000)
except KeyboardInterrupt:
    signal_handler(0, 0)
except Exception as e:
    print(f"Error: {e}")


"""
Monitoring process scheduling parameters. Press Ctrl+C to stop.
COMM                 PID    PPID   CPU  PRIO   NICE   POLICY     RUNTIME(ms)  VOL    NONVOL
sleep                37220  37211  7    120    0      NORMAL     0.00         0      0     
sed                  37221  37211  5    120    0      NORMAL     0.00         0      0     
cat                  37222  37211  18   120    0      NORMAL     0.00         0      0     
cpuUsage.sh          37223  37211  20   120    0      NORMAL     0.00         0      0     
cat                  37224  37211  21   120    0      NORMAL     0.00         0      0     
cpuUsage.sh          37225  37211  22   120    0      NORMAL     0.00         0      0     
cat                  37226  37211  23   120    0      NORMAL     0.00         0      0     
cpuUsage.sh          37227  37211  18   120    0      NORMAL     0.00         0      0     
cat                  37228  37211  23   120    0      NORMAL     0.00         0      0     
cpuUsage.sh          37229  37211  11   120    0      NORMAL     0.00         0      0     
cat                  37230  37211  11   120    0      NORMAL     0.00         0      0     
cpuUsage.sh          37231  37211  11   120    0      NORMAL     0.00         0      0     
cat                  37232  37211  11   120    0      NORMAL     0.00         0      0     
cpuUsage.sh          37233  37211  11   120    0      NORMAL     0.00         0      0     
cat                  37234  37211  11   120    0      NORMAL     0.00         0      0     
cpuUsage.sh          37235  37211  11   120    0      NORMAL     0.00         0      0     
cpuUsage.sh          37211  37210  23   120    0      NORMAL     0.13         30     1     
sh                   37210  3371   10   120    0      NORMAL     0.00         0      0     
"""