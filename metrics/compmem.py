#!/usr/bin/python3
#
# compmem.py - Analyze system memory usage and detect potential memory leaks
#
# This script uses eBPF to track kernel memory allocations and deallocations, providing:
# - Per-process kernel memory usage (total allocated kernel memory and number of active allocations)
# - Per-process user-space memory usage summaries (RSS, VmSize from /proc)
# - Potential kernel memory leaks (unfreed allocations)
# - System-wide memory statistics (total, used, free, and available memory)
#
# USAGE: compmem.py [-h] [-p PID] [-i INTERVAL] [-c COUNT] [-d] [-t] [-m MIN_SIZE] [-T TOP]
#
# Dependencies: BCC (BPF Compiler Collection), Python 3, root privileges, compatible kernel headers.

from bcc import BPF
from time import sleep
import argparse
import os
import sys
import signal
import datetime
import platform
import pwd # For getting process user

# Default configuration values
DEFAULT_INTERVAL = 4  # Report interval in seconds
DEFAULT_COUNT = -1    # Number of reports (-1 for infinite)
DEFAULT_TOP = 10      # Number of top processes to display
DEFAULT_MIN_SIZE = 0  # Minimum allocation size to track (bytes)

# Debug flag for verbose output
debug_enabled = False

def debug_print(msg):
    """Print debug messages if debug mode is enabled."""
    if debug_enabled:
        print(f"[DEBUG] {msg}")

# Handle Ctrl+C gracefully
def signal_handler(sig, frame):
    """Exit cleanly on Ctrl+C by handling SIGINT."""
    print("\nDetected Ctrl+C, exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description="Track kernel memory allocations and detect potential leaks using eBPF, includes user-space memory summary.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-p", "--pid", type=int, default=-1,
    help="Trace only this PID for kernel allocations; User-space info shown for all top processes.")
parser.add_argument("-i", "--interval", type=int, default=DEFAULT_INTERVAL,
    help="Print summary every INTERVAL seconds")
parser.add_argument("-c", "--count", type=int, default=DEFAULT_COUNT,
    help="Number of reports to print before exiting (-1 for infinite)")
parser.add_argument("-d", "--debug", action="store_true",
    help="Enable debug output")
parser.add_argument("-t", "--trace", action="store_true",
    help="Print trace messages for each kernel alloc/free event")
parser.add_argument("-m", "--min-size", type=int, default=DEFAULT_MIN_SIZE,
    help="Minimum kernel allocation size to track in bytes")
parser.add_argument("-T", "--top", type=int, default=DEFAULT_TOP,
    help="Show this many top processes based on kernel memory usage")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)  # Hidden option to print eBPF code

args = parser.parse_args()
debug_enabled = args.debug
debug_print("Debug mode enabled")

# Check kernel version for compatibility
kernel_version = platform.release()
debug_print(f"Running on kernel {kernel_version}")

# BPF program for kernel memory tracking
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/mm.h>
#include <linux/sched.h>

// Data structure to store allocation details
struct alloc_info_t {
    u64 size;           // Size of the allocation in bytes
    u64 timestamp_ns;   // Time of allocation (nanoseconds since boot)
    int stack_id;       // ID of the stack trace for this allocation
};

// Per-process memory statistics (kernel allocations)
struct proc_mem_info_t {
    u64 total_allocated;    // Total kernel memory currently allocated by this process via tracked functions
    u64 active_allocations; // Number of unfreed kernel allocations
};

// Statistics for potential memory leaks by stack trace
struct combined_alloc_info_t {
    u64 total_size;         // Total size of unfreed allocations for this stack
    u64 number_of_allocs;   // Number of unfreed allocations
};

// BPF maps
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);           // Maps kernel alloc address to its info
BPF_HASH(proc_mem, u32, struct proc_mem_info_t);               // Maps PID to process kernel memory stats
BPF_HASH(sizes, u64, u64);                                     // Temporary storage for allocation sizes (pid_tgid -> size)
BPF_STACK_TRACE(stack_traces, 10240);                          // Stores stack traces
BPF_HASH(combined_allocs, u64, struct combined_alloc_info_t, 10240); // Leak stats by stack ID

// Helper function to update process stats when kernel memory is allocated
static inline void update_proc_stats_alloc(u32 pid, u64 size) {
    struct proc_mem_info_t *info = proc_mem.lookup(&pid);
    struct proc_mem_info_t new_info = {0};

    if (info != 0) {
        new_info = *info;
    }

    new_info.total_allocated += size;
    new_info.active_allocations += 1;
    proc_mem.update(&pid, &new_info);

    #ifdef DEBUG
    bpf_trace_printk("Process %u kernel allocated %lu bytes\\n", pid, size);
    #endif
}

// Helper function to update process stats when kernel memory is freed
static inline void update_proc_stats_free(u32 pid, u64 size) {
    struct proc_mem_info_t *info = proc_mem.lookup(&pid);
    if (info == 0) {
        return;
    }

    struct proc_mem_info_t new_info = *info;
    if (size <= new_info.total_allocated) {
        new_info.total_allocated -= size;
    } else {
        new_info.total_allocated = 0; // Prevent underflow
    }
    if (new_info.active_allocations > 0) {
        new_info.active_allocations -= 1;
    } else {
        // Should not happen if allocs map is consistent, but handle defensively
        new_info.active_allocations = 0;
    }

    proc_mem.update(&pid, &new_info);

    #ifdef DEBUG
    bpf_trace_printk("Process %u kernel freed %lu bytes\\n", pid, size);
    #endif
}

// Helper function to track potential leaks by stack trace on allocation
static inline void update_statistics_add(int stack_id, u64 sz) {
    if (stack_id < 0) return; // Ignore invalid stack IDs
    u64 stack_id_64 = (u64)stack_id; // Use u64 for map key
    struct combined_alloc_info_t *cinfo = combined_allocs.lookup(&stack_id_64);
    struct combined_alloc_info_t new_cinfo = {0};

    if (cinfo != 0) {
        new_cinfo = *cinfo;
    }

    new_cinfo.total_size += sz;
    new_cinfo.number_of_allocs += 1;
    combined_allocs.update(&stack_id_64, &new_cinfo);
}

// Helper function to update leak stats on free
static inline void update_statistics_del(int stack_id, u64 sz) {
     if (stack_id < 0) return; // Ignore invalid stack IDs
     u64 stack_id_64 = (u64)stack_id; // Use u64 for map key
     struct combined_alloc_info_t *cinfo = combined_allocs.lookup(&stack_id_64);
     if (cinfo == 0) {
         return;
     }

    struct combined_alloc_info_t new_cinfo = *cinfo;
    if (sz <= new_cinfo.total_size) {
        new_cinfo.total_size -= sz;
    } else {
        new_cinfo.total_size = 0; // Prevent underflow
    }
    if (new_cinfo.number_of_allocs > 0) {
        new_cinfo.number_of_allocs -= 1;
    }

    // Clean up map entry if no outstanding allocations for this stack trace
    if (new_cinfo.total_size == 0 && new_cinfo.number_of_allocs == 0) {
        combined_allocs.delete(&stack_id_64);
    } else {
        combined_allocs.update(&stack_id_64, &new_cinfo);
    }
}

// Handle memory free event
static inline int handle_free_enter(void *ctx, void *address) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // Apply PID filter if set
    if (TARGET_PID != -1 && TARGET_PID != pid) {
        return 0;
    }

    if (address == NULL) {
        return 0; // Ignore NULL frees
    }
    u64 addr = (u64)address;
    struct alloc_info_t *info = allocs.lookup(&addr);
    if (info == 0) {
        return 0;  // Not an allocation we tracked
    }

    // Get allocation details before deleting
    u64 size = info->size;
    int stack_id = info->stack_id;

    allocs.delete(&addr); // Delete allocation record first
    update_proc_stats_free(pid, size);      // Update process stats
    update_statistics_del(stack_id, size);  // Update leak stats by stack

    #ifdef TRACE_ENABLED
    bpf_trace_printk("free entered, address = %lx, size = %lu\\n", address, size);
    #endif
    return 0;
}

// Raw tracepoint for kmalloc: Tracks kernel memory allocations
RAW_TRACEPOINT_PROBE(kmalloc)
{
    // TP_PROTO(unsigned long call_site, const void *ptr,
    //  size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
    const void *ptr = (const void *)ctx->args[1];
    size_t bytes_alloc = (size_t)ctx->args[3]; // Actual allocated size

    // Filter size *before* doing more work
    if (bytes_alloc < MIN_SIZE_FILTER) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // Apply PID filter if set
    if (TARGET_PID != -1 && TARGET_PID != pid) {
        return 0;
    }

    // Record allocation details if successful (ptr != NULL)
    if (ptr != NULL) {
        struct alloc_info_t info = {0};
        info.size = bytes_alloc;
        info.timestamp_ns = bpf_ktime_get_ns();
        // Get stack trace - use BPF_F_REUSE_STACKID for efficiency
        info.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);

        if (info.stack_id >= 0) {
            u64 addr = (u64)ptr;
            allocs.update(&addr, &info);
            update_statistics_add(info.stack_id, info.size);
            update_proc_stats_alloc(pid, info.size);

            #ifdef TRACE_ENABLED
            bpf_trace_printk("kmalloc exit, size = %lu, result = %lx, stack_id = %d\\n", info.size, addr, info.stack_id);
            #endif
        } else {
             #ifdef DEBUG
             bpf_trace_printk("kmalloc failed to get stackid, size = %lu\\n", info.size);
             #endif
        }
    } else {
        #ifdef TRACE_ENABLED
        bpf_trace_printk("kmalloc failed, req_size = %lu\\n", (size_t)ctx->args[2]);
        #endif
    }
    return 0;
}

// Raw tracepoint for kfree: Tracks memory deallocations
RAW_TRACEPOINT_PROBE(kfree)
{
    // TP_PROTO(unsigned long call_site, const void *ptr)
    const void *ptr = (const void *)ctx->args[1];
    return handle_free_enter(ctx, (void *)ptr); // Cast needed
}
"""

# Apply runtime configurations to eBPF code
bpf_text = bpf_text.replace("MIN_SIZE_FILTER", str(args.min_size))
bpf_text = bpf_text.replace("TARGET_PID", str(args.pid))
if args.trace:
    bpf_text = "#define TRACE_ENABLED\n" + bpf_text
if args.debug:
    bpf_text = "#define DEBUG\n" + bpf_text

if args.ebpf:
    print(bpf_text)
    exit()

# Load the eBPF program into the kernel
debug_print("Compiling and loading BPF program")
try:
    b = BPF(text=bpf_text)
    debug_print("BPF program loaded successfully")
    # Check if tracepoints attached correctly (basic check)
    if not BPF.tracepoint_exists("kmem", "kmalloc"):
         print("Warning: Raw tracepoint kmem:kmalloc not found. Kernel tracing might not work.", file=sys.stderr)
    if not BPF.tracepoint_exists("kmem", "kfree"):
         print("Warning: Raw tracepoint kmem:kfree not found. Kernel tracing might not work.", file=sys.stderr)
except Exception as e:
    print(f"Error loading BPF program: {e}", file=sys.stderr)
    print("Ensure BCC is installed, running as root, and kernel headers match your kernel version.", file=sys.stderr)
    sys.exit(1)


def get_system_memory_stats():
    """Read system-wide memory stats from /proc/meminfo (in bytes)."""
    stats = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    key = parts[0].strip()
                    value_str = parts[1].strip().split()[0]
                    try:
                        # Values are in kB, convert to bytes
                        stats[key] = int(value_str) * 1024
                    except ValueError:
                        debug_print(f"Could not parse value for {key}: {value_str}")
                        stats[key] = 0
    except FileNotFoundError:
        debug_print("Error: /proc/meminfo not found.")
        return {} # Return empty dict if file not found
    except Exception as e:
        debug_print(f"Error reading /proc/meminfo: {e}")
    return stats

def get_proc_status(pid):
    """Read specific memory fields (VmRSS, VmSize, Uid) from /proc/[pid]/status."""
    proc_stats = {'VmRSS': 0, 'VmSize': 0, 'Uid': -1, 'Name': '[unknown]'}
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Name:'):
                    proc_stats['Name'] = line.split(':', 1)[1].strip()
                elif line.startswith('VmRSS:'):
                    # Value is in kB, convert to bytes
                    proc_stats['VmRSS'] = int(line.split()[1]) * 1024
                elif line.startswith('VmSize:'):
                    # Value is in kB, convert to bytes
                    proc_stats['VmSize'] = int(line.split()[1]) * 1024
                elif line.startswith('Uid:'):
                    # Get the effective UID
                    proc_stats['Uid'] = int(line.split()[1])
    except FileNotFoundError:
        # Process likely exited between BPF map read and /proc read
        debug_print(f"Process {pid} exited before reading /proc/{pid}/status.")
        proc_stats['Name'] = '[exited]'
        return proc_stats # Return default values
    except Exception as e:
        debug_print(f"Error reading /proc/{pid}/status: {e}")
        return proc_stats # Return potentially partial/default values on other errors
    return proc_stats

def get_username(uid):
    """Convert UID to username."""
    if uid == -1:
        return "[unknown]"
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid) # Return UID if username not found
    except Exception as e:
        debug_print(f"Error getting username for UID {uid}: {e}")
        return str(uid)


def human_readable_size(size_bytes):
    """Convert size in bytes to human-readable format (e.g., KB, MB, GB)."""
    if size_bytes is None or size_bytes < 0:
        return "N/A"
    if size_bytes == 0:
        return "0B"
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    i = 0
    size_bytes = float(size_bytes)
    while size_bytes >= 1024 and i < len(units) - 1:
        size_bytes /= 1024.0
        i += 1
    # Show more precision for smaller units
    if i < 2: # B, KB
         return f"{size_bytes:.1f}{units[i]}"
    else: # MB, GB, ...
         return f"{size_bytes:.2f}{units[i]}"

def print_memory_usage():
    """Print system memory usage, process stats (kernel & user), and potential leaks."""
    sys_stats = get_system_memory_stats()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n[{timestamp}] Memory Usage Report")
    print("=" * 100)

    # System-wide memory stats
    total_mem = sys_stats.get('MemTotal', 0)
    free_mem = sys_stats.get('MemFree', 0)
    available_mem = sys_stats.get('MemAvailable', free_mem)
    buffers = sys_stats.get('Buffers', 0)
    cached = sys_stats.get('Cached', 0)
    slab = sys_stats.get('Slab', 0)
    used_mem = total_mem - available_mem
    used_percent = (used_mem / total_mem * 100) if total_mem > 0 else 0
    print("System Memory:")
    print(f"  Total:     {human_readable_size(total_mem):>10s}   Used:      {human_readable_size(used_mem):>10s} ({used_percent:.1f}%)")
    print(f"  Available: {human_readable_size(available_mem):>10s}   Free:      {human_readable_size(free_mem):>10s}")
    print(f"  Buffers:   {human_readable_size(buffers):>10s}   Cached:    {human_readable_size(cached):>10s}   Slab: {human_readable_size(slab):>10s}")

    # Process memory usage table
    print("\nTop Process Memory Usage (Sorted by Kernel Allocations tracked by BPF):")
    proc_stats = []
    bpf_proc_mem = b["proc_mem"]
    for pid_key, mem_info in bpf_proc_mem.items_lookup_and_delete_batch():
        if pid_key is None: continue
        pid = pid_key.value
        if pid < 300 and pid != 0: # Skip kernel threads roughly, keep pid 0 (swapper) if relevant
             continue
        p_status = get_proc_status(pid)
        if p_status['Name'] == '[exited]' or (p_status['VmRSS'] == 0 and p_status['VmSize'] == 0 and mem_info.total_allocated == 0):
            try:
                del bpf_proc_mem[pid_key]
            except KeyError:
                 pass
            continue
        username = get_username(p_status['Uid'])
        proc_stats.append({
            'pid': pid, 'user': username, 'comm': p_status['Name'],
            'kernel_allocated': mem_info.total_allocated, 'kernel_allocations': mem_info.active_allocations,
            'rss': p_status['VmRSS'], 'vmsize': p_status['VmSize'],
        })

    proc_stats.sort(key=lambda x: x['kernel_allocated'], reverse=True)
    print("\n%6s %-10s %-15s %15s %10s %10s %10s" %
          ("PID", "USER", "PROCESS", "KERNEL_ALLOC", "KERNEL_CNT", "RSS", "VMSIZE"))
    print("%6s %-10s %-15s %15s %10s %10s %10s" %
          ("------", "----------", "---------------", "---------------", "----------", "----------", "----------"))
    for i, p in enumerate(proc_stats[:args.top]):
        comm = p['comm'][:15]
        print("%6d %-10.10s %-15s %15s %10d %10s %10s" % (
            p['pid'], p['user'], comm,
            human_readable_size(p['kernel_allocated']), p['kernel_allocations'],
            human_readable_size(p['rss']), human_readable_size(p['vmsize'])
        ))
    if not proc_stats:
        print("  No process kernel allocations tracked yet (or processes filtered out).")

    # Potential kernel memory leaks section
    print("\nPotential Kernel Memory Leaks (Unfreed BPF-Tracked Allocations by Stack ID):")
    try:
        # Use the combined_allocs map directly for efficiency
        combined_allocs_map = b.get_table("combined_allocs")
        stack_traces_map = b.get_table("stack_traces")

        leak_by_stack = {}

        if combined_allocs_map:
            debug_print("Using combined_allocs map for leak report.")
            for stack_id_key, cinfo in combined_allocs_map.items():
                stack_id = stack_id_key.value
                if stack_id < 0 or cinfo.number_of_allocs == 0:
                    continue
                leak_by_stack[stack_id] = {
                     'size': cinfo.total_size,
                     'count': cinfo.number_of_allocs,
                     }
        else: # Fallback to iterating the allocs map (less efficient)
            debug_print("Falling back to iterating allocs map for leak report.")
            allocs_map = b.get_table("allocs")
            for address, info in allocs_map.items():
                if info.stack_id < 0: continue
                if info.stack_id not in leak_by_stack:
                    leak_by_stack[info.stack_id] = {'size': 0, 'count': 0}
                leak_by_stack[info.stack_id]['size'] += info.size
                leak_by_stack[info.stack_id]['count'] += 1

        sorted_leaks = sorted(leak_by_stack.items(), key=lambda item: item[1]['size'], reverse=True)
        total_leak_size = sum(leak['size'] for _, leak in sorted_leaks)
        total_leak_count = sum(leak['count'] for _, leak in sorted_leaks)

        if sorted_leaks:
            print(f"  Showing top {min(args.top, len(sorted_leaks))} potential leaks based on size:")
            for i, (stack_id, leak) in enumerate(sorted_leaks[:args.top]):
                print(f"  Leak {i+1}: {human_readable_size(leak['size'])} in {leak['count']} allocations (Stack ID: {stack_id})")
        else:
            print("  No potential kernel memory leaks detected (no unfreed BPF-tracked allocations).")

        print(f"\nTotal potential kernel leaks tracked: {human_readable_size(total_leak_size)} in {total_leak_count} allocations")

    except Exception as e:
         print(f"\nError gathering potential leak data: {e}")
         import traceback
         debug_print(traceback.format_exc())

    print("=" * 100)

# Main Execution Loop
print(f"Memory usage analyzer started. PID: {os.getpid()}")
print(f"Reporting every {args.interval} seconds. Press Ctrl+C to exit.")
if args.pid != -1:
    print(f"Monitoring kernel allocations for PID {args.pid} only.")
    # Check if target PID exists
    try:
        os.kill(args.pid, 0) # Send signal 0 to check existence without killing
    except OSError:
        print(f"Warning: Target PID {args.pid} does not exist or permission denied.")
    except Exception as e:
        print(f"Warning: Could not check target PID {args.pid}: {e}")

else:
    print("Monitoring kernel allocations for all relevant processes.")
if args.min_size > 0:
    print(f"Ignoring kernel allocations smaller than {args.min_size} bytes.")

count = 0
try:
    while True:
        sleep(args.interval)
        print_memory_usage()
        count += 1
        if args.count > 0 and count >= args.count:
            print(f"\nCompleted {count} reports, exiting...")
            break
except KeyboardInterrupt:
    print("\nDetected Ctrl+C, cleaning up and exiting...")
except Exception as e:
    print(f"\nAn unexpected error occurred: {e}")
    import traceback
    print(traceback.format_exc())
finally:
    # Clean up BPF resources if needed (though BCC often handles this on exit)
    if 'b' in locals():
        b.cleanup()
    print("Analysis stopped.")