#!/usr/bin/python3
#
# biopwise.py - Block Device I/O Per-Process Analyzer
#
# This script uses eBPF to track block device I/O activity by process, providing:
# - Read and write statistics per process
# - Synchronous vs asynchronous I/O tracking
# - I/O request size analysis
# - Device filtering capabilities
# - Detailed summaries of top I/O consumers
#
# USAGE: sudo ./biopwise.py [-h] [-r MAXROWS] [--sort {pid,comm,read,write,avg_size,sync,async_val,total}]
#                           [--device DEVICE] [--top TOP_N] [interval] [count]
#
# Dependencies: BCC (BPF Compiler Collection), Python 3, root privileges

from __future__ import print_function
import argparse
import time
import re  # For parsing /proc/partitions
import os  # For checking device files and getting major/minor numbers
from bcc import BPF
from bcc.utils import printb  # Python 2/3 compatible printing
import signal # For signal handling (Ctrl+C)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Summarize block device I/O activity per process sequentially.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
    sudo ./biopwise.py             # Print stats every 1 second (sort by total)
    sudo ./biopwise.py 2 5         # print 2 second summaries, 5 times
    sudo ./biopwise.py --sort write  # sort by bytes written
    sudo ./biopwise.py --sort avg_size # sort by average I/O size
    sudo ./biopwise.py --sort sync # sort by sync IO count
    sudo ./biopwise.py --device sda  # Trace I/O only for device 'sda'
    sudo ./biopwise.py --top 5       # Show top 5 processes in summary section
    sudo ./biopwise.py -r 10         # Show max 10 process lines per interval
"""
    )
    parser.add_argument("interval", nargs="?", default=1, type=int,
                        help="output interval, in seconds (default 1)")
    parser.add_argument("count", nargs="?", default=None, type=int,
                        help="number of outputs (default forever)")
    parser.add_argument("-r", "--maxrows", default=20, type=int,
                        help="maximum process rows to print per interval, default 20")
    parser.add_argument("--sort", default="total",
                        choices=["pid", "comm", "read", "write", "avg_size", "sync", "async_val", "total"],
                        help="sort by column, default 'total' bytes (read+write)")
    parser.add_argument("--device", type=str, default=None,
                        help="filter I/O by specific device name (e.g., sda, nvme0n1)")
    parser.add_argument("--top", dest="top_n", type=int, default=3,
                        help="number of top processes to show in summary, default 3")

    args = parser.parse_args()

    if args.sort == "async_val":
        args.sort_internal = "async_ios"
    else:
        args.sort_internal = args.sort

    return args

# --- BPF C Code ---
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
#include <linux/blk_types.h>

// Structure to store I/O statistics
struct val_t {
    u64 bytes;
    u64 ios;
    u64 sync_ios;
    u64 async_ios;
};

// Structure for the key of the BPF map
struct key_t {
    dev_t dev;
    u64 slot; // PID << 1 | R/W
    char comm[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t, struct val_t);

TRACEPOINT_PROBE(block, block_rq_issue)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct val_t *valp, zero = {};
    struct key_t key = {};

    key.dev = args->dev;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    int is_write = 0;
    int is_sync = 0;

    // Simplified check based on common rwbs format (e.g., "W", "WS", "R", "RS")
    if (args->rwbs[0] == 'W') {
        is_write = 1;
    } else if (args->rwbs[0] != 'R') {
         return 0; // Skip non R/W ops
    }

    // Check second character for Sync flag 'S'
    if (args->rwbs[1] == 'S') {
        is_sync = 1;
    }

    key.slot = ((u64)pid << 1) | is_write;

    valp = counts.lookup_or_try_init(&key, &zero);
    if (valp) {
        lock_xadd(&valp->bytes, args->bytes);
        lock_xadd(&valp->ios, 1);
        if (is_sync) {
            lock_xadd(&valp->sync_ios, 1);
        } else {
            lock_xadd(&valp->async_ios, 1);
        }
    }
    return 0;
}
"""

def get_device_map():
    """
    Parse /proc/partitions to build a map of (major,minor) device numbers to device names.
    This allows us to translate device numbers to human-readable names.
    """
    dev_map = {}
    try:
        with open('/proc/partitions', 'r') as f:
            lines = f.readlines()[2:]
        pattern = re.compile(r'\s*(\d+)\s+(\d+)\s+(\d+)\s+([\w\d]+[\w\d\-\_]*)$')
        for line in lines:
            match = pattern.match(line.strip())
            if match:
                major, minor, _, name = match.groups()
                dev_map[(int(major), int(minor))] = name
    except FileNotFoundError:
        print("Warning: /proc/partitions not found. Device names will be unavailable.", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Error reading /proc/partitions: {e}. Device names may be missing.", file=sys.stderr)
    return dev_map

def format_bytes(byte_count):
    """Convert byte count to human-readable format with appropriate unit"""
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024**2:
        return f"{byte_count / 1024:.1f}K"
    elif byte_count < 1024**3:
        return f"{byte_count / (1024**2):.1f}M"
    else:
        return f"{byte_count / (1024**3):.1f}G"

# Main Execution Logic
def run_biopwise(args):
    """Sets up BPF, runs the main loop, prints data sequentially."""

    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Error initializing BPF: {e}", file=sys.stderr)
        print("Ensure you have kernel headers installed and are running as root.", file=sys.stderr)
        exit(1)

    device_map = get_device_map()
    prev_data = {}
    count_down = args.count
    interval_num = 0
    exiting = False
    is_first_interval = True

    # Exit on Ctrl+C
    def signal_handler(sig, frame):
        nonlocal exiting
        print("\nExiting biopwise...")
        exiting = True
    signal.signal(signal.SIGINT, signal_handler)

    print(f"Starting biopwise: interval={args.interval}s, count={args.count or 'forever'}, "
          f"sort={args.sort}, filter={args.device or 'None'}, maxrows={args.maxrows}, top={args.top_n}")
    print("Press Ctrl+C to exit.")

    while not exiting:
        if args.count is not None:
            if count_down == 0:
                break
            count_down -= 1

        # Sleep and Read BPF Map
        try:
            time.sleep(args.interval)
            interval_num += 1
            cumulative_counts = b.get_table("counts")
        except KeyboardInterrupt: # Catch sleep interruption
             exiting = True
             continue
        except Exception as e:
            print(f"\nError during sleep or map read: {e}", file=sys.stderr)
            exiting = True
            continue

        # Process Data & Calculate Deltas
        deltas = {}
        global_totals = {'rbytes': 0, 'wbytes': 0, 'rios': 0, 'wios': 0, 'sync': 0, 'async_ios': 0}
        new_prev_data = {}

        for key, current_val in cumulative_counts.items():
            py_key = (key.dev, key.slot, key.comm)

            pid = key.slot >> 1
            is_write = key.slot & 1
            major = os.major(key.dev)
            minor = os.minor(key.dev)
            dev_tuple = (major, minor)
            dev_name = device_map.get(dev_tuple, f"{major}:{minor}")
            comm = key.comm.decode('utf-8', 'replace')

            if args.device and dev_name != args.device:
                continue

            prev_val = prev_data.get(py_key, None)

            delta_bytes = current_val.bytes - (prev_val.bytes if prev_val else 0)
            delta_ios = current_val.ios - (prev_val.ios if prev_val else 0)
            delta_sync_ios = current_val.sync_ios - (prev_val.sync_ios if prev_val else 0)
            delta_async_ios = current_val.async_ios - (prev_val.async_ios if prev_val else 0)

            # Store current value for next interval before checking for zero delta
            new_prev_data[py_key] = current_val

            if delta_bytes == 0 and delta_ios == 0 and delta_sync_ios == 0 and delta_async_ios == 0:
                 continue # Skip delta aggregation if no activity for this specific key

            # Aggregate deltas per process
            agg_key = (pid, comm)
            if agg_key not in deltas:
                deltas[agg_key] = {
                    'rbytes': 0, 'wbytes': 0, 'rios': 0, 'wios': 0,
                    'sync_ios': 0, 'async_ios': 0, 'total_bytes': 0, 'total_ios': 0,
                    'avg_size': 0.0, 'devices': set()
                }

            entry = deltas[agg_key]
            entry['devices'].add(dev_name)

            if is_write:
                entry['wbytes'] += delta_bytes
                entry['wios'] += delta_ios
            else:
                entry['rbytes'] += delta_bytes
                entry['rios'] += delta_ios

            entry['sync_ios'] += delta_sync_ios
            entry['async_ios'] += delta_async_ios

            entry['total_bytes'] = entry['rbytes'] + entry['wbytes']
            entry['total_ios'] = entry['rios'] + entry['wios']

            if entry['total_ios'] > 0:
                entry['avg_size'] = entry['total_bytes'] / float(entry['total_ios'])
            else:
                entry['avg_size'] = 0.0

            # Update Global Totals (Only after the first interval)
            if not is_first_interval:
                if is_write:
                    global_totals['wbytes'] += delta_bytes
                    global_totals['wios'] += delta_ios
                else:
                    global_totals['rbytes'] += delta_bytes
                    global_totals['rios'] += delta_ios
                global_totals['sync'] += delta_sync_ios
                global_totals['async_ios'] += delta_async_ios

        # Prepare for Next Interval
        prev_data = new_prev_data

        # Skip Printing on First Interval
        if is_first_interval:
            is_first_interval = False
            print("\n(First interval skipped - collecting baseline)")
            continue # Go to the next interval

        # Sorting
        line_data = [{'pid': pid, 'comm': comm, **stats} for (pid, comm), stats in deltas.items()]

        if args.sort_internal == 'pid': sort_key_func = lambda x: x['pid']
        elif args.sort_internal == 'comm': sort_key_func = lambda x: x['comm']
        elif args.sort_internal == 'read': sort_key_func = lambda x: x['rbytes']
        elif args.sort_internal == 'write': sort_key_func = lambda x: x['wbytes']
        elif args.sort_internal == 'avg_size': sort_key_func = lambda x: x['avg_size']
        elif args.sort_internal == 'sync': sort_key_func = lambda x: x['sync_ios']
        elif args.sort_internal == 'async_ios': sort_key_func = lambda x: x['async_ios']
        else: sort_key_func = lambda x: x['total_bytes'] # 'total' or default

        sorted_data = sorted(line_data, key=sort_key_func, reverse=True)

        print(f"\n--- Interval {interval_num} ({time.strftime('%H:%M:%S')}) ---")

        # Print Header
        header_title = f"biopwise (sort: {args.sort}, filter: {args.device or 'None'})"
        header_cols = "{:<6} {:<16} {:<8} {:>9} {:>9} {:>7} {:>7} {:>9} {:>7} {:>7}".format(
            "PID", "COMM", "DEVICES",
            "READ", "WRITE", "R_IOS", "W_IOS",
            "AVG_SZ", "SYNCS", "ASYNCS"
        )
        print(header_title)
        print(header_cols)

        # Print Process Data (Limited by maxrows)
        rows_to_display = min(args.maxrows, len(sorted_data))
        for i in range(rows_to_display):
            item = sorted_data[i]

            if args.device:
                device_str = args.device
            else:
                devs_list = sorted(list(item['devices']))
                devs_str = ",".join(devs_list)
                if len(devs_str) > 8:
                    devs_str = devs_str[:7] + "*"
                device_str = devs_str

            line = "{:<6} {:<16.16} {:<8.8} {:>9} {:>9} {:>7d} {:>7d} {:>9} {:>7d} {:>7d}".format(
                item['pid'], item['comm'], device_str,
                format_bytes(item['rbytes']), format_bytes(item['wbytes']),
                item['rios'], item['wios'],
                format_bytes(item['avg_size']),
                item['sync_ios'], item['async_ios']
            )
            print(line)

        if len(sorted_data) > rows_to_display:
            print("...") # Indicate truncation

        # Print Summary Section
        print("---") # Separator before summary

        # Print Overall Totals
        total_line = "Totals: R:{:<9} W:{:<9} IOs(R):{:<7d} IOs(W):{:<7d} Sync:{:<7d} Async:{:<7d}".format(
            format_bytes(global_totals['rbytes']), format_bytes(global_totals['wbytes']),
            global_totals['rios'], global_totals['wios'],
            global_totals['sync'], global_totals['async_ios']
        )
        print(total_line)

        # Print Top N Processes
        top_n = min(args.top_n, len(sorted_data))
        if top_n > 0:
            print(f"Top {top_n} Procs ({args.sort}):")
            for i in range(top_n): # Print all top_n lines
                item = sorted_data[i]
                metric_val = sort_key_func(item)
                if args.sort_internal in ['read', 'write', 'total', 'avg_size']:
                    metric_str = format_bytes(metric_val)
                else: # pid, ios, sync, async
                    metric_str = str(int(metric_val))

                top_line = f"  {item['pid']:<6} {item['comm']:<16.16} ({metric_str})"
                print(top_line)

        # Print Interval End Separator
        print("=======================================")

    


# --- Script Entry Point ---
if __name__ == "__main__":
    import sys
    arguments = parse_arguments()
    run_biopwise(arguments)