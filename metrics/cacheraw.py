#!/usr/bin/python3
#
# cacheraw.py - Linux Page Cache Usage Analyzer
#
# This script uses eBPF to track Linux page cache activity per process, providing:
# - Read hit/miss statistics by process
# - Write hit/miss statistics by process
# - Page cache utilization metrics
# - Dirty page tracking
# - Customizable display and sorting options
#
# USAGE: cacheraw.py [-h] [-p PID] [-s FIELD] [-r] [interval] [count]
#
# Dependencies: BCC (BPF Compiler Collection), Python 3, root privileges, Linux kernel with kprobes

from __future__ import absolute_import
from __future__ import division
# Do not import unicode_literals until #623 is fixed
# from __future__ import unicode_literals
from __future__ import print_function

import argparse
import pwd
import signal
import sys
from time import sleep, strftime
from collections import defaultdict
from bcc import BPF

# Define possible sorting fields
# We add the raw counts as potential sort keys
FIELDS = (
    "PID",
    "UID",
    "CMD",
    "READ_HITS", # MPA - Mark Page Accessed
    "READ_MISS", # APCL - Add to_ Page Cache LRU
    "WRITE_HITS",# MBD - Mark Buffer Dirty
    "WRITE_MISS",# APD - Account Page Dirtied
    "TOTAL_HITS",# Derived: MPA + MBD
    "TOTAL_MISS",# Derived: APCL + APD
    "DIRTIES",   # MBD + APD (Total writes marked dirty)
    "READ_HIT%", 
    "WRITE_HIT%" 
)
DEFAULT_SORT_FIELD = "TOTAL_HITS"

# Dictionary to map field names to indices in the output tuple
FIELD_MAP = {name: i for i, name in enumerate(FIELDS)}
DEFAULT_SORT_INDEX = FIELD_MAP[DEFAULT_SORT_FIELD]

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h> // For TASK_COMM_LEN

struct key_t {
    // NF_{APCL,MPA,MBD,APD}
    u64 nf; // Represents the kernel function/tracepoint type
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
};

// Enum to identify the source kernel function/tracepoint
enum nf_type {
    NF_APCL, // add_to_page_cache_lru   (Likely Read Miss / Write Allocate)
    NF_MPA,  // mark_page_accessed      (Read Hit)
    NF_MBD,  // mark_buffer_dirty     (Write Hit - buffer layer)
    NF_APD,  // *_account_dirtied / writeback_dirty_* (Write - page marked dirty)
};

BPF_HASH(counts, struct key_t);

// Helper function to increment the count for a specific event type (nf)
static int __do_count(void *ctx, enum nf_type nf) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid; // Not used in key, but useful for potential filtering

    // PID filtering
    if (FILTER_PID && pid != FILTER_PID_VALUE) {
        return 0; // Skip if PID doesn't match filter
    }
    // Optional: Filter kernel threads (usually PID 0 or 2) if desired
    // if (pid == 0) return 0;

    struct key_t key = {};
    key.nf = nf;
    key.pid = pid;
    key.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    // Atomically increment the counter for this key
    counts.increment(key);
    return 0;
}

// Attach points using kprobes and tracepoints
int do_count_apcl(struct pt_regs *ctx) { // add_to_page_cache_lru
    return __do_count(ctx, NF_APCL);
}
int do_count_mpa(struct pt_regs *ctx) {  // mark_page_accessed
    return __do_count(ctx, NF_MPA);
}
int do_count_mbd(struct pt_regs *ctx) {  // mark_buffer_dirty
    return __do_count(ctx, NF_MBD);
}
int do_count_apd(struct pt_regs *ctx) {  // account_page_dirtied / folio_account_dirtied
    return __do_count(ctx, NF_APD);
}
// Use tracepoints as fallback/alternative for accounting dirtied pages
int do_count_apd_tp(void *ctx) {         // writeback:writeback_dirty_folio/page
    return __do_count(ctx, NF_APD);
}
"""

# Function to gather data from /proc/meminfo (remains the same)
def get_meminfo():
    """Get memory statistics from /proc/meminfo"""
    result = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k = line.split(':', 3)
                v = k[1].split()
                result[k[0]] = int(v[0])
    except FileNotFoundError:
        print("Error: /proc/meminfo not found. Cannot display memory stats.", file=sys.stderr)
        return {"Cached": 0, "Buffers": 0}
    except Exception as e:
        print(f"Error reading /proc/meminfo: {e}", file=sys.stderr)
        return {"Cached": 0, "Buffers": 0}
    return result

# Function to process the BPF map data
def get_processes_stats(bpf, sort_field_index=DEFAULT_SORT_INDEX, sort_reverse=True):
    """
    Reads the BPF hash map, aggregates stats per process, calculates derived
    metrics, sorts the results, and clears the map.

    Returns a list of tuples, where each tuple represents a process and contains:
    (PID, UID_str, CMD, MPA, APCL, MBD, APD, TOTAL_HITS, TOTAL_MISS, DIRTIES, READ_HIT%, WRITE_HIT%)
    """
    counts = bpf.get_table("counts")
    stats = defaultdict(lambda: defaultdict(int))

    # Process each key-value pair from the BPF map
    for k, v in counts.items():
        try:
            comm_decoded = k.comm.decode('utf-8', 'replace')
        except UnicodeDecodeError:
            comm_decoded = "decode_err"
        # Aggregate counts per process (PID, UID, COMM) across different nf types
        stats[(k.pid, k.uid, comm_decoded)][k.nf] += v.value

    stats_list = []
    for (pid, uid, comm), count in stats.items():
        # Get counts for different page cache events
        apcl = count.get(0, 0) # NF_APCL
        mpa = count.get(1, 0)  # NF_MPA
        mbd = count.get(2, 0)  # NF_MBD
        apd = count.get(3, 0)  # NF_APD

        # Calculate derived metrics
        read_hits = mpa
        read_misses = apcl 
        write_hits_buffer = mbd
        write_dirty_page = apd
        total_hits = mpa + mbd
        total_misses = apcl + apd
        dirties = mbd + apd 

        # Calculate hit percentages
        total_reads = read_hits + read_misses
        read_hit_perc = (100 * read_hits / total_reads) if total_reads > 0 else 0.0

        total_dirtied_events = mbd + apd
        write_hit_perc = (100 * mbd / total_dirtied_events) if total_dirtied_events > 0 else 0.0

        # Get username
        try:
            username = pwd.getpwuid(uid)[0]
        except KeyError:
            username = str(uid) # Fallback to UID if user not found

        stats_list.append(
            (pid, username, comm,
             read_hits, read_misses, write_hits_buffer, write_dirty_page, # Raw counts
             total_hits, total_misses, dirties, # Derived totals
             read_hit_perc, write_hit_perc # Percentages
             )
        )

    # Sort the list based on the specified field index
    try:
        stats_list.sort(key=lambda stat: stat[sort_field_index], reverse=sort_reverse)
    except IndexError:
        print(f"Warning: Invalid sort field index ({sort_field_index}). Using default.", file=sys.stderr)
        stats_list.sort(key=lambda stat: stat[DEFAULT_SORT_INDEX], reverse=sort_reverse)

    # Clear the BPF table for the next interval
    counts.clear()

    return stats_list


def print_header(sort_by, sort_reverse):
    """Prints the header row for the output."""
    # Adjusted header fields to match the output tuple structure
    header = (
        "PID", "USER", "CMD",
        "RD_HIT", "RD_MISS", "WR_HIT", "WR_MISS_D", # Raw counts (abbreviated)
        "TOTAL_H", "TOTAL_M", "DIRTIES",            # Derived totals
        "RD_HIT%", "WR_HIT%"                         # Percentages
    )
    sort_indicator = "<" if sort_reverse else ">"
    header_line = "{:<8} {:<8} {:<16} {:>8} {:>8} {:>8} {:>10} {:>9} {:>9} {:>9} {:>9} {:>9}".format(*header)

    # Mark the sorted column
    try:
        sort_idx_in_header = FIELDS.index(sort_by)
        # Find the position of the sorted column in the formatted string
        # This is approximate but good enough for visual indication
        col_positions = [0, 9, 18, 35, 44, 53, 64, 74, 84, 94, 104, 114]
        if sort_idx_in_header < len(col_positions):
             pos = col_positions[sort_idx_in_header]
             # Insert indicator near the start of the column header text
             header_line = header_line[:pos] + sort_indicator + header_line[pos+1:]

    except (ValueError, IndexError):
        pass # Ignore if sort_by name isn't found or index is bad

    print(header_line)


def print_stats(stats_list, max_rows=None):
    """Prints the formatted statistics for each process."""
    count = 0
    for stat in stats_list:
        # stat tuple: (pid, username, comm, read_hits, read_misses, write_hits_buffer, write_dirty_page,
        #              total_hits, total_misses, dirties, read_hit_perc, write_hit_perc)
        print(
            "{:<8d} {:<8.8} {:<16.16} {:>8d} {:>8d} {:>8d} {:>10d} {:>9d} {:>9d} {:>9d} {:>8.1f}% {:>8.1f}%".format(
                stat[0], stat[1], stat[2],  # PID, USER, CMD
                stat[3], stat[4], stat[5], stat[6], # Raw counts
                stat[7], stat[8], stat[9], # Derived totals
                stat[10], stat[11]         # Percentages
            )
        )
        count += 1
        if max_rows is not None and count >= max_rows:
            if len(stats_list) > max_rows:
                print(f"... ({len(stats_list) - max_rows} more processes)")
            break

def print_explanation():
    """Prints the explanation of the output fields."""
    print("\n--- Field Explanations ---")
    print("PID          : Process ID")
    print("USER         : User name (or UID if not found)")
    print("CMD          : Process command name")
    print("--- Raw Event Counts (per interval) ---")
    print("RD_HIT       : Read Hits      - Page found in cache for reading.")
    print("RD_MISS      : Read Misses    - Page likely added to cache for read (or write-alloc).")
    print("WR_HIT       : Write Hits     - Write occurred to a buffer cache entry.")
    print("WR_MISS_D    : Write Miss/Dirty - Page marked dirty by a write.")
    print("--- Derived Metrics (per interval) ---")
    print("TOTAL_H      : Total Hits     (RD_HIT + WR_HIT) - Sum of read hits and buffer write hits.")
    print("TOTAL_M      : Total Misses   (RD_MISS + WR_MISS_D) - Sum of pages added and pages marked dirty. Ambiguous, use raw counts.")
    print("DIRTIES      : Dirty Events   (WR_HIT + WR_MISS_D) - Total times a page/buffer was marked dirty.")
    print("RD_HIT%      : Read Hit %     (RD_HIT * 100 / (RD_HIT + RD_MISS)) - Percentage of reads that hit the cache.")
    print("WR_HIT%      : Write Hit %    (WR_HIT * 100 / DIRTIES) - Percentage of dirtying events hitting buffers vs pages. Higher -> more buffer cache writes.")
    print("--------------------------\n")

    
# Signal handler for graceful exit
def signal_handler(signum, frame):
    print("\nCaught signal, detaching BPF probes and exiting...")
    # No explicit detach needed for BPF object going out of scope in Python,
    # but good practice if cleanup were more complex.
    sys.exit(0)

# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Monitor Linux page cache activity per process (sequential output).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    cacheraw              # Monitor cache activity, refresh every 5 seconds
    cacheraw 1            # Refresh every 1 second
    cacheraw 1 10         # Refresh every 1 second, print 10 intervals then exit
    cacheraw -p 1234      # Monitor only process PID 1234
    cacheraw -s READ_MISS # Sort by read misses (descending)
    cacheraw -s PID -r    # Sort by PID ascending
"""
    )
    parser.add_argument("-p", "--pid", type=int, metavar="PID",
                        help="trace this PID only")
    parser.add_argument("-s", "--sort", default=DEFAULT_SORT_FIELD, choices=FIELDS,
                        help=f"sort by field (default: {DEFAULT_SORT_FIELD})")
    parser.add_argument("-r", "--reverse", action="store_false",
                        help="sort ascending (default: descending)")
    parser.add_argument('interval', type=int, default=5, nargs='?',
                        help='Interval between updates, in seconds (default: 5)')
    parser.add_argument('count', type=int, default=None, nargs='?',
                        help='Number of updates to print before exiting (default: infinite)')
    parser.add_argument("--max-rows", type=int, default=20,
                        help="Maximum number of process rows to display per interval (default: 20)")

    args = parser.parse_args()

    # Prepare BPF text
    if args.pid:
        bpf_text = bpf_text.replace('FILTER_PID && pid != FILTER_PID_VALUE', '1 && pid != %d' % args.pid)
    else:
        bpf_text = bpf_text.replace('FILTER_PID && pid != FILTER_PID_VALUE', '0') # Effectively disable filtering

    # Initialize BPF
    try:
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count_apcl")
        b.attach_kprobe(event="mark_page_accessed", fn_name="do_count_mpa")
        b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count_mbd")

        # Handle different kernel versions for accounting dirtied pages
        if BPF.get_kprobe_functions(b'folio_account_dirtied'):
             b.attach_kprobe(event="folio_account_dirtied", fn_name="do_count_apd")
        elif BPF.get_kprobe_functions(b'account_page_dirtied'):
             b.attach_kprobe(event="account_page_dirtied", fn_name="do_count_apd")
        elif BPF.tracepoint_exists("writeback", "writeback_dirty_folio"):
             b.attach_tracepoint(tp="writeback:writeback_dirty_folio", fn_name="do_count_apd_tp")
        elif BPF.tracepoint_exists("writeback", "writeback_dirty_page"):
             b.attach_tracepoint(tp="writeback:writeback_dirty_page", fn_name="do_count_apd_tp")
        else:
             print("Error: Cannot attach to page dirtied functions (kprobe/tracepoint). Kernel version/config issue?", file=sys.stderr)
             sys.exit(1)

    except Exception as e:
        print(f"Error initializing BPF or attaching probes: {e}", file=sys.stderr)
        sys.exit(1)

    # Print explanations once at the beginning
    print_explanation()

    # Setup signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    print(f"Starting cacheraw updates every {args.interval} seconds...")
    if args.pid:
        print(f"Filtering for PID {args.pid}")
    print(f"Sorting by {args.sort} ({'Descending' if args.reverse else 'Ascending'})")
    print(f"Displaying top {args.max_rows} processes per interval.")
    print("Press Ctrl+C to exit.")

    # Main loop
    interval_count = 0
    sort_index = FIELD_MAP.get(args.sort, DEFAULT_SORT_INDEX) # Get index from field name

    while True:
        try:
            sleep(args.interval)
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None) # Call handler manually

        # Get memory info
        mem = get_meminfo()
        cached = mem.get("Cached", 0) / 1024
        buff = mem.get("Buffers", 0) / 1024

        # Get process stats from BPF map
        process_stats = get_processes_stats(b, sort_field_index=sort_index, sort_reverse=args.reverse)

        # Print interval header
        print("\n--- %s ---" % strftime("%H:%M:%S"))
        print("System Cache Info: Buffers MB: %.0f / Cached MB: %.0f" % (buff, cached))

        # Print process table header and data
        print_header(args.sort, args.reverse)
        print_stats(process_stats, max_rows=args.max_rows)

        interval_count += 1
        if args.count is not None and interval_count >= args.count:
            print(f"\nReached requested count of {args.count} intervals. Exiting.")
            break