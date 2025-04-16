#!/usr/bin/python3
#
# netpack.py - Network Packet Transmission Latency Analyzer
#
# This script uses eBPF to track network packet transmission latency, providing:
# - Real-time packet transmission latency measurements
# - Packet size monitoring
# - Kernel-side delay measurement between queue and transmission
#
# USAGE: netpack.py [-h] [-d]
#
# Dependencies: BCC (BPF Compiler Collection), Python 3, root privileges, Linux kernel 4.7+

from bcc import BPF
import time
import sys
import argparse

# BPF program
bpf_text = r"""
struct bpf_wq {
    int dummy;
};

#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <bcc/proto.h>

// Data sent to userspace
struct data_t {
    u64 ts;         // timestamp at net_dev_xmit
    u64 delta_ns;   // time from net_dev_queue -> net_dev_xmit (nanoseconds)
    char dev[16];
    u32 len;
};

BPF_HASH(startmap, u64, u64);        // skbaddr -> timestamp
BPF_PERF_OUTPUT(events);

// store timestamp at packet queue
TRACEPOINT_PROBE(net, net_dev_queue) {
    u64 skbaddr = (u64)args->skbaddr;  // Cast void* to u64
    u64 ts = bpf_ktime_get_ns();
    startmap.update(&skbaddr, &ts);
    return 0;
}

// measure time when packet is handed to xmit
TRACEPOINT_PROBE(net, net_dev_xmit) {
    u64 skbaddr = (u64)args->skbaddr;  // Cast void* to u64
    u64 *tsp = startmap.lookup(&skbaddr);

    if (!tsp) {
        return 0;  // we didn't see this skb in net_dev_queue, skip
    }

    u64 delta = bpf_ktime_get_ns() - *tsp;
    startmap.delete(&skbaddr);

    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.delta_ns = delta;
    data.len = args->len;

    // copy device name (up to 15 chars + null terminator) from dev->name
    bpf_probe_read_kernel_str(&data.dev[0], sizeof(data.dev), 0);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# Process events from perf_submit
def print_event(cpu, data, size):
    """Print packet transmission information from BPF event data"""
    event = b["events"].event(data)
    # Convert nanoseconds to microseconds for easier reading
    delta_us = event.delta_ns / 1000.0
    print("%-15s len=%-6d latency=%.2f us" % (event.dev.decode('utf-8', 'replace'),
                                             event.len,
                                             delta_us))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Measure kernel-side packet transmit delay between net_dev_queue and net_dev_xmit."
    )
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Print BPF program before starting (for debugging).")
    args = parser.parse_args()

    if args.debug:
        print(bpf_text)

    # Initialize BPF
    b = BPF(text=bpf_text)

    # Open perf buffer
    b["events"].open_perf_buffer(print_event)

    print("Tracing packet queue -> xmit latency... Ctrl-C to end.")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nTracing stopped.")

# References:
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md

"""
Tracing packet queue -> xmit latency... Ctrl-C to end.
                len=256    latency=9.77 us
                len=71     latency=14.95 us
                len=75     latency=13.60 us
                len=71     latency=13.02 us
                len=89     latency=19.86 us
                len=54     latency=2.31 us
                len=54     latency=6.31 us
                len=82     latency=12.20 us
                len=66     latency=12.10 us
                len=71     latency=13.05 us
                len=71     latency=13.18 us
                len=71     latency=13.47 us
                len=71     latency=13.21 us
                len=71     latency=13.44 us
                len=93     latency=5.91 us
                len=93     latency=0.58 us
                len=104    latency=14.08 us
                len=104    latency=2.65 us
                len=94     latency=8.46 us
                len=543    latency=2.60 us
                len=316    latency=0.45 us
                len=66     latency=10.30 us
                len=54     latency=2.19 us
                len=90     latency=4.55 us
                len=553    latency=3.86 us
"""