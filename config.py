# config.py
import os

# Absolute path to the directory containing your eBPF scripts
SCRIPT_DIR = os.path.abspath("./metrics")

# List of available eBPF scripts and their expected arguments
# Add descriptions for user-friendliness in the UI
AVAILABLE_SCRIPTS = [
    
    {
        "name": "TCP Connection Latency",
        "file": os.path.join(SCRIPT_DIR, "tcpconnlat-bpfcc.py"),
        "description": "Traces TCP active connection latency (connect time).",
        "args": [
            {"name": "--pid", "type": int, "required": False, "help": "Trace this PID only"},
            {"name": "--timestamp", "type": str, "required": False, "default": "", "help": "Include timestamp on output (leave empty or set to 'True')"},
            {"name": "--lport", "type": str, "required": False, "default": "", "help": "Include local port in output (leave empty or set to 'True')"},
            {"name": "--ipv4", "type": str, "required": False, "default": "", "help": "Trace IPv4 family only (leave empty or set to 'True')"},
            {"name": "--ipv6", "type": str, "required": False, "default": "", "help": "Trace IPv6 family only (leave empty or set to 'True')"},
            {"name": "duration_ms", "type": float, "required": False, "default": "0", "help": "Minimum duration to trace in milliseconds"}
        ],
        "output_parser": lambda line: {"type": "tcp_latency", "data": line.strip()}
    },
    
    {
        "name": "Syscall Nest Analyzer",
        "file": os.path.join(SCRIPT_DIR, "sysnest.py"),
        "description": "Summarize syscall counts and latencies, grouped by process or syscall",
        "args": [
            {"name": "--pid", "type": int, "required": False, "help": "Trace only this PID"},
            {"name": "--tid", "type": int, "required": False, "help": "Trace only this TID"},
            {"name": "--ppid", "type": int, "required": False, "help": "Trace only children of this PID"},
            {"name": "--interval", "type": int, "required": False, "help": "Print summary interval (seconds)"},
            {"name": "--duration", "type": int, "required": False, "help": "Total duration of trace (seconds)"},
            {"name": "--top", "type": int, "required": False, "default": "10", "help": "Print only the top N main items"},
            {"name": "--details-top", "type": int, "required": False, "default": "5", "help": "Print only the top N detailed items per main item"},
            {"name": "--milliseconds", "type": str, "required": False, "default": "", "help": "Display latency in milliseconds (leave empty or set to 'True')"},
            {"name": "--group-by", "type": str, "required": False, "choices": ["process", "syscall"], "default": "syscall", "help": "How to group the output"}
        ],
        "output_parser": lambda line: {"type": "syscall_nest", "data": line.strip()}
    },
    
    {
        "name": "Scheduler Parameters Monitor",
        "file": os.path.join(SCRIPT_DIR, "schparm.py"),
        "description": "Monitor and report on scheduler parameters of processes",
        "args": [],
        "output_parser": lambda line: {"type": "scheduler_params", "data": line.strip()}
    },
    
    {
        "name": "Page Fault Monitor",
        "file": os.path.join(SCRIPT_DIR, "pagefault.py"),
        "description": "Monitor and analyze page fault activity by process",
        "args": [],
        "output_parser": lambda line: {"type": "page_fault", "data": line.strip()}
    },
    
    {
        "name": "Network Packet Analyzer",
        "file": os.path.join(SCRIPT_DIR, "netpack.py"),
        "description": "Measure packet transmission times through kernel queues",
        "args": [],
        "output_parser": lambda line: {"type": "network_packet", "data": line.strip()}
    },
    
    {
        "name": "CPU Scheduler Runtime",
        "file": os.path.join(SCRIPT_DIR, "cpuschrun.py"),
        "description": "Combined CPU metrics analyzer for scheduling and runtime",
        "args": [
            {"name": "--time", "type": str, "required": False, "choices": ["us", "ms", "s"], "default": "us", "help": "Time units (us, ms, s)"},
            {"name": "--timestamp", "type": str, "required": False, "default": "", "help": "Include timestamp on output (leave empty or set to 'True')"},
            {"name": "--pid", "type": int, "required": False, "help": "Trace this PID only"},
            {"name": "--interval", "type": int, "required": False, "default": "99999999", "help": "Output interval in seconds"},
            {"name": "--count", "type": int, "required": False, "default": "99999999", "help": "Number of outputs"},
            {"name": "--per-process", "type": str, "required": False, "default": "", "help": "Show per-process metrics (leave empty or set to 'True')"},
            {"name": "--idle", "type": str, "required": False, "default": "", "help": "Include idle process (leave empty or set to 'True')"},
            {"name": "--milliseconds", "type": str, "required": False, "default": "", "help": "Use millisecond histogram (leave empty or set to 'True')"},
            {"name": "--scoring", "type": str, "required": False, "default": "", "help": "Show priority scoring (leave empty or set to 'True')"},
            {"name": "--runqueue", "type": str, "required": False, "default": "", "help": "Include run queue analysis (leave empty or set to 'True')"}
        ],
        "output_parser": lambda line: {"type": "cpu_scheduler", "data": line.strip()}
    },
    
    {
        "name": "Comprehensive Memory Analyzer",
        "file": os.path.join(SCRIPT_DIR, "compmem.py"),
        "description": "Analyze system memory usage and detect potential memory leaks",
        "args": [
            {"name": "--pid", "type": int, "required": False, "default": "-1", "help": "Trace only this PID for kernel allocations"},
            {"name": "--interval", "type": int, "required": False, "default": "4", "help": "Print summary every INTERVAL seconds"},
            {"name": "--count", "type": int, "required": False, "default": "-1", "help": "Number of reports to print before exiting (-1 for infinite)"},
            {"name": "--debug", "type": str, "required": False, "default": "", "help": "Enable debug output (leave empty or set to 'True')"},
            {"name": "--trace", "type": str, "required": False, "default": "", "help": "Print trace messages for each kernel alloc/free event"},
            {"name": "--min-size", "type": int, "required": False, "default": "0", "help": "Minimum kernel allocation size to track in bytes"},
            {"name": "--top", "type": int, "required": False, "default": "10", "help": "Show this many top processes based on kernel memory usage"}
        ],
        "output_parser": lambda line: {"type": "memory_analysis", "data": line.strip()}
    },
    
    {
        "name": "Page Cache Raw Analyzer",
        "file": os.path.join(SCRIPT_DIR, "cacheraw.py"),
        "description": "Linux Page Cache Usage Analyzer with detailed metrics",
        "args": [
            {"name": "--pid", "type": int, "required": False, "help": "Trace only this PID"},
            {"name": "--sort", "type": str, "required": False, "default": "TOTAL_HITS", 
                "choices": ["PID", "UID", "CMD", "READ_HITS", "READ_MISS", "WRITE_HITS", "WRITE_MISS", 
                            "TOTAL_HITS", "TOTAL_MISS", "DIRTIES", "READ_HIT%", "WRITE_HIT%"],
                "help": "Sort by field"},
            {"name": "--reverse", "type": str, "required": False, "default": "", "help": "Sort ascending (leave empty or set to 'True')"},
            {"name": "interval", "type": int, "required": False, "default": "5", "help": "Interval between updates in seconds"},
            {"name": "count", "type": int, "required": False, "help": "Number of updates to print before exiting"},
            {"name": "--max-rows", "type": int, "required": False, "default": "20", "help": "Maximum number of process rows to display per interval"}
        ],
        "output_parser": lambda line: {"type": "page_cache", "data": line.strip()}
    },
    
    {
        "name": "Block I/O Per-Process Analyzer",
        "file": os.path.join(SCRIPT_DIR, "biopwise.py"),
        "description": "Block Device I/O Per-Process Analyzer for detailed I/O statistics",
        "args": [
            {"name": "interval", "type": int, "required": False, "default": "1", "help": "Output interval in seconds"},
            {"name": "count", "type": int, "required": False, "help": "Number of outputs (default forever)"},
            {"name": "--maxrows", "type": int, "required": False, "default": "20", "help": "Maximum process rows to print per interval"},
            {"name": "--sort", "type": str, "required": False, 
                "choices": ["pid", "comm", "read", "write", "avg_size", "sync", "async_val", "total"], 
                "default": "total", "help": "Sort by column"},
            {"name": "--device", "type": str, "required": False, "help": "Filter I/O by specific device name (e.g., sda, nvme0n1)"},
            {"name": "--top", "type": int, "required": False, "default": "3", "help": "Number of top processes to show in summary"}
        ],
        "output_parser": lambda line: {"type": "block_io", "data": line.strip()}
    }
]

# Default remote server URL
DEFAULT_SERVER_URL = "http://127.0.0.1:5000/data" 
# For another machine, use its IP address or hostname
# DEFAULT_SERVER_URL = "http://<remote_ip>:5000/data"
