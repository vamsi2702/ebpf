
# eBPF-Profiler

**A GUI-Based Tool for Low-Overhead Networked Application Performance Analysis using eBPF/BCC**

This project provides a profiling tool designed to collect detailed performance data from networked applications running on Linux systems. It leverages the power of eBPF (extended Berkeley Packet Filter) via the BCC (BPF Compiler Collection) framework to capture kernel-level metrics with minimal performance impact. The tool features a Python-based GUI (using PySide6) for user-friendly control and transmits collected data to a remote server endpoint for logging.

## Features

*   **Low-Overhead Monitoring:** Utilizes eBPF for efficient in-kernel data collection.
*   **Graphical User Interface:** Easy-to-use interface built with PySide6 for selecting metrics, configuring parameters, and controlling monitoring.
*   **Broad Metric Coverage:** Includes BCC scripts to monitor:
    *   System Call Counts and Latencies (`sysnest.py`)
    *   TCP Connection Establishment Latency (`tcpconnlat-bpfcc.py`)
    *   Network Packet Kernel Queue Time (`netpack.py`)
    *   CPU Scheduling Behavior & Run Queue Latency (`cpuschrun.py`, `schparm.py`)
    *   Memory Usage: Page Faults (`pagefault.py`), Kernel Allocations (`compmem.py`)
    *   Page Cache Hit/Miss Ratios (`cacheraw.py`)
    *   Block I/O Statistics per Process (`biopwise.py`)
*   **Dynamic Configuration:** GUI dynamically adapts argument fields based on the selected metric script.
*   **Remote Data Transmission:** Sends collected metrics periodically (JSON over HTTP POST) to a configurable remote server.
*   **Robustness:** Includes data buffering and a basic retry mechanism for network transmission.
*   **Extensible:** Easily add new metric scripts by defining them in `config.py`.

## Architecture Overview

The system consists of:

1.  **GUI Application (`main_app.py`):** The main user interface built with Python and PySide6. It manages configuration, controls workers, buffers data, and handles network transmission.
2.  **Worker Threads (`worker.py`):** Launched by the GUI to run individual BCC metric scripts in separate subprocesses, capture their output, and communicate back to the GUI via signals.
3.  **Configuration (`config.py`):** Defines available metric scripts, their arguments, descriptions, and output parsing logic.
4.  **BCC Metric Scripts (`metrics/*.py`):** Python scripts using the BCC framework. Each contains embedded eBPF C code that attaches to kernel hooks (kprobes/tracepoints) to collect specific metrics. They print formatted data to standard output.
5.  **Remote Server (`server.py`):** A simple Flask server that listens for HTTP POST requests, receives JSON data payloads from the profiler client, and logs the data.

## Requirements

*   **Operating System:** Linux with a kernel version supporting eBPF and the necessary features for BCC (generally 4.1+ is needed, but specific scripts might require newer features, e.g., 4.7+ for `netpack.py`, ~5.x+ recommended for broader feature support).
*   **Kernel Headers:** Matching kernel headers must be installed for BCC to compile eBPF programs (e.g., `linux-headers-$(uname -r)` on Debian/Ubuntu).
*   **BCC (BPF Compiler Collection):** Must be installed system-wide. Follow the official [BCC installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md) for your distribution. This typically involves installing dependencies like `clang`, `llvm`, `luajit`, etc.
*   **Python:** Python 3.6+
*   **Python Libraries:** `PySide6`, `requests`, `Flask`.
*   **Permissions:** **Root privileges (`sudo`) are required** to run the main GUI application (`main_app.py`) because eBPF programs need elevated permissions to load into the kernel.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Ensure BCC is installed:** Follow the official BCC installation instructions for your Linux distribution *before* proceeding. This is the most critical system dependency.

3.  **Install Kernel Headers:**
    ```bash
    # Debian/Ubuntu
    sudo apt-get update
    sudo apt-get install -y linux-headers-$(uname -r)

    # Fedora (example, adjust dnf command as needed)
    # sudo dnf install kernel-devel
    ```

4.  **Install Python dependencies:**
    ```bash
    pip3 install PySide6 requests Flask
    ```

## Usage

1.  **Start the Remote Server:**
    Open a terminal and run the Flask server. It will log received data to the console and `server_data.log`.
    ```bash
    python3 server.py
    ```
    By default, it listens on `http://0.0.0.0:5000`. You can access it locally via `http://127.0.0.1:5000`.

2.  **Run the GUI Application:**
    Open another terminal and run the main application **with root privileges**:
    ```bash
    sudo python3 main_app.py
    ```

3.  **Using the GUI:**
    *   **Select Script:** Choose the desired performance metric script from the dropdown menu. The description will appear below.
    *   **Enter Arguments:** Fill in the required arguments (marked with `*`) and any optional arguments for the selected script. Tooltips provide help.
    *   **Configure Server URL:** Verify or change the "Server URL" field to match where your `server.py` (or other compatible endpoint) is running. Default is `http://127.0.0.1:5000/data`.
    *   **Start Monitoring:** Click the "Start Monitoring" button. The status bar and log area will show updates. The button will disable, and "Stop Monitoring" will enable.
    *   **Observe Logs:** View status messages, potential errors, and data transmission logs in the "Logs / Status" text area. Check the `server.py` terminal/log file for received data.
    *   **Stop Monitoring:** Click the "Stop Monitoring" button when finished. The underlying BCC script will be terminated, final data will be sent, and the UI controls will reset.

## Project Structure

```
ebpf-profiler-gui/
├── main_app.py           # Main application logic, GUI event handling, data sending
├── ui_main_window.py     # PySide6 UI layout definition
├── worker.py             # Class to run BCC scripts in subprocesses via threads
├── config.py             # Configuration: defines scripts, arguments, server URL
├── server.py             # Simple Flask server to receive and log data
├── requirements.txt      # Python dependencies (for pip)
└── metrics/              # Directory containing the BCC/eBPF metric scripts
    ├── biopwise.py       # Block I/O per process
    ├── cacheraw.py       # Page cache hits/misses
    ├── compmem.py        # Kernel memory allocations/leaks + user memory
    ├── cpuschrun.py      # CPU run queue latency & runtime distribution
    ├── netpack.py        # Network packet kernel transmit queue latency
    ├── pagefault.py      # Minor/major page faults per process
    ├── schparm.py        # Process scheduling parameters on exit
    ├── syscount.py       # (Referenced in config.py) System call counts
    ├── sysnest.py        # System call counts and latency (detailed)
    ├── tcpconnlat-bpfcc.py # TCP connection establishment latency
    └── ...               # Other metric scripts
```

## Metric Scripts Overview

The `metrics/` directory contains individual Python scripts that use the BCC framework to perform eBPF-based tracing. Refer to the source code of each script and `config.py` for specific arguments and details.

*   `biopwise.py`: Tracks block device I/O (reads/writes, counts, sizes, sync/async) per process.
*   `cacheraw.py`: Monitors page cache activity (read/write hits & misses) per process.
*   `compmem.py`: Analyzes kernel memory allocations (`kmalloc`/`kfree`), reports potential leaks by stack trace, and shows user RSS/VmSize.
*   `cpuschrun.py`: Measures CPU run times and run queue latencies, showing distributions and per-process stats.
*   `netpack.py`: Measures latency between `net_dev_queue` and `net_dev_xmit` tracepoints for kernel packet queueing time.
*   `pagefault.py`: Counts minor (memory) and major (disk) page faults per process.
*   `schparm.py`: Reports process scheduling parameters (priority, policy, nice) upon process exit.
*   `sysnest.py`: Traces system call entry/exit, providing detailed counts and latency statistics, groupable by process or syscall.
*   `tcpconnlat-bpfcc.py`: Measures the time taken to establish outbound TCP connections (SYN -> ESTABLISHED).

## Limitations

*   **Root Privileges Required:** The main application must be run with `sudo` due to eBPF requirements.
*   **Kernel Version Dependency:** eBPF features and the availability/stability of specific tracepoints or kprobes depend heavily on the Linux kernel version. Scripts may need adjustments for different kernels.
*   **BCC Dependency:** Requires a full BCC installation, which can sometimes be complex depending on the distribution.
*   **Basic Server:** The included `server.py` is primarily for logging and basic sequence checking. It does not perform advanced analysis or storage.
*   **Parsing Brittleness:** The reliability of data collection depends on the `output_parser` in `config.py` correctly interpreting the `stdout` of the BCC scripts. Changes in script output format could break parsing.



Presentation Link: https://drive.google.com/file/d/1DsCNb3yKUbhtK-MQi6R3kLTO5PbbkNor/view?usp=sharing
