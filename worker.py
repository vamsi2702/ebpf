# worker.py
import subprocess
import threading
import select
import os
import time
from PySide6.QtCore import QObject, Signal

class Worker(QObject):
    # Signals to communicate with the main GUI thread
    output_ready = Signal(object) # Sends parsed data
    error_occurred = Signal(str)
    process_finished = Signal() 

    def __init__(self, script_config, script_args, python_executable="python3"):
        super().__init__()
        self.script_config = script_config
        self.script_args = script_args # This will be a list like ['--pid', '1234', '--syscalls', 'read,write']
        self.python_executable = python_executable
        self._process = None
        self._running = False
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self._running = True
        self.thread.start()

    def stop(self):
        self._running = False
        if self._process:
            try:
                print(f"Terminating process {self._process.pid} for {self.script_config['name']}")
                self._process.terminate() # Try graceful termination first
                try:
                    self._process.wait(timeout=2) # Wait a bit
                except subprocess.TimeoutExpired:
                     print(f"Killing process {self._process.pid} for {self.script_config['name']}")
                     self._process.kill() # Force kill if terminate didn't work
            except ProcessLookupError:
                print(f"Process for {self.script_config['name']} already finished.")
            except Exception as e:
                self.error_occurred.emit(f"Error stopping process: {e}")
        
        # Join thread with a short timeout 
        if self.thread.is_alive():
            self.thread.join(timeout=1) # Wait for thread to finish
            
        # Make sure we always emit process_finished signal when stopping
        # to ensure proper cleanup in the main application
        self.process_finished.emit()

    def run(self):
        script_path = self.script_config["file"]
        parser = self.script_config.get("output_parser", lambda line: {"type": "unknown", "data": line.strip()})

        command = [self.python_executable, script_path] + self.script_args

        print(f"Worker: Running command: {' '.join(command)}") # Debug print

        try:
            # NOTE: Requires running the main app with sudo!
            # We capture stdout and stderr. bufsize=1 means line buffered.
            # universal_newlines=True decodes output as text.
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                universal_newlines=True,
                env=os.environ.copy() # Pass environment
            )

            # Non-blocking read using select
            while self._running and self._process.poll() is None:
                # Check if stdout has data ready to be read
                readable, _, _ = select.select([self._process.stdout], [], [], 0.1) # 0.1s timeout
                if readable:
                    line = self._process.stdout.readline()
                    if line:
                        try:
                            parsed_data = parser(line)
                            if parsed_data: # Don't send empty results
                                self.output_ready.emit(parsed_data)
                        except Exception as e:
                            self.error_occurred.emit(f"Error parsing output line '{line.strip()}': {e}")
                    elif not self._running: # Break if stopping and no more output
                         break
                else:
                    # Timeout occurred, check if we should still be running
                    if not self._running:
                        break

            # Capture any remaining output/errors after process ends or stop is called
            stdout_rem, stderr_rem = self._process.communicate()
            if stdout_rem:
                 for line in stdout_rem.splitlines():
                      if line:
                           try:
                               parsed_data = parser(line)
                               if parsed_data: self.output_ready.emit(parsed_data)
                           except Exception as e:
                                self.error_occurred.emit(f"Error parsing final output line '{line.strip()}': {e}")
            if stderr_rem:
                self.error_occurred.emit(f"Script stderr:\n{stderr_rem.strip()}")

            if self._process.returncode != 0 and self._running: # Don't report error if stopped manually
                 self.error_occurred.emit(f"Script exited with code {self._process.returncode}")

        except FileNotFoundError:
            self.error_occurred.emit(f"Error: Script '{script_path}' not found or python executable '{self.python_executable}' not found.")
        except PermissionError:
             self.error_occurred.emit(f"Error: Permission denied. Run the application with sudo.")
        except Exception as e:
            self.error_occurred.emit(f"An unexpected error occurred: {e}")
        finally:
            self._process = None # Clear process handle
            if self._running: # If it finished naturally or errored, signal finished
                self.process_finished.emit()
            print(f"Worker thread for {self.script_config['name']} finished.")