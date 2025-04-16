# main_app.py
import sys
import os
import json
import requests # For sending data
import time # For timestamp generation
from collections import deque

from PySide6.QtWidgets import QApplication, QMainWindow, QLineEdit, QLabel, QWidget, QMessageBox
from PySide6.QtCore import Slot, QTimer

from ui_main_window import Ui_MainWindow # Import the UI definition
from config import AVAILABLE_SCRIPTS, DEFAULT_SERVER_URL
from worker import Worker

# --- Check if running as root ---
# It's better to inform the user than just fail later
if os.geteuid() != 0:
    print("WARNING: This application likely needs root privileges (sudo) to run eBPF scripts.")
    # Optionally, show a graphical warning or exit
    # QtWidgets.QMessageBox.warning(None, "Permissions Required", "Run this application using 'sudo'.")
    # sys.exit(1)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.current_worker = None
        self.argument_widgets = {} # Keep track of dynamically created arg inputs
        
        # Increase buffer size to prevent data loss (from 100 to 1000)
        self.output_buffer = deque(maxlen=1000) 
        
        # Track sequence numbers for detecting missing data
        self.send_sequence = 0
        self.last_send_time = 0
        
        # Reduce interval from 5s to 2s for more frequent sending
        self.send_timer = QTimer(self)
        self.send_timer.setInterval(2000) # Send data every 2 seconds
        self.send_timer.timeout.connect(self.send_data_to_server)
        
        # Add a backup timer to ensure data gets sent even if few events occur
        self.backup_timer = QTimer(self)
        self.backup_timer.setInterval(10000)  # Force send every 10 seconds
        self.backup_timer.timeout.connect(self.force_send_data)

        # Failed data storage for retries
        self.failed_transmissions = []
        self.retry_timer = QTimer(self)
        self.retry_timer.setInterval(15000)  # Retry every 15 seconds
        self.retry_timer.timeout.connect(self.retry_failed_transmissions)

        # Populate script dropdown
        for i, script_info in enumerate(AVAILABLE_SCRIPTS):
            self.ui.comboBoxScripts.addItem(f"{script_info['name']} ({os.path.basename(script_info['file'])})", userData=i)

        # Set default server URL
        self.ui.lineEditServerUrl.setText(DEFAULT_SERVER_URL)

        # Connect signals
        self.ui.comboBoxScripts.currentIndexChanged.connect(self.update_argument_fields)
        self.ui.pushButtonStart.clicked.connect(self.start_monitoring)
        self.ui.pushButtonStop.clicked.connect(self.stop_monitoring)

        # Initial setup
        self.update_argument_fields() # Populate args for the default selected script

    def log_message(self, message):
        print(f"LOG: {message}") # Also print to console for debugging
        self.ui.textEditLog.append(message)

    def clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    @Slot()
    def update_argument_fields(self):
        # Clear previous argument fields
        self.clear_layout(self.ui.formLayoutArgs)
        self.argument_widgets.clear()

        # Get selected script config
        selected_index = self.ui.comboBoxScripts.currentData()
        if selected_index is None: return # Should not happen if list is populated
        script_config = AVAILABLE_SCRIPTS[selected_index]

        # Add description
        desc_label = QLabel(f"<i>{script_config.get('description', 'No description.')}</i>")
        desc_label.setWordWrap(True)
        self.ui.formLayoutArgs.addRow(desc_label)


        # Dynamically create input fields for arguments
        for arg_def in script_config.get("args", []):
            arg_name = arg_def["name"]
            label = QLabel(f"{arg_name}:")
            input_widget = QLineEdit()
            tooltip = arg_def.get('help', '')
            if arg_def.get('required', False):
                tooltip += " (Required)"
                label.setText(f"{arg_name}*:") # Mark required
            input_widget.setToolTip(tooltip)
            if 'default' in arg_def:
                input_widget.setText(str(arg_def['default']))
            input_widget.setObjectName(arg_name) # Use name to retrieve value later
            self.ui.formLayoutArgs.addRow(label, input_widget)
            self.argument_widgets[arg_name] = input_widget


    @Slot()
    def start_monitoring(self):
        # Add a safeguard to handle potential inconsistent state
        if self.current_worker:
            # Check if worker thread is actually still running
            if hasattr(self.current_worker, 'thread') and self.current_worker.thread.is_alive():
                self.log_message("Error: Monitoring is already in progress.")
                return
            else:
                # Worker reference exists but thread is not running - clean up
                self.log_message("Warning: Cleaning up previous monitoring session.")
                self.current_worker = None

        selected_index = self.ui.comboBoxScripts.currentData()
        if selected_index is None:
             self.log_message("Error: No script selected.")
             return
        script_config = AVAILABLE_SCRIPTS[selected_index]
        script_args_list = []

        # Collect arguments from the UI
        positional_args = []
        named_args = []

        try:
            for arg_def in script_config.get("args", []):
                arg_name = arg_def["name"]
                widget = self.argument_widgets.get(arg_name)
                if not widget: continue # Should not happen

                value_str = widget.text().strip()

                if arg_def.get("required", False) and not value_str:
                    raise ValueError(f"Argument '{arg_name}' is required.")

                if value_str: # Only add arg if value is provided
                     # Basic type checking/conversion (can be expanded)
                    arg_type = arg_def.get("type", str)
                    try:
                        if arg_type == int:
                             value = int(value_str)
                        elif arg_type == float:
                             value = float(value_str)
                        else: # Default to string
                            value = value_str
                    except ValueError:
                         raise ValueError(f"Invalid value for argument '{arg_name}'. Expected {arg_type.__name__}.")

                    # Check if this is a positional or named argument
                    if arg_name.startswith("--"):
                        # Named argument (e.g., --pid, --interval)
                        named_args.append(arg_name)
                        
                        # Special handling for boolean flag arguments
                        # If value is "True" or "true", treat it as a flag with no value
                        if value_str.lower() == "true":
                            # Just add the flag name, no value
                            pass
                        else:
                            # Add the value for non-flag arguments
                            named_args.append(str(value))
                    else:
                        # Positional argument (e.g., interval, count)
                        positional_args.append(str(value))

                # Combine arguments with positional first, then named
                script_args_list = positional_args + named_args

        except ValueError as e:
            self.log_message(f"Configuration Error: {e}")
            QMessageBox.warning(self, "Input Error", str(e))
            return

        self.log_message(f"Starting '{script_config['name']}'...")
        self.log_message(f"Arguments: {' '.join(script_args_list)}") # Debug print args

        # Reset sequence counter and clear any previous data
        self.send_sequence = 0
        self.output_buffer.clear()
        self.failed_transmissions.clear()
        
        # Create and start the worker
        self.current_worker = Worker(script_config, script_args_list)
        self.current_worker.output_ready.connect(self.handle_output)
        self.current_worker.error_occurred.connect(self.handle_error)
        self.current_worker.process_finished.connect(self.handle_finish) # Handle natural finish/error

        self.current_worker.start()
        
        # Start timers
        self.send_timer.start() # Start timer to send data periodically
        self.backup_timer.start() # Start backup timer
        self.retry_timer.start() # Start retry timer

        # Update UI state
        self.ui.pushButtonStart.setEnabled(False)
        self.ui.pushButtonStop.setEnabled(True)
        self.ui.comboBoxScripts.setEnabled(False)
        self.ui.argsGroupBox.setEnabled(False)
        self.ui.serverGroupBox.setEnabled(False)
        self.ui.statusbar.showMessage(f"Running: {script_config['name']}...")

    @Slot()
    def force_send_data(self):
        """Force send data even if buffer is small to prevent long delays"""
        if self.output_buffer:
            self.send_data_to_server()

    @Slot()
    def stop_monitoring(self):
        if not self.current_worker:
            self.log_message("Not currently monitoring.")
            return

        self.log_message("Stopping monitoring...")
        self.send_timer.stop()
        self.backup_timer.stop()
        self.retry_timer.stop()
        
        # Stop the worker
        if self.current_worker:
            self.current_worker.stop() # Request worker thread and process to stop
        
        # Send any remaining data immediately
        self.send_data_to_server()
        
        # Try to send any previously failed transmissions
        self.retry_failed_transmissions()
        
        self.output_buffer.clear()
        self.failed_transmissions.clear()

        # Reset UI state immediately for responsiveness
        self.ui.pushButtonStart.setEnabled(True)
        self.ui.pushButtonStop.setEnabled(False)
        self.ui.comboBoxScripts.setEnabled(True)
        self.ui.argsGroupBox.setEnabled(True)
        self.ui.serverGroupBox.setEnabled(True)
        self.ui.statusbar.showMessage("Monitoring stopped.")
        
        # Clear worker reference - handle_finish will also be called via signal
        self.current_worker = None

    @Slot(object)
    def handle_output(self, data):
        # Handle data received from the worker thread
        # Add sequence info to detect missing data
        self.output_buffer.append(data)
        
        # If buffer is getting large, trigger an immediate send to prevent overflow
        if len(self.output_buffer) > 800:  # 80% of buffer capacity
            self.log_message(f"Buffer filling up ({len(self.output_buffer)} items) - sending data immediately")
            self.send_data_to_server()

    @Slot(str)
    def handle_error(self, error_message):
        # Handle errors reported by the worker thread
        self.log_message(f"Error: {error_message}")
        # Optionally show a popup
        # QMessageBox.warning(self, "Monitoring Error", error_message)

    @Slot()
    def handle_finish(self):
        # Called when the worker thread confirms the process has ended
        self.log_message("Monitoring process finished.")
        self.send_timer.stop() # Stop sending timer if process finishes on its own
        self.backup_timer.stop() # Stop backup timer
        self.retry_timer.stop() # Stop retry timer

        # Send any remaining data
        self.send_data_to_server()
        
        # Retry any failed transmissions
        self.retry_failed_transmissions()
        
        self.output_buffer.clear()
        self.failed_transmissions.clear()

        # Clear the worker reference
        self.current_worker = None

        # Ensure UI is in stopped state
        self.ui.pushButtonStart.setEnabled(True)
        self.ui.pushButtonStop.setEnabled(False)
        self.ui.comboBoxScripts.setEnabled(True)
        self.ui.argsGroupBox.setEnabled(True)
        self.ui.serverGroupBox.setEnabled(True)
        self.ui.statusbar.showMessage("Monitoring finished.")

    @Slot()
    def retry_failed_transmissions(self):
        """Retry sending previously failed data transmissions"""
        if not self.failed_transmissions:
            return
            
        self.log_message(f"Retrying {len(self.failed_transmissions)} failed transmissions...")
        server_url = self.ui.lineEditServerUrl.text().strip()
        
        if not server_url:
            return
            
        # Try to send each failed payload
        still_failed = []
        for payload in self.failed_transmissions:
            try:
                response = requests.post(server_url, json=payload, timeout=5)
                response.raise_for_status()
                self.log_message(f"Successfully resent data batch with {len(payload.get('metrics', []))} metrics")
            except Exception as e:
                still_failed.append(payload)
                
        # Update failed transmissions list
        self.failed_transmissions = still_failed
        if still_failed:
            self.log_message(f"{len(still_failed)} transmissions still failing, will retry later")

    def send_data_to_server(self):
        if not self.output_buffer:
            return

        server_url = self.ui.lineEditServerUrl.text().strip()
        if not server_url:
            self.log_message("Warning: Server URL is empty. Cannot send data.")
            return

        # Grab all data from the buffer
        data_to_send = list(self.output_buffer)
        self.output_buffer.clear()
        
        # Create a batch ID to track this transmission
        batch_id = f"batch_{self.send_sequence}"
        self.send_sequence += 1

        self.log_message(f"Sending {len(data_to_send)} data points to {server_url} (ID: {batch_id})...")

        try:
            # Add context and sequence information
            payload = {
                "timestamp": time.time(),
                "source_script": self.current_worker.script_config['name'] if self.current_worker else "N/A",
                "batch_id": batch_id,
                "sequence": self.send_sequence,
                "metrics": data_to_send
            }
            
            self.last_send_time = time.time()
            response = requests.post(server_url, json=payload, timeout=5) # 5 second timeout
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            self.log_message(f"Data sent successfully (Status: {response.status_code}, Batch: {batch_id}).")

        except requests.exceptions.RequestException as e:
            self.log_message(f"Error sending data to server: {e}")
            # Store failed transmission for retry
            self.failed_transmissions.append(payload)
            self.log_message(f"Queued batch {batch_id} for retry. {len(self.failed_transmissions)} pending retries.")
        except Exception as e:
            self.log_message(f"Unexpected error during data sending: {e}")
            # Store failed transmission for retry here too
            self.failed_transmissions.append(payload)

    def closeEvent(self, event):
        # Ensure worker is stopped when closing the window
        if self.current_worker:
            self.log_message("Window closed. Stopping active monitoring...")
            self.stop_monitoring()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())