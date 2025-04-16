# ui_main_window.py (Simplified UI Definition)
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QLineEdit, QFormLayout, QTextEdit, QStatusBar, QScrollArea, QGroupBox
)
from PySide6.QtCore import Qt

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setWindowTitle("eBPF Profiler GUI")
        MainWindow.resize(800, 600) 

        self.centralwidget = QWidget(MainWindow)
        self.verticalLayout = QVBoxLayout(self.centralwidget)

        # Script Selection
        self.selectionGroupBox = QGroupBox("Select Profiler Script")
        self.selectionLayout = QHBoxLayout(self.selectionGroupBox)
        self.labelScript = QLabel("Script:")
        self.comboBoxScripts = QComboBox()
        self.selectionLayout.addWidget(self.labelScript)
        self.selectionLayout.addWidget(self.comboBoxScripts, 1) # Stretch combobox
        self.verticalLayout.addWidget(self.selectionGroupBox)

        # Arguments Area
        self.argsGroupBox = QGroupBox("Script Arguments")
        self.scrollAreaArgs = QScrollArea()
        self.scrollAreaArgs.setWidgetResizable(True)
        self.argsWidgetContents = QWidget() # Widget to hold the dynamic form layout
        self.formLayoutArgs = QFormLayout(self.argsWidgetContents)
        self.scrollAreaArgs.setWidget(self.argsWidgetContents)
        self.verticalLayout.addWidget(self.argsGroupBox)
        self.argsGroupBox.setLayout(QVBoxLayout()) # Need layout for groupbox
        self.argsGroupBox.layout().addWidget(self.scrollAreaArgs) # Add scrollarea to groupbox layout

        # Server Config
        self.serverGroupBox = QGroupBox("Remote Server")
        self.serverLayout = QHBoxLayout(self.serverGroupBox)
        self.labelServerUrl = QLabel("Server URL:")
        self.lineEditServerUrl = QLineEdit()
        self.serverLayout.addWidget(self.labelServerUrl)
        self.serverLayout.addWidget(self.lineEditServerUrl)
        self.verticalLayout.addWidget(self.serverGroupBox)

        # Control Buttons
        self.controlLayout = QHBoxLayout()
        self.pushButtonStart = QPushButton("Start Monitoring")
        self.pushButtonStop = QPushButton("Stop Monitoring")
        self.pushButtonStop.setEnabled(False) # Initially disabled
        self.controlLayout.addWidget(self.pushButtonStart)
        self.controlLayout.addWidget(self.pushButtonStop)
        self.verticalLayout.addLayout(self.controlLayout)

        # Output/Log Area
        self.logGroupBox = QGroupBox("Logs / Status")
        self.logLayout = QVBoxLayout(self.logGroupBox)
        self.textEditLog = QTextEdit()
        self.textEditLog.setReadOnly(True)
        self.logLayout.addWidget(self.textEditLog)
        self.verticalLayout.addWidget(self.logGroupBox)


        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(MainWindow)
        MainWindow.setStatusBar(self.statusbar)

        # Add tooltips/placeholder text (optional but good)
        self.comboBoxScripts.setToolTip("Select the eBPF profiling script to run.")
        self.lineEditServerUrl.setToolTip("URL of the remote server to send data to (e.g., http://host:port/data).")
        self.pushButtonStart.setToolTip("Start running the selected script with the specified arguments.")
        self.pushButtonStop.setToolTip("Stop the currently running script.")
        self.textEditLog.setToolTip("Displays status messages, errors, and potentially aggregated data.")