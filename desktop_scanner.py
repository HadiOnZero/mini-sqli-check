#!/usr/bin/env python3
"""
SQL Injection Scanner - Desktop Version
PyQt5 GUI application for SQL injection vulnerability scanning
"""

import sys
import os
import time
import threading
from typing import Dict, List, Optional
from datetime import datetime

# PyQt5 imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox,
    QSpinBox, QGroupBox, QProgressBar, QMessageBox, QFileDialog,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QFrame, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QTextCharFormat, QColor, QPalette

# Import the scanner class
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from main import SQLInjectionScanner


class ScannerThread(QThread):
    """Thread for running the scanner to avoid blocking the GUI"""
    progress_updated = pyqtSignal(int)
    log_message = pyqtSignal(str, str)  # message, type (info, warning, error, success)
    scan_completed = pyqtSignal(dict)
    scan_failed = pyqtSignal(str)
    
    def __init__(self, scanner, url, method):
        super().__init__()
        self.scanner = scanner
        self.url = url
        self.method = method
        self.is_running = True
        
    def run(self):
        """Run the scanner in a separate thread"""
        try:
            self.log_message.emit(f"Starting scan for: {self.url}", "info")
            self.log_message.emit(f"Method: {self.method}", "info")
            
            # Start scanning
            results = self.scanner.scan_url(self.url, self.method)
            
            if self.is_running:
                self.scan_completed.emit(results)
                
        except Exception as e:
            if self.is_running:
                self.scan_failed.emit(str(e))
    
    def stop(self):
        """Stop the scanner thread"""
        self.is_running = False


class SQLInjectionScannerGUI(QMainWindow):
    """Main GUI window for the SQL Injection Scanner"""
    
    def __init__(self):
        super().__init__()
        self.scanner = None
        self.scan_thread = None
        self.current_results = None
        self.init_ui()
        self.apply_styles()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("SQL INJECTION SCANNER - FUTURE EDITION v2.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Create main content area with tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create scan tab
        scan_tab = self.create_scan_tab()
        self.tabs.addTab(scan_tab, "Scanner")
        
        # Create results tab
        results_tab = self.create_results_tab()
        self.tabs.addTab(results_tab, "Results")
        
        # Create payload tab
        payload_tab = self.create_payload_tab()
        self.tabs.addTab(payload_tab, "Payloads")
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
    def create_header(self):
        """Create the futuristic header section"""
        header = QFrame()
        header.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        header.setStyleSheet("""
            background-color: #000000;
            color: #00ff41;
            padding: 15px;
            border: 2px solid #00ff41;
            border-radius: 10px;
        """)
        
        layout = QHBoxLayout(header)
        
        title = QLabel("SQL INJECTION SCANNER")
        title.setFont(QFont("Courier New", 18, QFont.Bold))
        title.setStyleSheet("""
            color: #00ff41;
            text-shadow: 0 0 10px #00ff41;
            font-weight: bold;
            letter-spacing: 2px;
        """)
        
        subtitle = QLabel("DESKTOP VERSION v2.0")
        subtitle.setFont(QFont("Courier New", 10))
        subtitle.setStyleSheet("""
            color: #008f11;
            font-weight: bold;
            letter-spacing: 1px;
        """)
        
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addStretch()
        
        return header
        
    def create_scan_tab(self):
        """Create the scanner tab"""
        scan_widget = QWidget()
        layout = QVBoxLayout(scan_widget)
        
        # URL input section
        url_group = QGroupBox("Target Configuration")
        url_layout = QVBoxLayout()
        
        # URL input
        url_input_layout = QHBoxLayout()
        url_input_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com/page?id=1")
        url_input_layout.addWidget(self.url_input)
        url_layout.addLayout(url_input_layout)
        
        # Method and settings
        settings_layout = QHBoxLayout()
        
        # HTTP method
        settings_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST"])
        settings_layout.addWidget(self.method_combo)
        
        # Threads
        settings_layout.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 20)
        self.threads_spin.setValue(5)
        settings_layout.addWidget(self.threads_spin)
        
        # Timeout
        settings_layout.addWidget(QLabel("Timeout:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 60)
        self.timeout_spin.setValue(10)
        settings_layout.addWidget(self.timeout_spin)
        
        settings_layout.addStretch()
        url_layout.addLayout(settings_layout)
        
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("INITIATE SCAN")
        self.start_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("TERMINATE SCAN")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Log output
        log_group = QGroupBox("Scan Log")
        log_layout = QVBoxLayout()
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(200)
        self.log_output.setStyleSheet("""
            background-color: #000000;
            color: #00ff41;
            font-family: 'Courier New', monospace;
            border: 2px solid #00ff41;
            border-radius: 8px;
            padding: 10px;
        """)
        
        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        layout.addStretch()
        
        return scan_widget
        
    def create_results_tab(self):
        """Create the results tab"""
        results_widget = QWidget()
        layout = QVBoxLayout(results_widget)
        
        # Results summary
        summary_layout = QHBoxLayout()
        
        self.vulnerable_label = QLabel("VULNERABILITIES: 0")
        self.vulnerable_label.setStyleSheet("font-weight: bold; color: #ff0041; font-size: 12pt;")
        summary_layout.addWidget(self.vulnerable_label)
        
        self.parameters_label = QLabel("PARAMETERS: 0")
        self.parameters_label.setStyleSheet("font-weight: bold; color: #00ff41; font-size: 12pt;")
        summary_layout.addWidget(self.parameters_label)
        
        self.payloads_label = QLabel("PAYLOADS: 0")
        self.payloads_label.setStyleSheet("font-weight: bold; color: #008f11; font-size: 12pt;")
        summary_layout.addWidget(self.payloads_label)
        
        summary_layout.addStretch()
        
        # Save report button
        self.save_button = QPushButton("EXPORT REPORT")
        self.save_button.clicked.connect(self.save_report)
        self.save_button.setEnabled(False)
        summary_layout.addWidget(self.save_button)
        
        layout.addLayout(summary_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Parameter", "Status", "Payloads Tested", "Vulnerabilities", "Details"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.results_table)
        
        # Detailed results text
        details_group = QGroupBox("Detailed Results")
        details_layout = QVBoxLayout()
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("""
            font-family: 'Courier New', monospace;
            background-color: #0a0a0a;
            color: #00ff41;
            border: 2px solid #00ff41;
            border-radius: 8px;
            padding: 10px;
        """)
        
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        return results_widget
        
    def create_payload_tab(self):
        """Create the payloads tab"""
        payload_widget = QWidget()
        layout = QVBoxLayout(payload_widget)
        
        # Payload management
        payload_group = QGroupBox("Payload Management")
        payload_layout = QVBoxLayout()
        
        # Payload list
        self.payload_text = QTextEdit()
        self.payload_text.setMaximumHeight(300)
        
        # Load default payloads
        if self.scanner is None:
            self.scanner = SQLInjectionScanner()
        
        payload_layout.addWidget(QLabel("SQL Injection Payloads:"))
        payload_layout.addWidget(self.payload_text)
        
        # Payload buttons
        payload_button_layout = QHBoxLayout()
        
        self.load_payloads_button = QPushButton("Load Default Payloads")
        self.load_payloads_button.clicked.connect(self.load_default_payloads)
        
        self.clear_payloads_button = QPushButton("Clear Payloads")
        self.clear_payloads_button.clicked.connect(self.clear_payloads)
        
        payload_button_layout.addWidget(self.load_payloads_button)
        payload_button_layout.addWidget(self.clear_payloads_button)
        payload_button_layout.addStretch()
        
        payload_layout.addLayout(payload_button_layout)
        payload_group.setLayout(payload_layout)
        layout.addWidget(payload_group)
        
        # Error patterns
        error_group = QGroupBox("Error Detection Patterns")
        error_layout = QVBoxLayout()
        
        self.error_text = QTextEdit()
        self.error_text.setMaximumHeight(300)
        
        error_layout.addWidget(QLabel("SQL Error Patterns:"))
        error_layout.addWidget(self.error_text)
        
        error_button_layout = QHBoxLayout()
        
        self.load_errors_button = QPushButton("Load Default Patterns")
        self.load_errors_button.clicked.connect(self.load_default_errors)
        
        self.clear_errors_button = QPushButton("Clear Patterns")
        self.clear_errors_button.clicked.connect(self.clear_errors)
        
        error_button_layout.addWidget(self.load_errors_button)
        error_button_layout.addWidget(self.clear_errors_button)
        error_button_layout.addStretch()
        
        error_layout.addLayout(error_button_layout)
        error_group.setLayout(error_layout)
        layout.addWidget(error_group)
        
        layout.addStretch()
        
        # Load default payloads and patterns
        self.load_default_payloads()
        self.load_default_errors()
        
        return payload_widget
        
    def apply_styles(self):
        """Apply futuristic dark theme styles"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
                color: #00ff41;
            }
            
            QWidget {
                background-color: #000000;
                color: #00ff41;
                font-family: 'Courier New', monospace;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 2px solid #00ff41;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 15px;
                background-color: #0a0a0a;
                color: #00ff41;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                background-color: #0a0a0a;
                color: #00ff41;
            }
            
            QPushButton {
                padding: 12px 24px;
                border-radius: 8px;
                border: 2px solid #00ff41;
                background-color: #0a0a0a;
                color: #00ff41;
                font-weight: bold;
                font-size: 10pt;
            }
            
            QPushButton:hover {
                background-color: #00ff41;
                color: #000000;
                border-color: #00ff41;
            }
            
            QPushButton:pressed {
                background-color: #008f11;
                color: #000000;
                border-color: #008f11;
            }
            
            QPushButton:disabled {
                background-color: #1a1a1a;
                color: #555555;
                border-color: #555555;
            }
            
            QLineEdit, QComboBox, QSpinBox {
                padding: 10px;
                border: 2px solid #00ff41;
                border-radius: 8px;
                background-color: #0a0a0a;
                color: #00ff41;
                font-size: 10pt;
            }
            
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
                border-color: #00ff41;
                background-color: #1a1a1a;
                outline: none;
            }
            
            QLineEdit::placeholder {
                color: #555555;
            }
            
            QTextEdit {
                border: 2px solid #00ff41;
                border-radius: 8px;
                padding: 10px;
                background-color: #0a0a0a;
                color: #00ff41;
                font-family: 'Courier New', monospace;
                font-size: 9pt;
            }
            
            QTableWidget {
                gridline-color: #00ff41;
                background-color: #0a0a0a;
                alternate-background-color: #1a1a1a;
                color: #00ff41;
                border: 2px solid #00ff41;
                border-radius: 8px;
            }
            
            QTableWidget::item {
                background-color: #0a0a0a;
                color: #00ff41;
                padding: 8px;
            }
            
            QTableWidget::item:selected {
                background-color: #00ff41;
                color: #000000;
            }
            
            QHeaderView::section {
                background-color: #00ff41;
                color: #000000;
                padding: 10px;
                border: 1px solid #008f11;
                font-weight: bold;
                font-size: 10pt;
            }
            
            QProgressBar {
                border: 2px solid #00ff41;
                border-radius: 8px;
                text-align: center;
                height: 30px;
                background-color: #0a0a0a;
                color: #00ff41;
                font-weight: bold;
            }
            
            QProgressBar::chunk {
                background-color: #00ff41;
                border-radius: 6px;
            }
            
            QLabel {
                color: #00ff41;
                font-size: 10pt;
                font-weight: bold;
            }
            
            QTabWidget::pane {
                border: 2px solid #00ff41;
                background-color: #0a0a0a;
            }
            
            QTabBar::tab {
                background-color: #0a0a0a;
                color: #00ff41;
                border: 2px solid #00ff41;
                padding: 12px 24px;
                margin-right: 5px;
                font-weight: bold;
            }
            
            QTabBar::tab:selected {
                background-color: #00ff41;
                color: #000000;
            }
            
            QTabBar::tab:hover {
                background-color: #1a1a1a;
            }
            
            QScrollBar:vertical {
                border: 2px solid #00ff41;
                background-color: #0a0a0a;
                width: 18px;
                border-radius: 8px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #00ff41;
                border-radius: 6px;
                min-height: 25px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #008f11;
            }
            
            QScrollBar:horizontal {
                border: 2px solid #00ff41;
                background-color: #0a0a0a;
                height: 18px;
                border-radius: 8px;
            }
            
            QScrollBar::handle:horizontal {
                background-color: #00ff41;
                border-radius: 6px;
                min-width: 25px;
            }
            
            QScrollBar::handle:horizontal:hover {
                background-color: #008f11;
            }
            
            QStatusBar {
                background-color: #0a0a0a;
                color: #00ff41;
                border-top: 2px solid #00ff41;
                font-weight: bold;
            }
            
            QMessageBox {
                background-color: #0a0a0a;
                color: #00ff41;
            }
            
            QMessageBox QPushButton {
                min-width: 100px;
                min-height: 30px;
            }
        """)
        
    def log_message(self, message, message_type="info"):
        """Add a message to the log output"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "info": "#00ff41",
            "warning": "#ffff00",
            "error": "#ff0041",
            "success": "#00ff41"
        }
        
        color = color_map.get(message_type, "#00ff41")
        formatted_message = f'<span style="color: {color}">[{timestamp}] {message}</span>'
        
        self.log_output.append(formatted_message)
        
        # Auto-scroll to bottom
        scrollbar = self.log_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def start_scan(self):
        """Start the vulnerability scan"""
        url = self.url_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "⚠️ SYSTEM ALERT", "TARGET URL REQUIRED")
            return
            
        if not url.startswith(('http://', 'https://')):
            QMessageBox.warning(self, "⚠️ SYSTEM ALERT", "INVALID PROTOCOL - USE HTTP:// OR HTTPS://")
            return
            
        # Initialize scanner
        self.scanner = SQLInjectionScanner(
            timeout=self.timeout_spin.value(),
            threads=self.threads_spin.value()
        )
        
        # Update UI state
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.save_button.setEnabled(False)
        
        # Clear previous results
        self.clear_results()
        
        # Start scan thread
        method = self.method_combo.currentText()
        self.scan_thread = ScannerThread(self.scanner, url, method)
        
        # Connect signals
        self.scan_thread.log_message.connect(self.log_message)
        self.scan_thread.scan_completed.connect(self.scan_completed)
        self.scan_thread.scan_failed.connect(self.scan_failed)
        
        # Start scanning
        self.log_message("Starting vulnerability scan...", "info")
        self.scan_thread.start()
        
        # Start progress timer
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(100)
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.log_message("Stopping scan...", "warning")
            self.scan_thread.stop()
            self.scan_thread.quit()
            self.scan_thread.wait()
            
        self.scan_stopped()
        
    def scan_stopped(self):
        """Handle scan stop completion"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        if hasattr(self, 'progress_timer'):
            self.progress_timer.stop()
            
        self.statusBar().showMessage("Scan stopped")
        
    def scan_completed(self, results):
        """Handle scan completion"""
        self.current_results = results
        self.progress_timer.stop()
        
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.save_button.setEnabled(True)
        
        # Display results
        self.display_results(results)
        
        # Log completion
        if results['vulnerable']:
            self.log_message(f"Scan completed! Found {len(results['vulnerable_parameters'])} vulnerable parameter(s)", "success")
        else:
            self.log_message("Scan completed! No vulnerabilities detected", "success")
            
        self.statusBar().showMessage("Scan completed")
        
    def scan_failed(self, error_message):
        """Handle scan failure"""
        self.progress_timer.stop()
        
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        # Show error
        self.log_message(f"Scan failed: {error_message}", "error")
        QMessageBox.critical(self, "❌ SCAN FAILURE", f"SYSTEM ERROR DETECTED:\n{error_message}")
        
        self.statusBar().showMessage("Scan failed")
        
    def update_progress(self):
        """Update progress bar"""
        current_value = self.progress_bar.value()
        if current_value < 90:  # Leave some room for completion
            self.progress_bar.setValue(current_value + 1)
            
    def display_results(self, results):
        """Display scan results in the UI"""
        # Update summary labels
        vulnerable_count = len(results.get('vulnerable_parameters', []))
        param_count = len(results.get('parameters_tested', []))
        
        self.vulnerable_label.setText(f"Vulnerabilities: {vulnerable_count}")
        self.parameters_label.setText(f"Parameters: {param_count}")
        
        # Calculate total payloads tested
        total_payloads = sum(len(param.get('payloads_tested', [])) 
                           for param in results.get('parameters_tested', []))
        self.payloads_label.setText(f"Payloads: {total_payloads}")
        
        # Update results table
        self.results_table.setRowCount(0)
        
        for param_result in results.get('parameters_tested', []):
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            # Parameter name
            self.results_table.setItem(row, 0, 
                QTableWidgetItem(param_result['parameter']))
            
            # Status
            status = "VULNERABLE" if param_result['vulnerable'] else "SAFE"
            status_item = QTableWidgetItem(status)
            if param_result['vulnerable']:
                status_item.setBackground(QColor('#330000'))
                status_item.setForeground(QColor('#ff0041'))
            else:
                status_item.setBackground(QColor('#003300'))
                status_item.setForeground(QColor('#00ff41'))
            self.results_table.setItem(row, 1, status_item)
            
            # Payloads tested
            self.results_table.setItem(row, 2, 
                QTableWidgetItem(str(len(param_result['payloads_tested']))))
            
            # Vulnerabilities found
            vuln_count = len(param_result['errors_found'])
            self.results_table.setItem(row, 3, 
                QTableWidgetItem(str(vuln_count)))
            
            # Details button
            details_button = QPushButton("View Details")
            details_button.clicked.connect(
                lambda checked, p=param_result: self.show_parameter_details(p))
            self.results_table.setCellWidget(row, 4, details_button)
            
        # Resize columns
        self.results_table.resizeColumnsToContents()
        
        # Update detailed results
        self.update_detailed_results(results)
        
    def update_detailed_results(self, results):
        """Update the detailed results text"""
        if not results:
            return
            
        report = self.scanner.generate_report(results)
        self.details_text.setPlainText(report)
        
    def show_parameter_details(self, param_result):
        """Show detailed information for a parameter"""
        details = f"Parameter: {param_result['parameter']}\n"
        details += f"Status: {'VULNERABLE' if param_result['vulnerable'] else 'SAFE'}\n"
        details += f"Payloads tested: {len(param_result['payloads_tested'])}\n"
        details += f"Vulnerabilities found: {len(param_result['errors_found'])}\n\n"
        
        if param_result['errors_found']:
            details += "Vulnerabilities found:\n"
            for i, error in enumerate(param_result['errors_found'], 1):
                details += f"\n{i}. Payload: {error['payload']}\n"
                details += f"   Error: {error['error_pattern']}\n"
                details += f"   Response time: {error['response_time']:.2f}s\n"
        
        QMessageBox.information(self, f"Parameter Details - {param_result['parameter']}", details)
        
    def clear_results(self):
        """Clear all results"""
        self.results_table.setRowCount(0)
        self.details_text.clear()
        self.vulnerable_label.setText("Vulnerabilities: 0")
        self.parameters_label.setText("Parameters: 0")
        self.payloads_label.setText("Payloads: 0")
        self.log_output.clear()
        self.current_results = None
        self.save_button.setEnabled(False)
        
    def save_report(self):
        """Save the scan report to a file"""
        if not self.current_results:
            QMessageBox.warning(self, "⚠️ SYSTEM ALERT", "NO SCAN DATA AVAILABLE FOR EXPORT")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Report", 
            f"sqliscan_report_{int(time.time())}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                self.scanner.save_report(self.current_results, filename)
                self.log_message(f"Report saved to: {filename}", "success")
                QMessageBox.information(self, "✅ EXPORT COMPLETE", f"REPORT SUCCESSFULLY EXPORTED TO:\n{filename}")
            except Exception as e:
                self.log_message(f"Failed to save report: {str(e)}", "error")
                QMessageBox.critical(self, "❌ EXPORT FAILURE", f"SYSTEM ERROR - EXPORT FAILED:\n{str(e)}")
                
    def load_default_payloads(self):
        """Load default SQL injection payloads"""
        if self.scanner is None:
            self.scanner = SQLInjectionScanner()
            
        payloads_text = "\n".join(self.scanner.payloads)
        self.payload_text.setPlainText(payloads_text)
        
    def clear_payloads(self):
        """Clear all payloads"""
        self.payload_text.clear()
        
    def load_default_errors(self):
        """Load default error patterns"""
        if self.scanner is None:
            self.scanner = SQLInjectionScanner()
            
        error_text = "\n".join(self.scanner.error_patterns)
        self.error_text.setPlainText(error_text)
        
    def clear_errors(self):
        """Clear all error patterns"""
        self.error_text.clear()
        
    def closeEvent(self, event):
        """Handle application close event"""
        if self.scan_thread and self.scan_thread.isRunning():
            reply = QMessageBox.question(
                self, "⚠️ SCAN IN PROGRESS",
                "SYSTEM ALERT: Scan operation in progress. Terminate process?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.stop_scan()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("SQL Injection Scanner")
    app.setApplicationVersion("1.0")
    
    # Set application icon (if available)
    # app.setWindowIcon(QIcon("icon.png"))
    
    # Create and show main window
    window = SQLInjectionScannerGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()