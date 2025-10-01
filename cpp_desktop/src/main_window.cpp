#include "main_window.h"
#include "sql_injection_scanner.h"
#include "scan_thread.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QProgressBar>
#include <QTextEdit>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QTabWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QFont>
#include <QPalette>
#include <QStyle>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_scanner(std::make_unique<SQLInjectionScanner>())
    , m_scanThread(nullptr)
    , m_isScanning(false)
{
    setupUi();
    applyStyles();
    
    // Connect scanner signals
    connect(m_scanner.get(), &SQLInjectionScanner::scanProgress, this, &MainWindow::onScanProgress);
    connect(m_scanner.get(), &SQLInjectionScanner::scanCompleted, this, &MainWindow::onScanCompleted);
    connect(m_scanner.get(), &SQLInjectionScanner::scanFailed, this, &MainWindow::onScanFailed);
    connect(m_scanner.get(), &SQLInjectionScanner::logMessage, this, &MainWindow::onLogMessage);
    
    setWindowTitle("SQL INJECTION SCANNER - FUTURE EDITION v2.0");
    resize(1200, 800);
}

MainWindow::~MainWindow()
{
    if (m_scanThread && m_scanThread->isRunning()) {
        m_scanThread->stop();
        m_scanThread->wait();
    }
}

void MainWindow::setupUi()
{
    // Create central widget and main layout
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    
    // Create header
    QFrame *header = new QFrame();
    header->setFrameStyle(QFrame::StyledPanel | QFrame::Raised);
    header->setStyleSheet("background-color: #000000; color: #00ff41; padding: 15px; border: 2px solid #00ff41; border-radius: 10px;");
    
    QHBoxLayout *headerLayout = new QHBoxLayout(header);
    
    QLabel *title = new QLabel("SQL INJECTION SCANNER");
    title->setFont(QFont("Courier New", 18, QFont::Bold));
    title->setStyleSheet("color: #00ff41; text-shadow: 0 0 10px #00ff41; font-weight: bold; letter-spacing: 2px;");
    
    QLabel *subtitle = new QLabel("DESKTOP VERSION v2.0");
    subtitle->setFont(QFont("Courier New", 10));
    subtitle->setStyleSheet("color: #008f11; font-weight: bold; letter-spacing: 1px;");
    
    headerLayout->addWidget(title);
    headerLayout->addWidget(subtitle);
    headerLayout->addStretch();
    
    mainLayout->addWidget(header);
    
    // Create tab widget
    m_tabs = new QTabWidget();
    mainLayout->addWidget(m_tabs);
    
    // Create scan tab
    QWidget *scanTab = new QWidget();
    QVBoxLayout *scanLayout = new QVBoxLayout(scanTab);
    
    // URL input section
    QGroupBox *urlGroup = new QGroupBox("KONFIGURASI TARGET");
    QVBoxLayout *urlLayout = new QVBoxLayout();
    
    // URL input
    QHBoxLayout *urlInputLayout = new QHBoxLayout();
    urlInputLayout->addWidget(new QLabel("URL Target:"));
    m_urlInput = new QLineEdit();
    m_urlInput->setPlaceholderText("http://example.com/page?id=1");
    urlInputLayout->addWidget(m_urlInput);
    urlLayout->addLayout(urlInputLayout);
    
    // Method and settings
    QHBoxLayout *settingsLayout = new QHBoxLayout();
    
    // HTTP method
    settingsLayout->addWidget(new QLabel("Metode:"));
    m_methodCombo = new QComboBox();
    m_methodCombo->addItems({"GET", "POST"});
    settingsLayout->addWidget(m_methodCombo);
    
    // Threads
    settingsLayout->addWidget(new QLabel("Thread:"));
    m_threadsSpin = new QSpinBox();
    m_threadsSpin->setRange(1, 20);
    m_threadsSpin->setValue(5);
    settingsLayout->addWidget(m_threadsSpin);
    
    // Timeout
    settingsLayout->addWidget(new QLabel("Timeout:"));
    m_timeoutSpin = new QSpinBox();
    m_timeoutSpin->setRange(5, 60);
    m_timeoutSpin->setValue(10);
    settingsLayout->addWidget(m_timeoutSpin);
    
    settingsLayout->addStretch();
    urlLayout->addLayout(settingsLayout);
    
    urlGroup->setLayout(urlLayout);
    scanLayout->addWidget(urlGroup);
    
    // Control buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    m_startButton = new QPushButton("MULAI SCAN");
    connect(m_startButton, &QPushButton::clicked, this, &MainWindow::onStartScan);
    
    m_stopButton = new QPushButton("HENTIKAN SCAN");
    m_stopButton->setEnabled(false);
    connect(m_stopButton, &QPushButton::clicked, this, &MainWindow::onStopScan);
    
    m_clearButton = new QPushButton("BERSIHKAN HASIL");
    connect(m_clearButton, &QPushButton::clicked, this, &MainWindow::onClearResults);
    
    buttonLayout->addWidget(m_startButton);
    buttonLayout->addWidget(m_stopButton);
    buttonLayout->addWidget(m_clearButton);
    buttonLayout->addStretch();
    
    scanLayout->addLayout(buttonLayout);
    
    // Progress bar
    m_progressBar = new QProgressBar();
    m_progressBar->setVisible(false);
    scanLayout->addWidget(m_progressBar);
    
    // Log output
    QGroupBox *logGroup = new QGroupBox("LOG SCAN");
    QVBoxLayout *logLayout = new QVBoxLayout();
    
    m_logOutput = new QTextEdit();
    m_logOutput->setReadOnly(true);
    m_logOutput->setMaximumHeight(200);
    m_logOutput->setStyleSheet("background-color: #000000; color: #00ff41; font-family: 'Courier New', monospace; border: 2px solid #00ff41; border-radius: 8px; padding: 10px;");
    
    logLayout->addWidget(m_logOutput);
    logGroup->setLayout(logLayout);
    scanLayout->addWidget(logGroup);
    
    scanLayout->addStretch();
    
    // Create results tab
    QWidget *resultsTab = new QWidget();
    QVBoxLayout *resultsLayout = new QVBoxLayout(resultsTab);
    
    // Results summary
    QHBoxLayout *summaryLayout = new QHBoxLayout();
    
    m_vulnerableLabel = new QLabel("KERENTANAN: 0");
    m_vulnerableLabel->setStyleSheet("font-weight: bold; color: #ff0041; font-size: 12pt;");
    summaryLayout->addWidget(m_vulnerableLabel);
    
    m_parametersLabel = new QLabel("PARAMETER: 0");
    m_parametersLabel->setStyleSheet("font-weight: bold; color: #00ff41; font-size: 12pt;");
    summaryLayout->addWidget(m_parametersLabel);
    
    m_payloadsLabel = new QLabel("PAYLOAD: 0");
    m_payloadsLabel->setStyleSheet("font-weight: bold; color: #008f11; font-size: 12pt;");
    summaryLayout->addWidget(m_payloadsLabel);
    
    summaryLayout->addStretch();
    
    // Save report button
    m_saveButton = new QPushButton("EXPORT LAPORAN");
    m_saveButton->setEnabled(false);
    connect(m_saveButton, &QPushButton::clicked, this, &MainWindow::onSaveReport);
    summaryLayout->addWidget(m_saveButton);
    
    resultsLayout->addLayout(summaryLayout);
    
    // Results table
    m_resultsTable = new QTableWidget();
    m_resultsTable->setColumnCount(5);
    m_resultsTable->setHorizontalHeaderLabels({"Parameter", "Status", "Payload Diuji", "Kerentanan", "Detail"});
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->setAlternatingRowColors(true);
    
    resultsLayout->addWidget(m_resultsTable);
    
    // Detailed results text
    QGroupBox *detailsGroup = new QGroupBox("HASIL DETAIL");
    QVBoxLayout *detailsLayout = new QVBoxLayout();
    
    m_detailsText = new QTextEdit();
    m_detailsText->setReadOnly(true);
    m_detailsText->setStyleSheet("font-family: 'Courier New', monospace; background-color: #0a0a0a; color: #00ff41; border: 2px solid #00ff41; border-radius: 8px; padding: 10px;");
    
    detailsLayout->addWidget(m_detailsText);
    detailsGroup->setLayout(detailsLayout);
    resultsLayout->addWidget(detailsGroup);
    
    // Add tabs
    m_tabs->addTab(scanTab, "Scanner");
    m_tabs->addTab(resultsTab, "Hasil");
    
    // Status bar
    statusBar()->showMessage("Siap");
}

void MainWindow::applyStyles()
{
    setStyleSheet(R"(
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
    )");
}

void MainWindow::onStartScan()
{
    QString url = m_urlInput->text().trimmed();
    
    if (url.isEmpty()) {
        QMessageBox::warning(this, "⚠️ ALERT SISTEM", "URL TARGET DIBUTUHKAN");
        return;
    }
    
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        QMessageBox::warning(this, "⚠️ ALERT SISTEM", "PROTOKOL TIDAK VALID - GUNAKAN HTTP:// ATAU HTTPS://");
        return;
    }
    
    // Initialize scanner
    m_scanner->setTimeout(m_timeoutSpin->value() * 1000); // Convert to milliseconds
    m_scanner->setThreads(m_threadsSpin->value());
    
    // Update UI state
    m_startButton->setEnabled(false);
    m_stopButton->setEnabled(true);
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0);
    m_saveButton->setEnabled(false);
    m_isScanning = true;
    
    // Clear previous results
    onClearResults();
    
    // Start scan
    QString method = m_methodCombo->currentText();
    QJsonObject results = m_scanner->scanUrl(url, method);
    
    // Process results
    if (results["vulnerable"].toBool()) {
        onScanCompleted(results);
    } else {
        onScanCompleted(results);
    }
    
    // Reset UI state
    m_startButton->setEnabled(true);
    m_stopButton->setEnabled(false);
    m_progressBar->setVisible(false);
    m_isScanning = false;
    
    if (results["vulnerable"].toBool()) {
        m_saveButton->setEnabled(true);
    }
}

void MainWindow::onStopScan()
{
    // For now, just reset the UI since we're using synchronous scanning
    m_startButton->setEnabled(true);
    m_stopButton->setEnabled(false);
    m_progressBar->setVisible(false);
    m_isScanning = false;
    statusBar()->showMessage("Scan dihentikan");
}

void MainWindow::onClearResults()
{
    m_resultsTable->setRowCount(0);
    m_detailsText->clear();
    m_vulnerableLabel->setText("KERENTANAN: 0");
    m_parametersLabel->setText("PARAMETER: 0");
    m_payloadsLabel->setText("PAYLOAD: 0");
    m_logOutput->clear();
    m_currentResults = QJsonObject();
    m_saveButton->setEnabled(false);
}

void MainWindow::onSaveReport()
{
    if (m_currentResults.isEmpty()) {
        QMessageBox::warning(this, "⚠️ ALERT SISTEM", "TIDAK ADA DATA SCAN UNTUK DIEKSPOR");
        return;
    }
    
    QString filename = QFileDialog::getSaveFileName(
        this, "Export Laporan", 
        QString("sqliscan_report_%1.txt").arg(QDateTime::currentDateTime().toSecsSinceEpoch()),
        "File Teks (*.txt);;Semua File (*)"
    );
    
    if (!filename.isEmpty()) {
        if (m_scanner->saveReport(m_currentResults, filename)) {
            QMessageBox::information(this, "✅ EKSPOR SELESAI", QString("LAPORAN BERHASIL DIEKSPOR KE:\n%1").arg(filename));
        }
    }
}

void MainWindow::onScanProgress(int progress)
{
    m_progressBar->setValue(progress);
}

void MainWindow::onScanCompleted(const QJsonObject &results)
{
    m_currentResults = results;
    
    // Update summary labels
    updateSummaryLabels(results);
    
    // Display results in table
    displayResults(results);
    
    // Update detailed results
    QString report = m_scanner->generateReport(results);
    m_detailsText->setPlainText(report);
    
    // Log completion
    if (results["vulnerable"].toBool()) {
        int vulnCount = results["vulnerable_parameters"].toArray().size();
        onLogMessage(QString("Scan selesai! Ditemukan %1 parameter rentan").arg(vulnCount), "success");
    } else {
        onLogMessage("Scan selesai! Tidak ada kerentanan yang terdeteksi", "success");
    }
    
    statusBar()->showMessage("Scan selesai");
}

void MainWindow::onScanFailed(const QString &errorMessage)
{
    onLogMessage(QString("Scan gagal: %1").arg(errorMessage), "error");
    QMessageBox::critical(this, "❌ KEGAGALAN SCAN", QString("ERROR SISTEM TERDETEKSI:\n%1").arg(errorMessage));
    statusBar()->showMessage("Scan gagal");
}

void MainWindow::onLogMessage(const QString &message, const QString &messageType)
{
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString color;
    
    if (messageType == "error") {
        color = "#ff0041";
    } else if (messageType == "warning") {
        color = "#ffff00";
    } else if (messageType == "success") {
        color = "#00ff41";
    } else {
        color = "#00ff41";
    }
    
    QString formattedMessage = QString("<span style=\"color: %1\">[%2] %3</span>").arg(color).arg(timestamp).arg(message);
    m_logOutput->append(formattedMessage);
    
    // Auto-scroll to bottom
    QScrollBar *scrollbar = m_logOutput->verticalScrollBar();
    scrollbar->setValue(scrollbar->maximum());
}

void MainWindow::displayResults(const QJsonObject &results)
{
    m_resultsTable->setRowCount(0);
    
    QJsonArray parametersTested = results["parameters_tested"].toArray();
    
    for (const QJsonValue &val : parametersTested) {
        QJsonObject paramResult = val.toObject();
        
        int row = m_resultsTable->rowCount();
        m_resultsTable->insertRow(row);
        
        // Parameter name
        m_resultsTable->setItem(row, 0, new QTableWidgetItem(paramResult["parameter"].toString()));
        
        // Status
        QString status = paramResult["vulnerable"].toBool() ? "RENTAN" : "AMAN";
        QTableWidgetItem *statusItem = new QTableWidgetItem(status);
        if (paramResult["vulnerable"].toBool()) {
            statusItem->setBackground(QColor("#330000"));
            statusItem->setForeground(QColor("#ff0041"));
        } else {
            statusItem->setBackground(QColor("#003300"));
            statusItem->setForeground(QColor("#00ff41"));
        }
        m_resultsTable->setItem(row, 1, statusItem);
        
        // Payloads tested
        m_resultsTable->setItem(row, 2, new QTableWidgetItem(QString::number(paramResult["payloads_tested"].toArray().size())));
        
        // Vulnerabilities found
        int vulnCount = paramResult["errors_found"].toArray().size();
        m_resultsTable->setItem(row, 3, new QTableWidgetItem(QString::number(vulnCount)));
        
        // Details button
        QPushButton *detailsButton = new QPushButton("LIHAT DETAIL");
        connect(detailsButton, &QPushButton::clicked, [this, paramResult]() {
            QString details = QString("Parameter: %1\nStatus: %2\nPayload diuji: %3\nKerentanan ditemukan: %4\n\n")
                .arg(paramResult["parameter"].toString())
                .arg(paramResult["vulnerable"].toBool() ? "RENTAN" : "AMAN")
                .arg(paramResult["payloads_tested"].toArray().size())
                .arg(paramResult["errors_found"].toArray().size());
            
            if (paramResult["vulnerable"].toBool()) {
                details += "Kerentanan yang ditemukan:\n";
                QJsonArray errors = paramResult["errors_found"].toArray();
                for (int i = 0; i < errors.size(); ++i) {
                    QJsonObject error = errors[i].toObject();
                    details += QString("\n%1. Payload: %2\n   Error: %3\n   Waktu Response: %4 detik\n")
                        .arg(i + 1)
                        .arg(error["payload"].toString())
                        .arg(error["error_pattern"].toString())
                        .arg(error["response_time"].toDouble());
                }
            }
            
            QMessageBox::information(this, QString("Detail Parameter - %1").arg(paramResult["parameter"].toString()), details);
        });
        m_resultsTable->setCellWidget(row, 4, detailsButton);
    }
    
    // Resize columns
    m_resultsTable->resizeColumnsToContents();
}

void MainWindow::updateSummaryLabels(const QJsonObject &results)
{
    QJsonArray vulnerableParams = results["vulnerable_parameters"].toArray();
    QJsonArray parametersTested = results["parameters_tested"].toArray();
    
    m_vulnerableLabel->setText(QString("KERENTANAN: %1").arg(vulnerableParams.size()));
    m_parametersLabel->setText(QString("PARAMETER: %1").arg(parametersTested.size()));
    
    // Calculate total payloads tested
    int totalPayloads = 0;
    for (const QJsonValue &val : parametersTested) {
        totalPayloads += val.toObject()["payloads_tested"].toArray().size();
    }
    m_payloadsLabel->setText(QString("PAYLOAD: %1").arg(totalPayloads));
}