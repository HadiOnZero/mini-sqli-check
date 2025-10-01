#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include <QMainWindow>
#include <QJsonObject>
#include <memory>

QT_BEGIN_NAMESPACE
class QLineEdit;
class QComboBox;
class QSpinBox;
class QPushButton;
class QProgressBar;
class QTextEdit;
class QTableWidget;
class QTabWidget;
class QLabel;
class QGroupBox;
class QThread;
QT_END_NAMESPACE

class SQLInjectionScanner;
class ScanThread;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartScan();
    void onStopScan();
    void onClearResults();
    void onSaveReport();
    void onScanProgress(int progress);
    void onScanCompleted(const QJsonObject &results);
    void onScanFailed(const QString &error);
    void onLogMessage(const QString &message, const QString &type);
    void onParameterDetails();

private:
    void setupUi();
    void applyStyles();
    void displayResults(const QJsonObject &results);
    void updateSummaryLabels(const QJsonObject &results);
    
    // UI Elements
    QLineEdit *m_urlInput;
    QComboBox *m_methodCombo;
    QSpinBox *m_threadsSpin;
    QSpinBox *m_timeoutSpin;
    QPushButton *m_startButton;
    QPushButton *m_stopButton;
    QPushButton *m_clearButton;
    QPushButton *m_saveButton;
    QProgressBar *m_progressBar;
    QTextEdit *m_logOutput;
    QTableWidget *m_resultsTable;
    QTextEdit *m_detailsText;
    QLabel *m_vulnerableLabel;
    QLabel *m_parametersLabel;
    QLabel *m_payloadsLabel;
    QTabWidget *m_tabs;
    
    // Scanner
    std::unique_ptr<SQLInjectionScanner> m_scanner;
    ScanThread *m_scanThread;
    QJsonObject m_currentResults;
    
    // State
    bool m_isScanning;
};

#endif // MAIN_WINDOW_H