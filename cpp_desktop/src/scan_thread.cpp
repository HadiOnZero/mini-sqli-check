#include "scan_thread.h"
#include "sql_injection_scanner.h"

ScanThread::ScanThread(SQLInjectionScanner *scanner, const QString &url, const QString &method, QObject *parent)
    : QThread(parent)
    , m_scanner(scanner)
    , m_url(url)
    , m_method(method)
    , m_isRunning(true)
{
    // Connect scanner signals to our signals
    if (m_scanner) {
        connect(m_scanner, &SQLInjectionScanner::scanProgress, this, &ScanThread::scanProgress);
        connect(m_scanner, &SQLInjectionScanner::logMessage, this, &ScanThread::logMessage);
    }
}

ScanThread::~ScanThread()
{
    stop();
}

void ScanThread::stop()
{
    m_isRunning = false;
}

void ScanThread::run()
{
    if (!m_scanner || !m_isRunning) {
        return;
    }
    
    try {
        emit logMessage(QString("Memulai scan untuk: %1").arg(m_url), "info");
        emit logMessage(QString("Metode: %1").arg(m_method), "info");
        
        // Perform the scan
        QJsonObject results = m_scanner->scanUrl(m_url, m_method);
        
        if (m_isRunning) {
            emit scanCompleted(results);
        }
        
    } catch (const std::exception &e) {
        if (m_isRunning) {
            emit scanFailed(QString("Exception during scan: %1").arg(e.what()));
        }
    } catch (...) {
        if (m_isRunning) {
            emit scanFailed("Unknown exception during scan");
        }
    }
}