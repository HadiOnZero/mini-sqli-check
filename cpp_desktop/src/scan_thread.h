#ifndef SCAN_THREAD_H
#define SCAN_THREAD_H

#include <QThread>
#include <QJsonObject>
#include <memory>

class SQLInjectionScanner;

class ScanThread : public QThread
{
    Q_OBJECT

public:
    explicit ScanThread(SQLInjectionScanner *scanner, const QString &url, const QString &method, QObject *parent = nullptr);
    ~ScanThread();
    
    void stop();

signals:
    void scanProgress(int progress);
    void scanCompleted(const QJsonObject &results);
    void scanFailed(const QString &error);
    void logMessage(const QString &message, const QString &type);

protected:
    void run() override;

private:
    SQLInjectionScanner *m_scanner;
    QString m_url;
    QString m_method;
    bool m_isRunning;
};

#endif // SCAN_THREAD_H