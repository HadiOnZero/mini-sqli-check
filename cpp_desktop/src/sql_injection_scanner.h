#ifndef SQL_INJECTION_SCANNER_H
#define SQL_INJECTION_SCANNER_H

#include <QString>
#include <QVector>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QElapsedTimer>
#include <QMutex>
#include <QMutexLocker>

struct ScanResult {
    QString parameter;
    bool vulnerable;
    QStringList payloadsTested;
    QJsonArray errorsFound;
    QVector<double> responseTimes;
};

struct ErrorFound {
    QString payload;
    QString errorPattern;
    double responseTime;
};

struct Vulnerability {
    QString url;
    QString parameter;
    QString method;
};

class SQLInjectionScanner : public QObject
{
    Q_OBJECT

public:
    explicit SQLInjectionScanner(int timeout = 10, int threads = 5, QObject *parent = nullptr);
    ~SQLInjectionScanner();

    QJsonObject scanUrl(const QString &url, const QString &method = "GET");
    QString generateReport(const QJsonObject &results);
    bool saveReport(const QJsonObject &results, const QString &filename = "");

    // Getters
    int timeout() const { return m_timeout; }
    int threads() const { return m_threads; }
    QStringList payloads() const { return m_payloads; }
    QStringList errorPatterns() const { return m_errorPatterns; }
    QVector<Vulnerability> vulnerabilities() const;

    // Setters
    void setTimeout(int timeout) { m_timeout = timeout; }
    void setThreads(int threads) { m_threads = threads; }
    void setPayloads(const QStringList &payloads) { m_payloads = payloads; }
    void setErrorPatterns(const QStringList &patterns) { m_errorPatterns = patterns; }

signals:
    void scanProgress(int progress);
    void scanCompleted(const QJsonObject &results);
    void scanFailed(const QString &error);
    void logMessage(const QString &message, const QString &type);

private slots:
    void onRequestFinished(QNetworkReply *reply);

private:
    ScanResult testParameter(const QString &url, const QString &param, const QString &method = "GET");
    QStringList extractParameters(const QString &url);
    void processResponse(QNetworkReply *reply, const QString &payload, const QString &param, ScanResult &result);
    
    int m_timeout;
    int m_threads;
    QNetworkAccessManager *m_networkManager;
    QStringList m_payloads;
    QStringList m_errorPatterns;
    QVector<Vulnerability> m_vulnerabilities;
    QMutex m_mutex;
    QElapsedTimer m_scanTimer;
    
    // HTTP request tracking
    int m_activeRequests;
    int m_totalRequests;
    int m_completedRequests;
};

#endif // SQL_INJECTION_SCANNER_H