#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>
#include <QUrlQuery>
#include <QObject>

struct HttpResponse {
    int statusCode;
    QString body;
    QString error;
    double responseTime; // in seconds
    bool success;
};

class HttpClient : public QObject
{
    Q_OBJECT

public:
    explicit HttpClient(int timeout = 10000, QObject *parent = nullptr);
    ~HttpClient();

    HttpResponse get(const QString &url, int timeout = -1);
    HttpResponse post(const QString &url, const QUrlQuery &data, int timeout = -1);
    
    void setUserAgent(const QString &userAgent);
    void addHeader(const QString &name, const QString &value);
    void clearHeaders();

signals:
    void requestFinished(const HttpResponse &response);

private slots:
    void onRequestFinished();
    void onRequestError(QNetworkReply::NetworkError error);

private:
    HttpResponse executeRequest(QNetworkRequest &request, int timeout);
    
    QNetworkAccessManager *m_manager;
    int m_defaultTimeout;
    QString m_userAgent;
    QHash<QString, QString> m_headers;
};

#endif // HTTP_CLIENT_H