#include "http_client.h"
#include <QElapsedTimer>
#include <QEventLoop>

HttpClient::HttpClient(int timeout, QObject *parent)
    : QObject(parent)
    , m_manager(new QNetworkAccessManager(this))
    , m_defaultTimeout(timeout)
    , m_userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
{
}

HttpClient::~HttpClient()
{
}

HttpResponse HttpClient::get(const QString &url, int timeout)
{
    QNetworkRequest request(QUrl(url));
    return executeRequest(request, timeout);
}

HttpResponse HttpClient::post(const QString &url, const QUrlQuery &data, int timeout)
{
    QNetworkRequest request(QUrl(url));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    
    return executeRequest(request, timeout, data.toString(QUrl::FullyEncoded).toUtf8());
}

void HttpClient::setUserAgent(const QString &userAgent)
{
    m_userAgent = userAgent;
}

void HttpClient::addHeader(const QString &name, const QString &value)
{
    m_headers[name] = value;
}

void HttpClient::clearHeaders()
{
    m_headers.clear();
}

HttpResponse HttpClient::executeRequest(QNetworkRequest &request, int timeout, const QByteArray &postData)
{
    HttpResponse response;
    response.success = false;
    response.responseTime = 0.0;
    
    // Set timeout
    int requestTimeout = (timeout > 0) ? timeout : m_defaultTimeout;
    
    // Set headers
    request.setRawHeader("User-Agent", m_userAgent.toUtf8());
    for (auto it = m_headers.begin(); it != m_headers.end(); ++it) {
        request.setRawHeader(it.key().toUtf8(), it.value().toUtf8());
    }
    
    QElapsedTimer timer;
    timer.start();
    
    QNetworkReply *reply = nullptr;
    
    if (postData.isEmpty()) {
        reply = m_manager->get(request);
    } else {
        reply = m_manager->post(request, postData);
    }
    
    // Use event loop for synchronous operation
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(reply, QOverload<QNetworkReply::NetworkError>::of(&QNetworkReply::error),
                     &loop, &QEventLoop::quit);
    
    // Timeout handling
    QTimer::singleShot(requestTimeout, &loop, &QEventLoop::quit);
    
    loop.exec();
    
    response.responseTime = timer.elapsed() / 1000.0; // Convert to seconds
    
    if (reply->error() == QNetworkReply::NoError) {
        response.success = true;
        response.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        response.body = QString::fromUtf8(reply->readAll());
    } else {
        response.success = false;
        response.error = reply->errorString();
        response.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    }
    
    reply->deleteLater();
    return response;
}

void HttpClient::onRequestFinished()
{
    QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply) return;
    
    HttpResponse response;
    response.success = (reply->error() == QNetworkReply::NoError);
    response.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    response.body = QString::fromUtf8(reply->readAll());
    response.error = reply->errorString();
    
    emit requestFinished(response);
    reply->deleteLater();
}

void HttpClient::onRequestError(QNetworkReply::NetworkError error)
{
    Q_UNUSED(error)
    QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply) return;
    
    HttpResponse response;
    response.success = false;
    response.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    response.error = reply->errorString();
    
    emit requestFinished(response);
    reply->deleteLater();
}