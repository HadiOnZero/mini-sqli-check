#include "parameter_extractor.h"
#include <QUrl>
#include <QUrlQuery>
#include <QRegularExpression>

QStringList ParameterExtractor::extractParameters(const QString &url)
{
    QUrl qurl(url);
    if (!qurl.isValid()) {
        return QStringList();
    }
    
    QUrlQuery query(qurl.query());
    QStringList parameters;
    
    for (const auto &item : query.queryItems()) {
        parameters.append(item.first);
    }
    
    return parameters;
}

QString ParameterExtractor::buildUrlWithParameter(const QString &baseUrl, const QString &param, const QString &value)
{
    QUrl url(baseUrl);
    if (!url.isValid()) {
        return baseUrl;
    }
    
    QUrlQuery query(url.query());
    
    // Add the parameter
    query.addQueryItem(param, value);
    
    url.setQuery(query);
    return url.toString();
}

bool ParameterExtractor::isValidUrl(const QString &url)
{
    QUrl qurl(url);
    return qurl.isValid() && (qurl.scheme() == "http" || qurl.scheme() == "https");
}

QString ParameterExtractor::encodeParameter(const QString &param)
{
    return QUrl::toPercentEncoding(param);
}