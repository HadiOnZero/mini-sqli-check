#ifndef PARAMETER_EXTRACTOR_H
#define PARAMETER_EXTRACTOR_H

#include <QString>
#include <QStringList>
#include <QUrl>
#include <QUrlQuery>

class ParameterExtractor
{
public:
    static QStringList extractParameters(const QString &url);
    static QString buildUrlWithParameter(const QString &baseUrl, const QString &param, const QString &value);
    static bool isValidUrl(const QString &url);
    static QString encodeParameter(const QString &param);
    
private:
    ParameterExtractor() = default; // Static class
};

#endif // PARAMETER_EXTRACTOR_H