#include <QApplication>
#include <QStyleFactory>
#include "src/main_window.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // Set application properties
    app.setApplicationName("SQL Injection Scanner");
    app.setApplicationVersion("2.0");
    app.setOrganizationName("Cyberpunk Security Tools");
    
    // Set fusion style for better theming
    app.setStyle(QStyleFactory::create("Fusion"));
    
    // Create and show main window
    MainWindow window;
    window.show();
    
    return app.exec();
}