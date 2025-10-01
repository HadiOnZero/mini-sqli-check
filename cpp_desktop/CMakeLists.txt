cmake_minimum_required(VERSION 3.16)

project(SQLInjectionScanner VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find required packages
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Concurrent)
find_package(Threads REQUIRED)

# Define the executable
add_executable(SQLInjectionScanner
    main.cpp
    src/sql_injection_scanner.cpp
    src/sql_injection_scanner.h
    src/http_client.cpp
    src/http_client.h
    src/parameter_extractor.cpp
    src/parameter_extractor.h
    src/main_window.cpp
    src/main_window.h
    src/scan_thread.cpp
    src/scan_thread.h
    src/result_widget.cpp
    src/result_widget.h
    src/payload_widget.cpp
    src/payload_widget.h
    resources/resources.qrc
)

# Link libraries
target_link_libraries(SQLInjectionScanner 
    Qt6::Core 
    Qt6::Widgets 
    Qt6::Network 
    Qt6::Concurrent
    Threads::Threads
)

# Set properties
set_target_properties(SQLInjectionScanner PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)

# Install target
install(TARGETS SQLInjectionScanner
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)