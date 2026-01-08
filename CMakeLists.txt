cmake_minimum_required(VERSION 3.16)
project(WANFRAME)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# --- 1. Dependencies ---
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt6 COMPONENTS Widgets REQUIRED)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# Database
find_path(SQLITE3_INCLUDE_DIR sqlite3.h)
find_library(SQLITE3_LIBRARY sqlite3)

if(NOT SQLITE3_INCLUDE_DIR OR NOT SQLITE3_LIBRARY)
    message(FATAL_ERROR "SQLite3 not found!")
endif()

pkg_check_modules(TINS REQUIRED libtins) 

find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found! Install libpcap-dev")
endif()

# --- 2. Include Directories ---
include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIR}
    ${TINS_INCLUDE_DIRS} 
    server
    client
    common
)

# ==========================
#        SERVER BUILD
# ==========================
add_executable(Server
    server/main.cpp
    server/NetworkCore.cpp
    server/Worker.cpp
    server/DatabaseManager.cpp
    server/SessionManager.cpp
    common/ByteBuffer.cpp
)

target_link_libraries(Server
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE3_LIBRARY}
    Threads::Threads
    dl 
)

# ==========================
#        CLIENT BUILD
# ==========================
add_executable(Client
    client/main.cpp
    client/NetworkController.cpp
    client/ClientNetwork.cpp
    client/Scanner.cpp
    client/SyslogCollector.cpp
    client/LoginWindow.cpp
    client/MainWindow.cpp
    client/DeviceMonitor.cpp
    client/SnmpClient.cpp
    common/ByteBuffer.cpp
)

target_link_libraries(Client
    Qt6::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${TINS_LIBRARIES}
    ${PCAP_LIBRARY}
)

# ==========================
#      RESOURCE HANDLING
# ==========================
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/certs" 
     DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")