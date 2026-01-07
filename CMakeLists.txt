cmake_minimum_required(VERSION 3.16) # Qt 6 generally requires a higher CMake version
project(WANFRAME)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# --- 1. Dependencies ---
find_package(OpenSSL REQUIRED)

# Updated for Qt 6
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt6 COMPONENTS Widgets REQUIRED)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# Manual SQLite3 Find
find_path(SQLITE3_INCLUDE_DIR sqlite3.h)
find_library(SQLITE3_LIBRARY sqlite3)

if(NOT SQLITE3_INCLUDE_DIR OR NOT SQLITE3_LIBRARY)
    message(FATAL_ERROR "SQLite3 not found!")
endif()

# --- 2. Include Directories ---
include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIR}
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
# Note: Added LoginWindow files here
add_executable(Client
    client/main.cpp
    client/NetworkController.cpp
    client/ClientNetwork.cpp
    client/Scanner.cpp
    client/SyslogCollector.cpp
    client/LoginWindow.cpp
    common/ByteBuffer.cpp
)

target_link_libraries(Client
    Qt6::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)