cmake_minimum_required(VERSION 3.10)
project(WANFRAME)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# --- 1. Dependencies ---
find_package(OpenSSL REQUIRED)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# Manual SQLite3 Find
find_path(SQLITE3_INCLUDE_DIR sqlite3.h)
find_library(SQLITE3_LIBRARY sqlite3)

if(NOT SQLITE3_INCLUDE_DIR OR NOT SQLITE3_LIBRARY)
    message(FATAL_ERROR "SQLite3 not found! Install it: sudo apt install libsqlite3-dev")
else()
    message(STATUS "Found SQLite3: ${SQLITE3_LIBRARY}")
endif()

# --- 2. Include Directories ---

add_library(WANCommon
    common/ByteBuffer.cpp
)

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
)

target_link_libraries(Server
    WANCommon
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
    client/ClientNetwork.cpp
    client/Scanner.cpp
    client/SyslogCollector.cpp
    client/DeviceMonitor.cpp
    client/SnmpClient.cpp
)

target_link_libraries(Client
    WANCommon
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

message(STATUS "Build setup complete.")