cmake_minimum_required(VERSION 3.10)
project(NetOps)

set(CMAKE_CXX_STANDARD 17)

# OpenSSL
find_package(OpenSSL REQUIRED)

# SQLite3
find_package(SQLite3 REQUIRED)

# Source Files
set(COMMON_SOURCES
    common/ByteBuffer.cpp
)

set(SERVER_SOURCES
    server/main.cpp
    server/NetworkCore.cpp
    server/Worker.cpp
    server/DatabaseManager.cpp
    server/SessionManager.cpp
    ${COMMON_SOURCES}
)

set(CLIENT_SOURCES
    client/main.cpp
    client/ClientNetwork.cpp
    ${COMMON_SOURCES}
)

# Executables
add_executable(Server ${SERVER_SOURCES})
target_link_libraries(Server OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)

add_executable(Client ${CLIENT_SOURCES})
target_link_libraries(Client OpenSSL::SSL OpenSSL::Crypto)