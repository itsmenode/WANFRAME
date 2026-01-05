cmake_minimum_required(VERSION 3.10)
project(WANFRAME)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Required Packages
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

# Include Directories
include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIRS}
    server
    client
    common
)

# --- SERVER EXECUTABLE ---
add_executable(Server
    server/main.cpp
    server/NetworkCore.cpp
    server/Worker.cpp
    server/DatabaseManager.cpp
    server/SessionManager.cpp
    common/protocol.cpp
)

# Link Libraries for Server
target_link_libraries(Server
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    Threads::Threads
    dl
)

# --- CLIENT EXECUTABLE ---
add_executable(Client
    client/main.cpp
    client/ClientNetwork.cpp
    client/Scanner.cpp
    common/protocol.cpp
)

# Link Libraries for Client
target_link_libraries(Client
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Output build status
message(STATUS "Build setup complete.")
message(STATUS "Server Source: server/main.cpp")
message(STATUS "Client Source: client/main.cpp")