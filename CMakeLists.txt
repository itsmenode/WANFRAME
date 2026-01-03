cmake_minimum_required(VERSION 3.10)
project(WANFRAME VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(server client common)

# ==========================================
#               SERVER BUILD
# ==========================================
add_executable(Server
    server/main.cpp
    server/NetworkCore.cpp
    server/DatabaseManager.cpp
    common/ByteBuffer.cpp
)

target_link_libraries(Server PRIVATE 
    SQLite::SQLite3 
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

# ==========================================
#               CLIENT BUILD
# ==========================================
add_executable(Client
    client/main.cpp
)

target_link_libraries(Client PRIVATE 
    Threads::Threads 
    OpenSSL::SSL 
    OpenSSL::Crypto
)