cmake_minimum_required(VERSION 3.17)
project(NetOpsMonitor CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(common STATIC common/ByteBuffer.cpp common/protocol.hpp)
target_include_directories(common PUBLIC common)

add_executable(netops_server server/main.cpp server/NetworkCore.cpp)

target_link_libraries(netops_server 
    PRIVATE 
    common 
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_executable(netops_client client/main.cpp)
target_link_libraries(netops_client 
    PRIVATE 
    common
    OpenSSL::SSL
    OpenSSL::Crypto
)