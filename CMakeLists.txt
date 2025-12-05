cmake_minimum_required(VERSION 3.17)
project(NetOpsMonitor CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Common Library (Shared Protocol/Buffers)
add_library(common STATIC common/ByteBuffer.cpp)
target_include_directories(common PUBLIC common)

# 2. The Server (Epoll)
add_executable(netops_server server/main.cpp)
target_link_libraries(netops_server PRIVATE common)

# 3. The Client (Blocking Test)
add_executable(netops_client client/main.cpp)
target_link_libraries(netops_client PRIVATE common)