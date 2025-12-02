cmake_minimum_required(VERSION 3.16)

project(NetOpsMonitor LANGUAGES CXX)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Server executable
add_executable(netops_server
    server/main_server.cpp
    common/protocol.cpp
)

# Client executable
add_executable(netops_client
    client/main_client.cpp
    common/protocol.cpp
)

# Optionally add warnings (GCC / Clang)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(netops_server PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(netops_client PRIVATE -Wall -Wextra -Wpedantic)
endif()