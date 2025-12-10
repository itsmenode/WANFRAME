cmake_minimum_required(VERSION 3.16)
project(NetOpsPlatform VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(Qt6 COMPONENTS Widgets REQUIRED)

find_package(SQLite3 REQUIRED)

add_subdirectory(common)
add_subdirectory(server)
add_subdirectory(client)