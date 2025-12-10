set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(CLIENT_SOURCES
    src/main.cpp
    src/main_window.cpp
    src/client_backend.cpp
    src/login_dialog.cpp
    src/scanner_thread.cpp
)

add_executable(NetOpsClient WIN32 ${CLIENT_SOURCES})

target_include_directories(NetOpsClient PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(NetOpsClient PRIVATE
    common_lib
    Qt6::Widgets
)