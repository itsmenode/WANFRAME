set(SERVER_SOURCES
    src/main.cpp
    src/server_core.cpp
    src/db_manager.cpp
    src/worker_thread.cpp
)

add_executable(NetOpsServer ${SERVER_SOURCES})

target_include_directories(NetOpsServer PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(NetOpsServer PRIVATE
    common_lib
    SQLite::SQLite3
    Threads::Threads
)