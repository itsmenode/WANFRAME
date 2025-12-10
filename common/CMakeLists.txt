set(COMMON_SOURCES
    src/protocol.cpp
    src/byte_buffer.cpp
    src/secure_layer.cpp
    src/utils.cpp
)

add_library(common_lib STATIC ${COMMON_SOURCES})

target_include_directories(common_lib PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(common_lib PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)