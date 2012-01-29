cmake_minimum_required (VERSION 2.8) 
add_definitions(-DUNICODE -D_UNICODE -DHAVE_CONFIG_H)
set(SRC_LIST main.cpp)
include_directories(${PROJECT_BINARY_DIR} ${OPENSSL_INCLUDE_DIR})

add_executable (server ${SRC_LIST})


