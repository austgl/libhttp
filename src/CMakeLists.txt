cmake_minimum_required (VERSION 2.8) 
add_definitions(-DUNICODE -D_UNICODE -DHAVE_CONFIG_H)
set(SRC_LIST main.cpp)
include_directories(${PROJECT_BINARY_DIR})

add_executable (server ${SRC_LIST})


if(WIN32)
target_link_libraries (server  debug libevent_d)
elseif(UNIX)
target_link_libraries (server  event)
endif()
