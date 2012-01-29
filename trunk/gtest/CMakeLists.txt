cmake_minimum_required (VERSION 2.8) 
add_definitions(-DUNICODE -D_UNICODE -DHAVE_CONFIG_H)
add_definitions(-DWIN32 -D_WIN32 -DSTRICT -DWIN32_LEAN_AND_MEAN -EHsc -D_HAS_EXCEPTIONS=1)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

ADD_LIBRARY(gtest STATIC gtest-all.cc)


