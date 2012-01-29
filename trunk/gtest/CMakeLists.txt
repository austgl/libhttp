cmake_minimum_required (VERSION 2.8) 
add_definitions(-DHAVE_CONFIG_H)

if(WIN32)
add_definitions(-DUNICODE -D_UNICODE  -DWIN32 -D_WIN32 -DSTRICT -DWIN32_LEAN_AND_MEAN -EHsc -D_HAS_EXCEPTIONS=1)
elseif(UNIX)
add_definitions(-D_THREAD_SAFE -DGTEST_HAS_PTHREAD=1)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

ADD_LIBRARY(gtest STATIC gtest-all.cc)


