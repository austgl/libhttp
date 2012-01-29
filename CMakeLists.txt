cmake_minimum_required (VERSION 2.8) 
PROJECT(websocketServer CXX C)

set (VERSION_MAJOR 1)
set (VERSION_MINOR 0)
find_package(OpenSSL REQUIRED)
find_package (Threads)
include (CheckFunctionExists)
check_function_exists (strcasecmp HAVE_STRCASECMP)
check_function_exists (snprintf HAVE_SNPRINTF)
configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
 )
 
include_directories(${PROJECT_SOURCE_DIR}/gtest/include)

ADD_SUBDIRECTORY(gtest) 
ADD_SUBDIRECTORY(http)
ADD_SUBDIRECTORY(src bin)