cmake_minimum_required (VERSION 2.8) 
add_definitions(-DUNICODE -D_UNICODE -DHAVE_CONFIG_H -D_CRT_SECURE_NO_WARNINGS)
include_directories(${PROJECT_BINARY_DIR})

foreach(testname template_util_unittest  type_traits_unittest libc_allocator_with_realloc_test sparsetable_unittest hashtable_test simple_test)
add_executable (${testname} ${testname}.cc)
target_link_libraries (${testname}  gtest)
ADD_TEST(${testname} ${CMAKE_CURRENT_BINARY_DIR}/${testname})
endforeach(testname)


