cmake_minimum_required (VERSION 2.8) 
add_definitions(-DUNICODE -D_UNICODE -DHAVE_CONFIG_H -D_CRT_SECURE_NO_WARNINGS)

set(SRC_LIST MyHtparseHooks.cpp MyHtparseHooks.h cminit.h evhtp.cpp evhtp.h evhtp_authority.h evhtp_callback.h evhtp_callback_type.h evhtp_callbacks.cpp evhtp_callbacks.h evhtp_connection.cpp evhtp_connection.h evhtp_defaults.h evhtp_hook_type.h evhtp_kv.h evhtp_path.cpp evhtp_path.h evhtp_proto.h evhtp_request.cpp evhtp_request.h evhtp_s.cpp evhtp_s.h evhtp_ssl_cfg.cpp evhtp_ssl_cfg.h evhtp_ssl_scache_type.h evhtp_types.h evhtp_uri.cpp evhtp_uri.h htp_method.h htp_scheme.h htp_type.h htparse.cpp htparse.h htparse_hooks.h htparse_imp.h  htpparse_error.h http_status_codes.h myhooks.h myqueue.h mystrcasecmp.cpp mystrcasecmp.h parser_flags.h parser_state.h  status_code.cpp status_code.h ) #evthr.cpp evthr.h 
include_directories(${PROJECT_BINARY_DIR}  ${OPENSSL_INCLUDE_DIR})

if(WIN32)
SET(GLOG_LIB libglog)
SET(TBB_DEBUG_LIB tbb_debug)
SET(TBB_LIB tbb)
SET(EVENT_LIB libevent)
SET(SOCKET_LIB Ws2_32)
elseif(UNIX)
SET(GLOG_LIB glog)
SET(TBB_DEBUG_LIB tbb)
SET(TBB_LIB tbb)
SET(SOCKET_LIB )
SET(EVENT_LIB "-L/usr/local/lib/event2 -levent_openssl -levent_core -Wl,-rpath=/usr/local/lib/event2")
endif()


ADD_LIBRARY(minihttp STATIC ${SRC_LIST})

#add_executable (test_parser test_parser.cpp)
#target_link_libraries (test_parser  minihttp )
#target_link_libraries (test_parser  libglog )

add_executable (htparse_unitest htparse_unitest.cpp)
target_link_libraries (htparse_unitest  minihttp gtest)
target_link_libraries (htparse_unitest  ${GLOG_LIB} )
target_link_libraries (htparse_unitest  debug ${TBB_DEBUG_LIB})
ADD_TEST(htparse_unitest ${CMAKE_CURRENT_BINARY_DIR}/htparse_unitest)

add_executable (simple_server simple_server_unitest.cpp)
target_link_libraries (simple_server  minihttp gtest)
target_link_libraries (simple_server  ${GLOG_LIB} ${EVENT_LIB} ${OPENSSL_LIBRARIES} onig ${SOCKET_LIB})
target_link_libraries (simple_server  debug ${TBB_DEBUG_LIB})


