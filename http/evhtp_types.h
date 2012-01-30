#pragma once

#include <stdint.h>

typedef struct evhtp_kv_s         evhtp_kv_t;
typedef struct evhtp_kvs_s        evhtp_kvs_t;


#define evhtp_header_s  evhtp_kv_s
#define evhtp_headers_s evhtp_kvs_s
#define evhtp_query_s   evhtp_kvs_s

#define evhtp_header_t  evhtp_kv_s
#define evhtp_headers_t evhtp_kvs_s
#define evhtp_query_t   evhtp_kvs_s

class EvHttpRequest;



#define EVHTP_RES_ERROR        0
#define EVHTP_RES_PAUSE        1
#define EVHTP_RES_FATAL        2
#define EVHTP_RES_OK           200

#define evhtp_header_find         evhtp_kv_find
#define evhtp_headers_find_header evhtp_kvs_find_kv
#define evhtp_headers_for_each    evhtp_kvs_for_each
#define evhtp_header_new          evhtp_kv_new
#define evhtp_header_free         evhtp_kv_free
#define evhtp_headers_new         evhtp_kvs_new
#define evhtp_headers_free        evhtp_kvs_free
#define evhtp_header_rm_and_free  evhtp_kv_rm_and_free
#define evhtp_headers_add_header  evhtp_kvs_add_kv
#define evhtp_query_new           evhtp_kvs_new
#define evhtp_query_free          evhtp_kvs_free




typedef struct evbuffer           evbuf_t;
typedef struct event              event_t;
typedef struct evconnlistener     evserv_t;
typedef struct bufferevent        evbev_t;


typedef struct event_base evbase_t;



typedef class evhtp_defaults_s   evhtp_defaults_t;
typedef class evhtp_callbacks_s  evhtp_callbacks_t;
typedef class HttpCallback   evhtp_callback_t;

typedef class EvHttpRequest    evhtp_request_t;
typedef class evhtp_hooks_s      evhtp_hooks_t;
typedef class evhtp_connection evhtp_connection_t;
typedef class evhtp_ssl_cfg    evhtp_ssl_cfg_t;
typedef uint16_t                  evhtp_res;
typedef uint8_t                   evhtp_error_flags;