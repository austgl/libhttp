#pragma once

#include "evhtp_types.h"

#include <stdint.h>
#include <event2/event.h>

enum evhtp_callback_type {
    evhtp_callback_type_hash,
    evhtp_callback_type_regex
};

class EvHttpRequest;
class HttpPath;

typedef void (*evhtp_callback_cb)(EvHttpRequest * req, void * arg);

typedef void (*evhtp_hook_err_cb)(EvHttpRequest * req, uint8_t errtype, void * arg);
typedef uint16_t (*evhtp_pre_accept_cb)(int fd, struct sockaddr * sa, int salen, void * arg);
typedef uint16_t (*evhtp_post_accept_cb)(evhtp_connection * conn, void * arg);
typedef uint16_t (*evhtp_hook_header_cb)(EvHttpRequest * req, evhtp_header_s * hdr, void * arg);
typedef uint16_t (*evhtp_hook_headers_cb)(EvHttpRequest * req, evhtp_headers_s * hdr, void * arg);
typedef uint16_t (*evhtp_hook_path_cb)(EvHttpRequest * req, HttpPath * path, void * arg);
typedef uint16_t (*evhtp_hook_read_cb)(EvHttpRequest * req, evbuffer * buf, void * arg);
typedef uint16_t (*evhtp_hook_request_fini_cb)(EvHttpRequest * req, void * arg);
typedef uint16_t (*evhtp_hook_connection_fini_cb)(evhtp_connection * connection, void * arg);
typedef uint16_t (*evhtp_hook_chunk_new_cb)(EvHttpRequest * r, uint64_t len, void * arg);
typedef uint16_t (*evhtp_hook_chunk_fini_cb)(EvHttpRequest * r, void * arg);
typedef uint16_t (*evhtp_hook_chunks_fini_cb)(EvHttpRequest * r, void * arg);
typedef uint16_t (*evhtp_hook_headers_start_cb)(EvHttpRequest * r, void * arg);