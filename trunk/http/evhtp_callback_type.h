#pragma once

#include "evhtp_types.h"

#include <stdint.h>
#include <event2/event.h>

enum evhtp_callback_type {
    evhtp_callback_type_hash,
    evhtp_callback_type_regex
};

class evhtp_request_s;

typedef void (*evhtp_callback_cb)(evhtp_request_s * req, void * arg);

typedef void (*evhtp_hook_err_cb)(evhtp_request_s * req, uint8_t errtype, void * arg);
typedef uint16_t (*evhtp_pre_accept_cb)(int fd, struct sockaddr * sa, int salen, void * arg);
typedef uint16_t (*evhtp_post_accept_cb)(evhtp_connection_s * conn, void * arg);
typedef uint16_t (*evhtp_hook_header_cb)(evhtp_request_s * req, evhtp_header_s * hdr, void * arg);
typedef uint16_t (*evhtp_hook_headers_cb)(evhtp_request_s * req, evhtp_headers_s * hdr, void * arg);
typedef uint16_t (*evhtp_hook_path_cb)(evhtp_request_s * req, evhtp_path_s * path, void * arg);
typedef uint16_t (*evhtp_hook_read_cb)(evhtp_request_s * req, evbuffer * buf, void * arg);
typedef uint16_t (*evhtp_hook_request_fini_cb)(evhtp_request_s * req, void * arg);
typedef uint16_t (*evhtp_hook_connection_fini_cb)(evhtp_connection_s * connection, void * arg);
typedef uint16_t (*evhtp_hook_chunk_new_cb)(evhtp_request_s * r, uint64_t len, void * arg);
typedef uint16_t (*evhtp_hook_chunk_fini_cb)(evhtp_request_s * r, void * arg);
typedef uint16_t (*evhtp_hook_chunks_fini_cb)(evhtp_request_s * r, void * arg);
typedef uint16_t (*evhtp_hook_headers_start_cb)(evhtp_request_s * r, void * arg);