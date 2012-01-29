#pragma once
#include "evhtp_types.h"
#include "evhtp_callback_type.h"

class evhtp_hooks_s {
public:
    evhtp_hook_headers_start_cb   on_headers_start;
    evhtp_hook_header_cb          on_header;
    evhtp_hook_headers_cb         on_headers;
    evhtp_hook_path_cb            on_path;
    evhtp_hook_read_cb            on_read;
    evhtp_hook_request_fini_cb    on_request_fini;
    evhtp_hook_connection_fini_cb on_connection_fini;
    evhtp_hook_err_cb             on_error;
    evhtp_hook_chunk_new_cb       on_new_chunk;
    evhtp_hook_chunk_fini_cb      on_chunk_fini;
    evhtp_hook_chunks_fini_cb     on_chunks_fini;

    void * on_headers_start_arg;
    void * on_header_arg;
    void * on_headers_arg;
    void * on_path_arg;
    void * on_read_arg;
    void * on_request_fini_arg;
    void * on_connection_fini_arg;
    void * on_error_arg;
    void * on_new_chunk_arg;
    void * on_chunk_fini_arg;
    void * on_chunks_fini_arg;
};

#define HOOK_AVAIL(var, hook_name)                 (var->hooks && var->hooks->hook_name)
#define HOOK_FUNC(var, hook_name)                  (var->hooks->hook_name)
#define HOOK_ARGS(var, hook_name)                  var->hooks->hook_name ## _arg

#define HOOK_REQUEST_RUN(request, hook_name, ...)  do {                                       \
        if (HOOK_AVAIL(request, hook_name)) {                                                 \
            return HOOK_FUNC(request, hook_name) (request, __VA_ARGS__,                       \
                                                  HOOK_ARGS(request, hook_name));             \
        }                                                                                     \
                                                                                              \
        if (HOOK_AVAIL(evhtp_request_get_connection(request), hook_name)) {                   \
            return HOOK_FUNC(request->conn, hook_name) (request, __VA_ARGS__,                 \
                                                        HOOK_ARGS(request->conn, hook_name)); \
        }                                                                                     \
} while (0)

#define HOOK_REQUEST_RUN_NARGS(request, hook_name) do {                                       \
        if (HOOK_AVAIL(request, hook_name)) {                                                 \
            return HOOK_FUNC(request, hook_name) (request,                                    \
                                                  HOOK_ARGS(request, hook_name));             \
        }                                                                                     \
                                                                                              \
        if (HOOK_AVAIL(request->conn, hook_name)) {                                           \
            return HOOK_FUNC(request->conn, hook_name) (request,                              \
                                                        HOOK_ARGS(request->conn, hook_name)); \
        }                                                                                     \
} while (0);

#define HOOK_REQUEST_RUN_NARGS_NO_RETURN(request, hook_name) do {                                       \
        if (HOOK_AVAIL(request, hook_name)) {                                                 \
            HOOK_FUNC(request, hook_name) (request,                                    \
                                                  HOOK_ARGS(request, hook_name));return;             \
        }                                                                                     \
                                                                                              \
        if (HOOK_AVAIL(request->conn, hook_name)) {                                           \
            HOOK_FUNC(request->conn, hook_name) (request,                              \
                                                        HOOK_ARGS(request->conn, hook_name)); return;\
        }                                                                                     \
} while (0);
