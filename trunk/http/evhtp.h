#pragma once

#include "htparse.h"

#include "http_status_codes.h"
#include "evhtp_types.h"
#include "myhooks.h"
#include "evhtp_callback_type.h"
#include "evhtp_hook_type.h"
#include "evhtp_proto.h"
#include "evhtp_ssl_scache_type.h"

#include <stdexcept>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>


#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>


class evhtp_connection;

typedef enum evhtp_hook_type       evhtp_hook_type;
typedef enum evhtp_callback_type   evhtp_callback_type;
typedef enum evhtp_proto           evhtp_proto;
typedef enum evhtp_ssl_scache_type evhtp_ssl_scache_type;

//typedef void (*evhtp_thread_init_cb)(evhtp_t * htp, evthr_t * thr, void * arg);

typedef int (*evhtp_headers_iterator)(evhtp_header_t * header, void * arg);

#define EVHTP_VERSION          "0.4.6"
#define EVHTP_VERSION_MAJOR    0
#define EVHTP_VERSION_MINOR    4
#define EVHTP_VERSION_PATCH    6

#define evhtp_headers_iterator evhtp_kvs_iterator


#define evhtp_request_content_len(r) htparser_get_content_length(r->conn->parser)

class evhtp;
void      evhtp_set_timeouts(evhtp * htp, struct timeval * r, struct timeval * w);
int       evhtp_ssl_use_threads(void);
int       evhtp_ssl_init(evhtp * htp, evhtp_ssl_cfg_t * ssl_cfg);


/**
 * @brief creates a lock around callbacks and hooks, allowing for threaded
 * applications to add/remove/modify hooks & callbacks in a thread-safe manner.
 *
 * @param htp
 *
 * @return 0 on success, -1 on error
 */
int evhtp_use_callback_locks(evhtp * htp);

/**
 * @brief sets a callback which is called if no other callbacks are matched
 *
 * @param htp the initialized evhtp_t
 * @param cb  the function to be executed
 * @param arg user-defined argument passed to the callback
 */
void evhtp_set_gencb(evhtp * htp, evhtp_callback_cb cb, void * arg);
void evhtp_set_pre_accept_cb(evhtp * htp, evhtp_pre_accept_cb, void * arg);
void evhtp_set_post_accept_cb(evhtp * htp, evhtp_post_accept_cb, void * arg);


/**
 * @brief sets a callback to be executed on a specific path
 *
 * @param htp the initialized evhtp_t
 * @param path the path to match
 * @param cb the function to be executed
 * @param arg user-defined argument passed to the callback
 *
 * @return evhtp_callback_t * on success, NULL on error.
 */
evhtp_callback_t * evhtp_set_cb(evhtp * htp, const char * path, evhtp_callback_cb cb, void * arg);


/**
 * @brief sets a callback to be executed based on a regex pattern
 *
 * @param htp the initialized evhtp_t
 * @param pattern a POSIX compat regular expression
 * @param cb the function to be executed
 * @param arg user-defined argument passed to the callback
 *
 * @return evhtp_callback_t * on success, NULL on error
 */
evhtp_callback_t * evhtp_set_regex_cb(evhtp * htp, const char * pattern, evhtp_callback_cb cb, void * arg);


/**
 * @brief sets a callback hook for either a connection or a path/regex .
 *
 * A user may set a variety of hooks either per-connection, or per-callback.
 * This allows the developer to hook into various parts of the request processing
 * cycle.
 *
 * a per-connection hook can be set at any time, but it is recommended to set these
 * during either a pre-accept phase, or post-accept phase. This allows a developer
 * to set hooks before any other hooks are called.
 *
 * a per-callback hook works differently. In this mode a developer can setup a set
 * of hooks prior to starting the event loop for specific callbacks. For example
 * if you wanted to hook something ONLY for a callback set by evhtp_set_cb or
 * evhtp_set_regex_cb this is the method of doing so.
 *
 * per-callback example:
 *
 * evhtp_callback_t * cb = evhtp_set_regex_cb(htp, "/anything/(.*)", default_cb, NULL);
 *
 * evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, anything_headers_cb, NULL);
 *
 * evhtp_set_hook(&cb->hooks, evhtp_hook_on_fini, anything_fini_cb, NULL);
 *
 * With the above example, once libevhtp has determined that it has a user-defined
 * callback for /anything/.*; anything_headers_cb will be executed after all headers
 * have been parsed, and anything_fini_cb will be executed before the request is
 * free()'d.
 *
 * The same logic applies to per-connection hooks, but it should be noted that if
 * a per-callback hook is set, the per-connection hook will be ignored.
 *
 * @param hooks double pointer to the evhtp_hooks_t structure
 * @param type the hook type
 * @param cb the callback to be executed.
 * @param arg optional argument which is passed when the callback is executed
 *
 * @return 0 on success, -1 on error (if hooks is NULL, it is allocated)
 */
int  evhtp_set_hook(evhtp_hooks_t ** hooks, evhtp_hook_type type, void * cb, void * arg);

int  evhtp_bind_socket(evhtp * htp, const char * addr, uint16_t port, int backlog);
int  evhtp_bind_sockaddr(evhtp * htp, struct sockaddr *, size_t sin_len, int backlog);

//int  evhtp_use_threads(evhtp_t * htp, evhtp_thread_init_cb init_cb, int nthreads, void * arg);

void evhtp_send_reply(evhtp_request_t * request, evhtp_res code);

void evhtp_send_reply_start(evhtp_request_t * request, evhtp_res code);
void evhtp_send_reply_body(evhtp_request_t * request, evbuf_t * buf);
void evhtp_send_reply_end(evhtp_request_t * request);

/**
 * @brief Determine if a response should have a body.
 * Follows the rules in RFC 2616 section 4.3.
 * @return 1 if the response MUST have a body; 0 if the response MUST NOT have
 *     a body.
 */
int  evhtp_response_needs_body(const evhtp_res code, const HttpMethod method);
void evhtp_send_reply_chunk_start(evhtp_request_t * request, evhtp_res code);
void evhtp_send_reply_chunk(evhtp_request_t * request, evbuf_t * buf);
void evhtp_send_reply_chunk_end(evhtp_request_t * request);







/**
 * @brief Adds a evhtp_callback_t to the evhtp_callbacks_t list
 *
 * @param cbs an allocated evhtp_callbacks_t structure
 * @param cb  an initialized evhtp_callback_t structure
 *
 * @return 0 on success, -1 on error
 */
int evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb);



/**
 * @brief Parses the query portion of the uri into a set of key/values
 *
 * Parses query arguments like "?herp=derp&foo=bar;blah=baz"
 *
 * @param query data containing the uri query arguments
 * @param len size of the data
 *
 * @return evhtp_query_t * on success, NULL on error
 */
evhtp_query_t * evhtp_parse_query(const char * query, size_t len);


/**
 * @brief Unescapes strings like '%7B1,%202,%203%7D' would become '{1, 2, 3}'
 *
 * @param out double pointer where output is stored. This is allocated by the user.
 * @param str the string to unescape
 * @param str_len the length of the string to unescape
 *
 * @return 0 on success, -1 on error
 */
int evhtp_unescape_string(unsigned char ** out, unsigned char * str, size_t str_len);

/**
 * @brief creates a new evhtp_header_t key/val structure
 *
 * @param key a null terminated string
 * @param val a null terminated string
 * @param kalloc if 1, key will be copied, otherwise no copy performed
 * @param valloc if 1, val will be copied, otehrwise no copy performed
 *
 * @return evhtp_header_t * or NULL on error
 */
evhtp_header_t * evhtp_header_new(const char * key, const char * val, char kalloc, char valloc);

/**
 * @brief creates a new evhtp_header_t, sets only the key, and adds to the
 *        evhtp_headers TAILQ
 *
 * @param headers the evhtp_headers_t TAILQ (evhtp_kv_t)
 * @param key a null terminated string
 * @param kalloc if 1 the string will be copied, otherwise assigned
 *
 * @return an evhtp_header_t pointer or NULL on error
 */
evhtp_header_t * evhtp_header_key_add(evhtp_headers_t * headers, const char * key, char kalloc);


/**
 * @brief finds the last header in the headers tailq and adds the value
 *
 * @param headers the evhtp_headers_t TAILQ (evhtp_kv_t)
 * @param val a null terminated string
 * @param valloc if 1 the string will be copied, otherwise assigned
 *
 * @return an evhtp_header_t pointer or NULL on error
 */
evhtp_header_t * evhtp_header_val_add(evhtp_headers_t * headers, const char * val, char valloc);


/**
 * @brief adds an evhtp_header_t to the end of the evhtp_headers_t tailq
 *
 * @param headers
 * @param header
 */
void evhtp_headers_add_header(evhtp_headers_t * headers, evhtp_header_t * header);

/**
 * @brief finds the value of a key in a evhtp_headers_t structure
 *
 * @param headers the evhtp_headers_t tailq
 * @param key the key to find
 *
 * @return the value of the header key if found, NULL if not found.
 */
const char * evhtp_header_find(evhtp_headers_t * headers, const char * key);




/**
 * @brief returns the htp_method enum version of the request method.
 *
 * @param r
 *
 * @return htp_method enum
 */
HttpMethod evhtp_request_get_method(evhtp_request_t * r);

void       evhtp_connection_pause(evhtp_connection_t * connection);
void       evhtp_connection_resume(evhtp_connection_t * connection);
void       evhtp_request_pause(evhtp_request_t * request);
void       evhtp_request_resume(evhtp_request_t * request);



/**
 * @brief returns the underlying evhtp_connection_t structure from a request
 *
 * @param request
 *
 * @return evhtp_connection_t on success, otherwise NULL
 */
evhtp_connection_t * evhtp_request_get_connection(evhtp_request_t * request);

/**
 * @brief Sets the connections underlying bufferevent
 *
 * @param conn
 * @param bev
 */
void evhtp_connection_set_bev(evhtp_connection_t * conn, evbev_t * bev);

/**
 * @brief sets the underlying bufferevent for a evhtp_request
 *
 * @param request
 * @param bev
 */
void evhtp_request_set_bev(evhtp_request_t * request, evbev_t * bev);


/**
 * @brief returns the underlying connections bufferevent
 *
 * @param conn
 *
 * @return bufferevent on success, otherwise NULL
 */
evbev_t * evhtp_connection_get_bev(evhtp_connection_t * conn);

/**
 * @brief returns the underlying requests bufferevent
 *
 * @param request
 *
 * @return bufferevent on success, otherwise NULL
 */
evbev_t * evhtp_request_get_bev(evhtp_request_t * request);



