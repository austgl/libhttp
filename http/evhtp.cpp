﻿#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glog/logging.h>

#include "evhtp_connection.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <memory> //auto_ptr
#include <inttypes.h>

#ifdef OS_TYPE_FreeBSD
#include <netinet/in.h> //htons
#include <arpa/inet.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <stdio.h>
#include "evhtp.h"
#include "MyHtparseHooks.h"
#include "evhtp_kv.h"
#include "evhtp_request.h"
#include "myhooks.h"
#include "evhtp_s.h"
#include "evhtp_callback.h"
#include "evhtp_callbacks.h"
#include "evhtp_hook_type.h"

#include "evhtp_uri.h"
#include "status_code.h"


#ifndef HAVE_STRCASECMP
#include "mystrcasecmp.h"
static int strcasecmp(const char *s1, const char *s2){
	return scm::strcasecmp(s1,s2);
}
#endif












/*
 * PRIVATE FUNCTIONS
 */



/**
 * @brief helper function to determine if http version is HTTP/1.0
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.0, else 0
 */
static int
_evhtp_is_http_10(const char major, const char minor) {
    if (major >= 1 && minor <= 0) {
        return 1;
    }

    return 0;
}

/**
 * @brief helper function to determine if http version is HTTP/1.1
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.1, else 0
 */
static int
_evhtp_is_http_11(const char major, const char minor) {
    if (major >= 1 && minor >= 1) {
        return 1;
    }

    return 0;
}

/**
 * @brief returns the HTTP protocol version
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return EVHTP_PROTO_10 if HTTP/1.0, EVHTP_PROTO_11 if HTTP/1.1, otherwise
 *         EVHTP_PROTO_INVALID
 */
static evhtp_proto
_evhtp_protocol(const char major, const char minor) {
    if (_evhtp_is_http_10(major, minor)) {
        return EVHTP_PROTO_10;
    }

    if (_evhtp_is_http_11(major, minor)) {
        return EVHTP_PROTO_11;
    }

    return EVHTP_PROTO_INVALID;
}

/**
 * @brief runs the user-defined on_path hook for a request
 *
 * @param request the request structure
 * @param path the path structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
_evhtp_path_hook(evhtp_request_t * request, HttpPath * path) {
    HOOK_REQUEST_RUN(request, on_path, path);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_header hook for a request
 *
 * once a full key: value header has been parsed, this will call the hook
 *
 * @param request the request strucutre
 * @param header the header structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
_evhtp_header_hook(evhtp_request_t * request, evhtp_header_t * header) {
    HOOK_REQUEST_RUN(request, on_header, header);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_Headers hook for a request after all headers
 *        have been parsed.
 *
 * @param request the request structure
 * @param headers the headers tailq structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
_evhtp_headers_hook(evhtp_request_t * request, evhtp_headers_t * headers) {
    HOOK_REQUEST_RUN(request, on_headers, headers);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_body hook for requests containing a body.
 *        the data is stored in the request->buffer_in so the user may either
 *        leave it, or drain upon being called.
 *
 * @param request the request strucutre
 * @param buf a evbuffer containing body data
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
_evhtp_body_hook(evhtp_request_t * request, evbuf_t * buf) {
    HOOK_REQUEST_RUN(request, on_read, buf);

    return EVHTP_RES_OK;
}


static evhtp_res
_evhtp_chunk_new_hook(evhtp_request_t * request, uint64_t len) {
    HOOK_REQUEST_RUN(request, on_new_chunk, len);

    return EVHTP_RES_OK;
}

static evhtp_res
_evhtp_chunk_fini_hook(evhtp_request_t * request) {
    HOOK_REQUEST_RUN_NARGS(request, on_chunk_fini);

    return EVHTP_RES_OK;
}

static evhtp_res
_evhtp_chunks_fini_hook(evhtp_request_t * request) {
    HOOK_REQUEST_RUN_NARGS(request, on_chunks_fini);

    return EVHTP_RES_OK;
}

static evhtp_res
_evhtp_headers_start_hook(evhtp_request_t * request) {
    HOOK_REQUEST_RUN_NARGS(request, on_headers_start);

    return EVHTP_RES_OK;
}










/** parser 开始解析。此时需要给connection初始化一个evhtp_request_t */
int MyHtparseHooks::on_msg_begin(IHTParser * p) {

    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());
	
    if (c->request) {
        if (c->request->finished == 1) {
            delete(c->request);
        } else {
            return -1;
        }
    }
	c->request = new EvHttpRequest(c);
    
    return 0;
}

int MyHtparseHooks::args(IHTParser * p, const char * data, size_t len) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());
    HttpUri  * uri = c->request->uri;

    if (!(uri->query = evhtp_parse_query(data, len))) {
        c->request->status = EVHTP_RES_ERROR;
        return -1;
    }

    uri->query_raw = (unsigned char*)calloc(len + 1, 1);
    memcpy(uri->query_raw, data, len);

    return 0;
}

int MyHtparseHooks::on_hdrs_begin(IHTParser * p) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());

    if ((c->request->status = _evhtp_headers_start_hook(c->request)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

int MyHtparseHooks::hdr_key(IHTParser * p, const char * data, size_t len) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());
    char               * key_s;     /* = strndup(data, len); */
    evhtp_header_t     * hdr;

    key_s      = (char*)malloc(len + 1);
    key_s[len] = '\0';
    memcpy(key_s, data, len);

    if ((hdr = evhtp_header_key_add(c->request->headers_in, key_s, 0)) == NULL) {
        c->request->status = EVHTP_RES_FATAL;
        return -1;
    }

    hdr->k_heaped = 1;
    return 0;
}

int MyHtparseHooks::hdr_val(IHTParser * p, const char * data, size_t len) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());
    char               * val_s;     /* = strndup(data, len); */
    evhtp_header_t     * header;

    val_s      = (char*)malloc(len + 1);
    val_s[len] = '\0';
    memcpy(val_s, data, len);

    if ((header = evhtp_header_val_add(c->request->headers_in, val_s, 0)) == NULL) {
        c->request->status = EVHTP_RES_FATAL;
        return -1;
    }

    header->v_heaped = 1;

    if ((c->request->status = _evhtp_header_hook(c->request, header)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

int MyHtparseHooks::path(IHTParser * p, const char * data, size_t len) {
   evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());
    evhtp_callback_t   * callback = NULL;
    evhtp_callback_cb    cb       = NULL;
    
    
    void               * cbarg    = NULL;


	HttpUri  * uri=new  HttpUri();    
	HttpPath * path=new HttpPath(data, len);
    
	{
		tbb::mutex::scoped_lock l(c->htp->lock);


		if ((callback = c->htp->callbacks.find(path->path) )) {
				/* matched a callback using *just* the path (/a/b/c/) */
				cb    = callback->cb;
				cbarg = callback->cbarg;
		} else if ((callback = c->htp->callbacks.find(path->full))) {
				/* matched a callback using both path and file (/a/b/c/d) */
				cb    = callback->cb;
				cbarg = callback->cbarg;				
		} else {
			/* no callbacks found for either case, use defaults */
			cb    = c->htp->defaults.cb;
			cbarg = c->htp->defaults.cbarg;

     	}

	}




    uri->path         = path;
	uri->scheme       = p->get_scheme();


    c->request->uri    = uri;
    c->request->cb     = cb;
    c->request->cbarg  = cbarg;
	c->request->method = p->get_method();

    if ((c->request->status = _evhtp_path_hook(c->request, path)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}     /* _evhtp_request_parser_path */

int MyHtparseHooks::on_hdrs_complete(IHTParser * p) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());
    const char         * expect_val;

    /* XXX proto should be set with htparsers on_hdrs_begin hook */
	c->request->keepalive = p->should_keep_alive();
	c->request->proto     = _evhtp_protocol(p->get_major(), p->get_minor());
    c->request->status    = _evhtp_headers_hook(c->request, c->request->headers_in);

    if (c->request->status != EVHTP_RES_OK) {
        return -1;
    }

#if 0
    if (!evhtp_header_find(c->request->headers_in, "Content-Length")) {
        return 0;
    }
#endif

    if (!(expect_val = evhtp_header_find(c->request->headers_in, "Expect"))) {
        return 0;
    }

    evbuffer_add_printf(bufferevent_get_output(c->bev),
                        "HTTP/%d.%d 100 Continue\r\n\r\n",
						p->get_major(),
						p->get_minor());

    return 0;
}

int MyHtparseHooks::body(IHTParser * p, const char * data, size_t len) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());
    evbuf_t            * buf = evbuffer_new();
    int                  res = 0;

    evbuffer_add(buf, data, len);

    if ((c->request->status = _evhtp_body_hook(c->request, buf)) != EVHTP_RES_OK) {
        res = -1;
    }

    if (evbuffer_get_length(buf)) {
        evbuffer_add_buffer(c->request->buffer_in, buf);
    }

    evbuffer_free(buf);

    return res;
}

int MyHtparseHooks::on_new_chunk(IHTParser * p) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());

    if ((c->request->status = _evhtp_chunk_new_hook(c->request,
		p->get_content_length())) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

int MyHtparseHooks::on_chunk_complete(IHTParser * p) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());

    if ((c->request->status = _evhtp_chunk_fini_hook(c->request)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

int MyHtparseHooks::on_chunks_complete(IHTParser * p) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());

    if ((c->request->status = _evhtp_chunks_fini_hook(c->request)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

int MyHtparseHooks::on_msg_complete(IHTParser * p) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(p->get_userdata());

    /* c->request->finished = 1; */

    if (c->request->cb) {
        (c->request->cb)(c->request, c->request->cbarg);
    }

    return 0;
}




/*
static void
_evhtp_run_in_thread(evthr_t * thr, void * arg, void * shared) {
    evhtp            * htp        = (evhtp*)shared;
    evhtp_connection_t * connection = (evhtp_connection_t*)arg;

    connection->evbase = evthr_get_base(thr);
    connection->thread = thr;

    evthr_inc_backlog(connection->thread);

    if (_evhtp_connection_accept(connection->evbase, connection) < 0) {
        return evhtp_connection_free(connection);
    }

    if (_evhtp_run_post_accept(htp, connection) < 0) {
        return evhtp_connection_free(connection);
    }
}*/



/*
 * PUBLIC FUNCTIONS
 */

HttpMethod
evhtp_request_get_method(evhtp_request_t * r) {
	return r->conn->parser->get_method();
}


/**
 * @brief resumes a connection (enables reading) and activates resume event.
 *
 * @param c
 */
void
evhtp_connection_resume(evhtp_connection_t * c) {
    if (!(bufferevent_get_enabled(c->bev) & EV_READ)) {
        bufferevent_enable(c->bev, EV_READ);
        event_active(c->resume_ev, EV_WRITE, 1);
    }
}

/**
 * @brief Wrapper around evhtp_connection_pause
 *
 * @see evhtp_connection_pause
 *
 * @param request
 */
void
evhtp_request_pause(evhtp_request_t * request) {
    return evhtp_connection_pause(request->conn);
}

/**
 * @brief Wrapper around evhtp_connection_resume
 *
 * @see evhtp_connection_resume
 *
 * @param request
 */
void
evhtp_request_resume(evhtp_request_t * request) {
    return evhtp_connection_resume(request->conn);
}

evhtp_header_t *
evhtp_header_key_add(evhtp_headers_t * headers, const char * key, char kalloc) {
    evhtp_header_t * header;

    if (!(header = evhtp_header_new(key, NULL, kalloc, 0))) {
        return NULL;
    }

    evhtp_headers_add_header(headers, header);

    return header;
}

evhtp_header_t *
evhtp_header_val_add(evhtp_headers_t * headers, const char * val, char valloc) {
    evhtp_header_t * header = TAILQ_LAST(headers, evhtp_headers_s);

    if (header == NULL) {
        return NULL;
    }

    header->vlen = strlen(val);

    if (valloc == 1) {
        header->val = (char*)malloc(header->vlen + 1);
        header->val[header->vlen] = '\0';
        memcpy(header->val, val, header->vlen);
    } else {
        header->val = (char *)val;
    }

    header->v_heaped = valloc;

    return header;
}

evhtp_kvs_t *
evhtp_kvs_new(void) {
    evhtp_kvs_t * kvs = (evhtp_kvs_t*)malloc(sizeof(evhtp_kvs_t));

    TAILQ_INIT(kvs);
    return kvs;
}

evhtp_kv_t *
evhtp_kv_new(const char * key, const char * val, char kalloc, char valloc) {
    evhtp_kv_t * kv;

    if (!(kv = (evhtp_kv_t*)malloc(sizeof(evhtp_kv_t)))) {
        return NULL;
    }

    kv->k_heaped = kalloc;
    kv->v_heaped = valloc;
    kv->klen     = 0;
    kv->vlen     = 0;

    if (key != NULL) {
        kv->klen = strlen(key);

        if (kalloc == 1) {
            char * s = (char*)malloc(kv->klen + 1);

            s[kv->klen] = '\0';
            memcpy(s, key, kv->klen);
            kv->key     = s;
        } else {
            kv->key = (char *)key;
        }
    }

    if (val != NULL) {
        kv->vlen = strlen(val);

        if (valloc == 1) {
            char * s =(char*) malloc(kv->vlen + 1);

            s[kv->vlen] = '\0';
            memcpy(s, val, kv->vlen);
            kv->val     = s;
        } else {
            kv->val = (char *)val;
        }
    }

    return kv;
}     /* evhtp_kv_new */

void
evhtp_kv_free(evhtp_kv_t * kv) {
    if (kv == NULL) {
        return;
    }

    if (kv->k_heaped && kv->key) {
        free(kv->key);
    }

    if (kv->v_heaped && kv->val) {
        free(kv->val);
    }

    free(kv);
}

void
evhtp_kv_rm_and_free(evhtp_kvs_t * kvs, evhtp_kv_t * kv) {
    if (kvs == NULL || kv == NULL) {
        return;
    }

    TAILQ_REMOVE(kvs, kv, next);

    evhtp_kv_free(kv);
}

void
evhtp_kvs_free(evhtp_kvs_t * kvs) {
    evhtp_kv_t * kv;
    evhtp_kv_t * save;

    if (kvs == NULL) {
        return;
    }

    for (kv = TAILQ_FIRST(kvs); kv != NULL; kv = save) {
        save = TAILQ_NEXT(kv, next);

        TAILQ_REMOVE(kvs, kv, next);

        evhtp_kv_free(kv);
    }

    free(kvs);
}

int
evhtp_kvs_for_each(evhtp_kvs_t * kvs, evhtp_kvs_iterator cb, void * arg) {
    evhtp_kv_t * kv;

    TAILQ_FOREACH(kv, kvs, next) {
        int res;

        if ((res = cb(kv, arg))) {
            return res;
        }
    }

    return 0;
}

const char *
evhtp_kv_find(evhtp_kvs_t * kvs, const char * key) {
    evhtp_kv_t * kv;

    if (kvs == NULL || key == NULL) {
        return NULL;
    }

    TAILQ_FOREACH(kv, kvs, next) {
        if (strcasecmp(kv->key, key) == 0) {
            return kv->val;
        }
    }

    return NULL;
}

evhtp_kv_t *
evhtp_kvs_find_kv(evhtp_kvs_t * kvs, const char * key) {
    evhtp_kv_t * kv;

    if (kvs == NULL || key == NULL) {
        return NULL;
    }

    TAILQ_FOREACH(kv, kvs, next) {
        if (strcasecmp(kv->key, key) == 0) {
            return kv;
        }
    }

    return NULL;
}

void
evhtp_kvs_add_kv(evhtp_kvs_t * kvs, evhtp_kv_t * kv) {
    if (kvs == NULL || kv == NULL) {
        return;
    }

    TAILQ_INSERT_TAIL(kvs, kv, next);
}

typedef enum {
    s_query_start = 0,
    s_query_question_mark,
    s_query_separator,
    s_query_key,
    s_query_val,
    s_query_key_hex_1,
    s_query_key_hex_2,
    s_query_val_hex_1,
    s_query_val_hex_2,
    s_query_done
} query_parser_state;

static inline int
evhtp_is_hex_query_char(unsigned char ch) {
    switch (ch) {
        case 'a': case 'A':
        case 'b': case 'B':
        case 'c': case 'C':
        case 'd': case 'D':
        case 'e': case 'E':
        case 'f': case 'F':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return 1;
        default:
            return 0;
    } /* switch */
}

enum unscape_state {
    unscape_state_start = 0,
    unscape_state_hex1,
    unscape_state_hex2
};

int
evhtp_unescape_string(unsigned char ** out, unsigned char * str, size_t str_len) {
    unsigned char    * optr;
    unsigned char    * sptr;
    unsigned char      d;
    unsigned char      ch;
    unsigned char      c;
    size_t             i;
    enum unscape_state state;

    if (out == NULL || *out == NULL) {
        return -1;
    }

    state = unscape_state_start;
    optr  = *out;
    sptr  = str;
    d     = 0;

    for (i = 0; i < str_len; i++) {
        ch = *sptr++;

        switch (state) {
            case unscape_state_start:
                if (ch == '%') {
                    state = unscape_state_hex1;
                    break;
                }

                *optr++ = ch;

                break;
            case unscape_state_hex1:
                if (ch >= '0' && ch <= '9') {
                    d     = (unsigned char)(ch - '0');
                    state = unscape_state_hex2;
                    break;
                }

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'f') {
                    d     = (unsigned char)(c - 'a' + 10);
                    state = unscape_state_hex2;
                    break;
                }

                state   = unscape_state_start;
                *optr++ = ch;
                break;
            case unscape_state_hex2:
                state   = unscape_state_start;

                if (ch >= '0' && ch <= '9') {
                    ch      = (unsigned char)((d << 4) + ch - '0');

                    *optr++ = ch;
                    break;
                }

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'f') {
                    ch      = (unsigned char)((d << 4) + c - 'a' + 10);
                    *optr++ = ch;
                    break;
                }

                break;
        } /* switch */
    }

    return 0;
}         /* evhtp_unescape_string */

evhtp_query_t *
evhtp_parse_query(const char * query, size_t len) {
    evhtp_query_t    * query_args;
    query_parser_state state = s_query_start;
    char               key_buf[1024];
    char               val_buf[1024];
    int                key_idx;
    int                val_idx;
    int                res;
    unsigned char      ch;
    size_t             i;

    query_args = evhtp_query_new();

    key_idx    = 0;
    val_idx    = 0;

    for (i = 0; i < len; i++) {
        res = 0;
        ch  = query[i];

        if (key_idx >= sizeof(key_buf) || val_idx >= sizeof(val_buf)) {
            res = -1;
            goto error;
        }

        switch (state) {
            case s_query_start:
                memset(key_buf, 0, sizeof(key_buf));
                memset(val_buf, 0, sizeof(val_buf));

                key_idx = 0;
                val_idx = 0;

                switch (ch) {
                    case '?':
                        state = s_query_key;
                        break;
                    case '/':
                        state = s_query_question_mark;
                        break;
                    default:
                        state = s_query_key;
                        goto query_key;
                }

                break;
            case s_query_question_mark:
                switch (ch) {
                    case '?':
                        state = s_query_key;
                        break;
                    case '/':
                        state = s_query_question_mark;
                        break;
                    default:
                        res   = -1;
                        goto error;
                }
                break;
query_key:
            case s_query_key:
                switch (ch) {
                    case '=':
                        state = s_query_val;
                        break;
                    case '%':
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx] = '\0';
                        state = s_query_key_hex_1;
                        break;
                    default:
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx]   = '\0';
                        break;
                }
                break;
            case s_query_key_hex_1:
                if (!evhtp_is_hex_query_char(ch)) {
                    res = -1;
                    goto error;
                }

                key_buf[key_idx++] = ch;
                key_buf[key_idx]   = '\0';

                state = s_query_key_hex_2;
                break;
            case s_query_key_hex_2:
                if (!evhtp_is_hex_query_char(ch)) {
                    res = -1;
                    goto error;
                }

                key_buf[key_idx++] = ch;
                key_buf[key_idx]   = '\0';

                state = s_query_key;
                break;
            case s_query_val:
                switch (ch) {
                    case ';':
                    case '&':
                        evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1));

                        memset(key_buf, 0, sizeof(key_buf));
                        memset(val_buf, 0, sizeof(val_buf));

                        key_idx            = 0;
                        val_idx            = 0;

                        state              = s_query_key;

                        break;
                    case '%':
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        state              = s_query_val_hex_1;
                        break;
                    default:
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        break;
                }     /* switch */
                break;
            case s_query_val_hex_1:
                if (!evhtp_is_hex_query_char(ch)) {
                    res = -1;
                    goto error;
                }

                val_buf[val_idx++] = ch;
                val_buf[val_idx]   = '\0';

                state = s_query_val_hex_2;
                break;
            case s_query_val_hex_2:
                if (!evhtp_is_hex_query_char(ch)) {
                    res = -1;
                    goto error;
                }

                val_buf[val_idx++] = ch;
                val_buf[val_idx]   = '\0';

                state = s_query_val;
                break;
            default:
                /* bad state */
                res   = -1;
                goto error;
        }       /* switch */
    }

    if (key_idx && val_idx) {
        evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1));
    }

    return query_args;
error:
    return NULL;
}     /* evhtp_parse_query */



int
evhtp_set_hook(evhtp_hooks_t ** hooks, evhtp_hook_type type, void * cb, void * arg) {
    if (*hooks == NULL) {
        if (!(*hooks =(evhtp_hooks_t*) calloc(sizeof(evhtp_hooks_t), 1))) {
            return -1;
        }
    }

    switch (type) {
        case evhtp_hook_on_headers_start:
            (*hooks)->on_headers_start       = (evhtp_hook_headers_start_cb)cb;
            (*hooks)->on_headers_start_arg   = arg;
            break;
        case evhtp_hook_on_header:
            (*hooks)->on_header = (evhtp_hook_header_cb)cb;
            (*hooks)->on_header_arg          = arg;
            break;
        case evhtp_hook_on_headers:
            (*hooks)->on_headers             = (evhtp_hook_headers_cb)cb;
            (*hooks)->on_headers_arg         = arg;
            break;
        case evhtp_hook_on_path:
            (*hooks)->on_path = (evhtp_hook_path_cb)cb;
            (*hooks)->on_path_arg            = arg;
            break;
        case evhtp_hook_on_read:
            (*hooks)->on_read = (evhtp_hook_read_cb)cb;
            (*hooks)->on_read_arg            = arg;
            break;
        case evhtp_hook_on_request_fini:
            (*hooks)->on_request_fini        = (evhtp_hook_request_fini_cb)cb;
            (*hooks)->on_request_fini_arg    = arg;
            break;
        case evhtp_hook_on_connection_fini:
            (*hooks)->on_connection_fini     = (evhtp_hook_connection_fini_cb)cb;
            (*hooks)->on_connection_fini_arg = arg;
            break;
        case evhtp_hook_on_error:
            (*hooks)->on_error = (evhtp_hook_err_cb)cb;
            (*hooks)->on_error_arg           = arg;
            break;
        case evhtp_hook_on_new_chunk:
            (*hooks)->on_new_chunk           = (evhtp_hook_chunk_new_cb)cb;
            (*hooks)->on_new_chunk_arg       = arg;
            break;
        case evhtp_hook_on_chunk_complete:
            (*hooks)->on_chunk_fini          = (evhtp_hook_chunk_fini_cb)cb;
            (*hooks)->on_chunk_fini_arg      = arg;
            break;
        case evhtp_hook_on_chunks_complete:
            (*hooks)->on_chunks_fini         = (evhtp_hook_chunks_fini_cb)cb;
            (*hooks)->on_chunks_fini_arg     = arg;
            break;
        default:
            return -1;
    }     /* switch */

    return 0;
}         /* evhtp_set_hook */


/*
static void
_evhtp_thread_init(evthr_t * thr, void * arg) {
    evhtp_t * htp = (evhtp_t *)arg;

    if (htp->thread_init_cb) {
        htp->thread_init_cb(htp, thr, htp->thread_init_cbarg);
    }
}*/





void
evhtp_set_pre_accept_cb(evhtp * htp, evhtp_pre_accept_cb cb, void * arg) {
    htp->defaults.pre_accept       = cb;
    htp->defaults.pre_accept_cbarg = arg;
}

void
evhtp_set_post_accept_cb(evhtp * htp, evhtp_post_accept_cb cb, void * arg) {
    htp->defaults.post_accept       = cb;
    htp->defaults.post_accept_cbarg = arg;
}





void
evhtp_connection_set_bev(evhtp_connection_t * conn, evbev_t * bev) {
    conn->bev = bev;
}

void
evhtp_request_set_bev(evhtp_request_t * request, evbev_t * bev) {
    return evhtp_connection_set_bev(request->conn, bev);
}


void
evhtp_set_timeouts(evhtp * htp, struct timeval * r_timeo, struct timeval * w_timeo) {
    if (r_timeo != NULL) {
        htp->recv_timeo =(timeval*) malloc(sizeof(struct timeval));
        memcpy(htp->recv_timeo, r_timeo, sizeof(struct timeval));
    }

    if (w_timeo != NULL) {
        htp->send_timeo = (timeval*)malloc(sizeof(struct timeval));
        memcpy(htp->send_timeo, w_timeo, sizeof(struct timeval));
    }
}

