#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <algorithm>
#include <glog/logging.h>
#include "htparse_imp.h"
#include "parser_flags.h"
#include <stdint.h>

#ifndef HAVE_STRCASECMP
#include "mystrcasecmp.h"
static int strcasecmp(const char *s1, const char *s2){
	return scm::strcasecmp(s1,s2);
}
#endif


#if '\n' != '\x0a' || 'A' != 65
#error "You have somehow found a non-ASCII host. We can't build here."
#endif


#define LF               (unsigned char)10
#define CR               (unsigned char)13
#define CRLF             "\x0d\x0a"



htparser::htparser(): error(htparse_error_none),state(s_start),flags(0),heval(eval_hdr_val_none),type(htp_type_none),scheme(htp_scheme_none),method(htp_method_UNKNOWN),major_(0),minor_(0),content_len(0),bytes_read(0),status(0),status_count(0),buf_idx(0),scheme_offset(0),host_offset(0),port_offset(0),path_offset(0),args_offset(0),userdata(NULL){
 memset(buf,0,sizeof(buf));
}
uint64_t htparser::get_bytes_read(){
	return this->bytes_read;
}
static uint32_t     usual[] = {
    0xffffdbfe,
    0x7fff37d6,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff
};

static int8_t       unhex[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static const char * errstr_map[] = {
    "htparse_error_none",
    "htparse_error_too_big",
    "htparse_error_invalid_method",
    "htparse_error_invalid_requestline",
    "htparse_error_invalid_schema",
    "htparse_error_invalid_protocol",
    "htparse_error_invalid_version",
    "htparse_error_invalid_header",
    "htparse_error_invalid_chunk_size",
    "htparse_error_invalid_chunk",
    "htparse_error_invalid_state",
    "htparse_error_user",
    "htparse_error_unknown"
};

static const char * method_strmap[] = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "MKCOL",
    "COPY",
    "MOVE",
    "OPTIONS",
    "PROPFIND",
    "PROPATCH",
    "LOCK",
    "UNLOCK",
    "TRACE"
};

#define _MIN_READ(a, b) ((a) < (b) ? (a) : (b))

#define _str3_cmp(m, c0, c1, c2, c3) \
    *(uint32_t *)m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define _str3Ocmp(m, c0, c1, c2, c3) \
    *(uint32_t *)m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define _str4cmp(m, c0, c1, c2, c3) \
    *(uint32_t *)m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define _str5cmp(m, c0, c1, c2, c3, c4)                          \
    *(uint32_t *)m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) \
    && m[4] == c4

#define _str6cmp(m, c0, c1, c2, c3, c4, c5)                      \
    *(uint32_t *)m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) \
    && (((uint32_t *)m)[1] & 0xffff) == ((c5 << 8) | c4)

#define _str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)             \
    *(uint32_t *)m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) \
    && ((uint32_t *)m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define _str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)              \
    *(uint32_t *)m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) \
    && ((uint32_t *)m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define _str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                 \
    *(uint32_t *)m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)        \
    && ((uint32_t *)m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4) \
    && m[8] == c8

#define __HTPARSE_GENHOOK(__n)                                                    \
    static inline int hook_ ## __n ## _run(htparser * p, htparse_hooks * hooks) { return hooks?(hooks->__n(p)):0; }

#define __HTPARSE_GENDHOOK(__n)                                                                             \
    static inline int hook_ ## __n ## _run(htparser * p, htparse_hooks * hooks, const char * s, size_t l) { \
	return hooks?(hooks->__n(p,s,l)):0; }

__HTPARSE_GENHOOK(on_msg_begin);
__HTPARSE_GENHOOK(on_hdrs_begin);
__HTPARSE_GENHOOK(on_hdrs_complete);
__HTPARSE_GENHOOK(on_new_chunk);
__HTPARSE_GENHOOK(on_chunk_complete);
__HTPARSE_GENHOOK(on_chunks_complete);
__HTPARSE_GENHOOK(on_msg_complete);

__HTPARSE_GENDHOOK(method);
__HTPARSE_GENDHOOK(scheme);
__HTPARSE_GENDHOOK(host);
__HTPARSE_GENDHOOK(port);
__HTPARSE_GENDHOOK(path);
__HTPARSE_GENDHOOK(args);
__HTPARSE_GENDHOOK(uri);
__HTPARSE_GENDHOOK(hdr_key);
__HTPARSE_GENDHOOK(hdr_val);
__HTPARSE_GENDHOOK(body);


static inline uint64_t
str_to_uint64(char * str, size_t n, int * err) {
    uint64_t value;

    if (n > 20) {
        /* 18446744073709551615 is 20 bytes */
        *err = 1;
        return 0;
    }

    for (value = 0; n--; str++) {
        uint64_t check;

        if (*str < '0' || *str > '9') {
            *err = 1;
            return 0;
        }

        check = value * 10 + (*str - '0');

        if ((value && check <= value) || check > 0xffffffffffffffffUL) {
            *err = 1;
            return 0;
        }

        value = check;
    }

    return value;
}
/*
static  int64_t _str_to_ssize_t(char * str, size_t n) {
    int64_t value;

    if (n == 0) {
        return -1;
    }

    for (value = 0; n--; str++) {
        if (*str < '0' || *str > '9') {
            return -1;
        }

        value = value * 10 + (*str - '0');


        if (value > INTMAX_MAX) {
            return -1;
        }
    }

    return value;
}*/

htpparse_error
htparser_get_error(htparser * p) {
	return p->get_error();
}

const char *
htparser_get_strerror(htparser * p) {
	return p->get_strerror();    
}

unsigned int
htparser_get_status(htparser * p) {
	return p->get_status();
}

int
htparser_should_keep_alive(htparser * p) {
	return p->should_keep_alive();
}

htp_scheme
htparser_get_scheme(htparser * p) {
	return p->get_scheme();
}

htp_method
htparser_get_method(htparser * p) {
	return p->get_method();
}

const char *
htparser_get_methodstr(htparser * p) {
	return p->get_methodstr();
}

void
htparser_set_major(htparser * p, unsigned char major) {
	p->set_major(major);    
}

void
htparser_set_minor(htparser * p, unsigned char minor) {
	p->set_minor(minor);
}

unsigned char
htparser_get_major(htparser * p) {
	return p->get_major();
}

unsigned char
htparser_get_minor(htparser * p) {
	return p->get_minor();
}

void *
htparser_get_userdata(htparser * p) {
	return p->get_userdata();
}

void
htparser_set_userdata(htparser * p, void * ud) {
	p->set_userdata(ud);    
}

uint64_t
htparser_get_content_length(htparser * p) {
	return p->get_content_length();    
}

uint64_t
htparser_get_bytes_read(htparser * p) {
    return p->get_bytes_read();
}

void
htparser_init(htparser * p, htp_type type) {
	return p->init(type);
}

IHTParser *
htparser_new(void) {
    return new htparser();
}

size_t
htparser_run(htparser * p, htparse_hooks * hooks, const char * data, size_t len) {
	return p->run(hooks,data,len);
}

int            htparser::should_keep_alive(){
	if (this->major_ > 0 && this->minor_ > 0) {
		if (this->flags & parser_flag_connection_close) {
			return 0;
		} else {
			return 1;
		}
	} else {
		if (this->flags & parser_flag_connection_keep_alive) {
			return 1;
		} else {
			return 0;
		}
	}

	return 0;
}
htp_scheme     htparser::get_scheme(){
	return this->scheme;
}
htp_method     htparser::get_method(){
	return this->method;
}
const char   * htparser::get_methodstr(){
	if (this->method >= htp_method_UNKNOWN) {
        return NULL;
    }

    return method_strmap[this->method];
}
void           htparser::set_major( unsigned char v){
	this->major_=v;
}
void           htparser::set_minor( unsigned char v){
	this->minor_=v;
}
unsigned char  htparser::get_major(){
	return this->major_;
}
unsigned char  htparser::get_minor(){
	return this->minor_;
}

unsigned int   htparser::get_status(){
	return this->status;
}

uint64_t       htparser::get_content_length(){
	return this->content_len;
}
htpparse_error htparser::get_error(){
	return this->error;
}
const char   * htparser::get_strerror(){
	return errstr_map[this->error];
}
void* htparser::get_userdata(){
	return this->userdata;

}
void   htparser::set_userdata( void * ud){
	this->userdata = ud;
}

size_t  htparser::run( htparse_hooks * hooks, const char * data, size_t len){
	unsigned char ch;
    char          c;
    size_t        i;

	//DLOG(INFO)<<"enter\n";
	//DLOG(INFO)<<"p="<<p<<"\n";
    
    this->error      = htparse_error_none;
    this->bytes_read = 0;

    for (i = 0; i < len; i++) {
        int res;
        int err;

        ch = data[i];
		
        if (this->buf_idx >= sizeof(this->buf)) {
			//太长了。
            this->error = htparse_error_too_big;
            return i + 1;
        }

        this->bytes_read += 1;

        switch (this->state) {
            case s_start:
				//DLOG(INFO)<<"["<<p<<"]"<<"s_start\n";

                this->flags = parser_flag_unknown;

                if (ch == CR || ch == LF) {
                    break;
                }

                if ((ch < 'A' || ch > 'Z') && ch != '_') {
                    this->error = htparse_error_inval_reqline;
                    return i + 1;
                }

                res = hook_on_msg_begin_run(this, hooks);

                this->buf[this->buf_idx++] = ch;
                this->buf[this->buf_idx]   = '\0';

                if (this->type == htp_type_request) {
                    this->state = s_method;
                } else if (this->type == htp_type_response && ch == 'H') {
                    this->state = s_http_H;
                } else {
                    this->error = htparse_error_inval_reqline;
                    return i + 1;
                }

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_method:
				//DLOG(INFO)<<"["<<p<<"]"<<"s_method\n";
                if (ch == ' ') {
                    char * m = this->buf;

                    switch (this->buf_idx) {
                        case 3:
                            if (_str3_cmp(m, 'G', 'E', 'T', '\0')) {
                                this->method = htp_method_GET;
                                break;
                            }

                            if (_str3_cmp(m, 'P', 'U', 'T', '\0')) {
                                this->method = htp_method_PUT;
                                break;
                            }

                            break;
                        case 4:
                            if (m[1] == 'O') {
                                if (_str3Ocmp(m, 'P', 'O', 'S', 'T')) {
                                    this->method = htp_method_POST;
                                    break;
                                }

                                if (_str3Ocmp(m, 'C', 'O', 'P', 'Y')) {
                                    this->method = htp_method_COPY;
                                    break;
                                }

                                if (_str3Ocmp(m, 'M', 'O', 'V', 'E')) {
                                    this->method = htp_method_MOVE;
                                    break;
                                }

                                if (_str3Ocmp(m, 'L', 'O', 'C', 'K')) {
                                    this->method = htp_method_LOCK;
                                    break;
                                }
                            } else {
                                if (_str4cmp(m, 'H', 'E', 'A', 'D')) {
                                    this->method = htp_method_HEAD;
                                    break;
                                }
                            }
                            break;
                        case 5:
                            if (_str5cmp(m, 'M', 'K', 'C', 'O', 'L')) {
                                this->method = htp_method_MKCOL;
                                break;
                            }

                            if (_str5cmp(m, 'T', 'R', 'A', 'C', 'E')) {
                                this->method = htp_method_TRACE;
                                break;
                            }
                            break;
                        case 6:
                            if (_str6cmp(m, 'D', 'E', 'L', 'E', 'T', 'E')) {
                                this->method = htp_method_DELETE;
                                break;
                            }

                            if (_str6cmp(m, 'U', 'N', 'L', 'O', 'C', 'K')) {
                                this->method = htp_method_UNLOCK;
                                break;
                            }
                            break;
                        case 7:
                            if (_str7_cmp(m, 'O', 'P', 'T', 'I', 'O', 'N', 'S', '\0')) {
                                this->method = htp_method_OPTIONS;
                            }

                            break;
                        case 8:
                            if (_str8cmp(m, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D')) {
                                this->method = htp_method_PROPFIND;
                            }

                            break;

                        case 9:
                            if (_str9cmp(m, 'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C', 'H')) {
                                this->method = htp_method_PROPPATCH;
                            }
                            break;
                    } /* switch */

                    res        = hook_method_run(this, hooks, this->buf, this->buf_idx);
                    this->buf_idx = 0;
                    this->state   = s_spaces_before_uri;

                    if (res) {
                        this->error = htparse_error_user;
                        return i + 1;
                    }

                    break;
                }

                if ((ch < 'A' || ch > 'Z') && ch != '_') {
                    this->error = htparse_error_inval_method;
                    return i + 1;
                }

                this->buf[this->buf_idx++] = ch;
                this->buf[this->buf_idx]   = '\0';

                break;
            case s_spaces_before_uri:
				//DLOG(INFO)<<"["<<p<<"]"<<"s_spaces_before_uri\n";
                switch (ch) {
                    case ' ':
                        break;
                    case '/':
                        this->path_offset       = &this->buf[this->buf_idx];

                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        this->state = s_after_slash_in_uri;
                        break;
                    default:
                        c        = (unsigned char)(ch | 0x20);

                        if (c >= 'a' && c <= 'z') {
                            this->scheme_offset     = &this->buf[this->buf_idx];
                            this->buf[this->buf_idx++] = ch;
                            this->buf[this->buf_idx]   = '\0';
                            this->state = s_schema;
                            break;
                        }

                        this->error = htparse_error_inval_reqline;
                        return i + 1;
                } /* switch */

                break;
            case s_schema:
				//DLOG(INFO)<<"["<<p<<"]"<<"s_schema\n";
                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'z') {
                    this->buf[this->buf_idx++] = ch;
                    this->buf[this->buf_idx]   = '\0';
                    break;
                }

                switch (ch) {
                    case ':':
                        this->scheme = htp_scheme_unknown;

                        switch (this->buf_idx) {
                            case 3:
                                if (_str3_cmp(this->scheme_offset, 'f', 't', 'p', ' ')) {
                                    this->scheme = htp_scheme_ftp;
                                    break;
                                }

                                if (_str3_cmp(this->scheme_offset, 'n', 'f', 's', ' ')) {
                                    this->scheme = htp_scheme_nfs;
                                    break;
                                }

                                break;
                            case 4:
                                if (_str4cmp(this->scheme_offset, 'h', 't', 't', 'p')) {
                                    this->scheme = htp_scheme_http;
                                    break;
                                }
                                break;
                            case 5:
                                if (_str5cmp(this->scheme_offset, 'h', 't', 't', 'p', 's')) {
                                    this->scheme = htp_scheme_https;
                                    break;
                                }
                                break;
                        } /* switch */

                        res                  = hook_scheme_run(this, hooks, this->scheme_offset, this->buf_idx);

#if 0
                        this->buf_idx           = 0;
                        this->buf[0]            = '\0';
#endif
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';

                        this->state             = s_schema_slash;

                        if (res) {
                            this->error = htparse_error_user;
                            return i + 1;
                        }

                        break;
                    default:
                        this->error = htparse_error_inval_schema;
                        return i + 1;
                } /* switch */

                break;
            case s_schema_slash:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_schema_slash\n";
                switch (ch) {
                    case '/':
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';

                        this->state = s_schema_slash_slash;
                        break;
                    default:
                        this->error = htparse_error_inval_schema;
                        return i + 1;
                }
                break;
            case s_schema_slash_slash:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_schema_slash_slash\n";
                switch (ch) {
                    case '/':
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        this->host_offset       = &this->buf[this->buf_idx];

                        this->state = s_host;
                        break;
                    default:
                        this->error = htparse_error_inval_schema;
                        return i + 1;
                }
                break;
            case s_host:
                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'z') {
                    this->buf[this->buf_idx++] = ch;
                    this->buf[this->buf_idx]   = '\0';
                    break;
                }

                if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                    this->buf[this->buf_idx++] = ch;
                    this->buf[this->buf_idx]   = '\0';
                    break;
                }

                res = hook_host_run(this, hooks, this->host_offset, (&this->buf[this->buf_idx] - this->host_offset));

                switch (ch) {
                    case ':':
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';

                        this->port_offset       = &this->buf[this->buf_idx];
                        this->state = s_port;
                        break;
                    case '/':
                        this->path_offset       = &this->buf[this->buf_idx];

                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';

                        this->state = s_after_slash_in_uri;
                        break;
                    case ' ':
                        /* this->buf should contain the whole uri */
                        this->state = s_http_09;
                        break;
                    default:
                        this->error = htparse_error_inval_schema;
                        return i + 1;
                } /* switch */

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_port:
                res = 0;

                if (ch >= '0' && ch <= '9') {
                    this->buf[this->buf_idx++] = ch;
                    this->buf[this->buf_idx]   = '\0';
                    break;
                }

                res = hook_port_run(this, hooks, this->buf, this->buf_idx);

                switch (ch) {
                    case '/':
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        this->path_offset       = &this->buf[this->buf_idx - 1];

                        this->state   = s_after_slash_in_uri;
                        break;
                    case ' ':
                        this->state   = s_http_09;
                        this->buf_idx = 0;
                        break;
                    default:
                        this->error   = htparse_error_inval_reqline;
                        return i + 1;
                }

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_after_slash_in_uri:
				//DLOG(INFO)<<"["<<p<<"]"<<"s_after_slash_in_uri\n";
                res = 0;

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    this->buf[this->buf_idx++] = ch;
                    this->buf[this->buf_idx]   = '\0';
                    this->state = s_check_uri;
                    break;
                }

                switch (ch) {
                    case ' ':
                    {
                        int r1 = hook_path_run(this, hooks, this->path_offset, this->buf_idx);
                        int r2 = hook_uri_run(this, hooks, this->buf, this->buf_idx);

                        this->state   = s_http_09;
                        this->buf_idx = 0;

                        if (r1 || r2) {
                            res = 1;
                        }
                    }

                    break;
                    case CR:
                        this->minor_ = 9;
                        this->state = s_almost_done;
                        break;
                    case LF:
                        this->minor_ = 9;
                        this->state = s_hdrline_start;
                        break;
                    case '.':
                    case '%':
                    case '/':
                    case '#':
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        this->state             = s_uri;
                        break;
                    case '?':
                        res                  = hook_path_run(this, hooks, this->buf, this->buf_idx);

                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        this->args_offset       = &this->buf[this->buf_idx];
                        this->state             = s_uri;

                        break;
                    default:
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';

                        this->state             = s_check_uri;
                        break;
                } /* switch */

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_check_uri:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_check_uri\n";
                res = 0;

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    this->buf[this->buf_idx++] = ch;
                    this->buf[this->buf_idx]   = '\0';
                    break;
                }

                switch (ch) {
                    case ' ':
                    {
                        int r1 = 0;
                        int r2 = 0;

                        if (this->args_offset) {
                            r1 = hook_args_run(this, hooks, this->args_offset, this->buf_idx);
                        } else {
                            r1 = hook_path_run(this, hooks, this->buf, this->buf_idx);
                        }

                        r2         = hook_uri_run(this, hooks, this->buf, this->buf_idx);
                        this->buf_idx = 0;
                        this->state   = s_http_09;

                        if (r1 || r2) {
                            res = 1;
                        }
                    }
                    break;
                    case '/':
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        this->state = s_after_slash_in_uri;
                        break;
                    case CR:
                        this->minor_ = 9;
                        this->buf_idx           = 0;
                        this->state = s_almost_done;
                        break;
                    case LF:
                        this->minor_ = 9;
                        this->buf_idx           = 0;

                        this->state = s_hdrline_start;
                        break;
                    default:
                        if (ch == '?') {
                            res = hook_path_run(this, hooks, this->path_offset, (&this->buf[this->buf_idx] - this->path_offset));
                            this->args_offset = &this->buf[this->buf_idx];
                        }

                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';

                        this->state = s_uri;

                        break;
                } /* switch */

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_uri:
				//DLOG(INFO)<<"["<<p<<"]"<<"s_uri\n";
                res = 0;

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    this->buf[this->buf_idx++] = ch;
                    this->buf[this->buf_idx]   = '\0';
                    break;
                }

                switch (ch) {
                    case ' ':
                    {
                        int r1 = 0;
                        int r2 = 0;

                        if (this->args_offset) {
                            r1 = hook_args_run(this, hooks, this->args_offset,
                                               (&this->buf[this->buf_idx] - this->args_offset));
                        } else {
                            r1 = hook_path_run(this, hooks, this->path_offset,
                                               (&this->buf[this->buf_idx] - this->path_offset));
                        }

                        this->buf_idx = 0;
                        this->state   = s_http_09;

                        if (r1 || r2) {
                            res = 1;
                        }
                    }
                    break;
                    case CR:
                        this->minor_             = 9;
                        this->buf_idx           = 0;
                        this->state             = s_almost_done;
                        break;
                    case LF:
                        this->minor_             = 9;
                        this->buf_idx           = 0;
                        this->state             = s_hdrline_start;
                        break;
                    default:
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        break;
                } /* switch */

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_http_09:
				//DLOG(INFO)<<"["<<p<<"]"<<"s_http_09\n";
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        this->minor_   = 9;
                        this->buf_idx = 0;
                        this->state   = s_almost_done;
                        break;
                    case LF:
                        this->minor_   = 9;
                        this->buf_idx = 0;
                        this->state   = s_hdrline_start;
                        break;
                    case 'H':
                        this->buf_idx = 0;
                        this->state   = s_http_H;
                        break;
                    default:
                        this->error   = htparse_error_inval_proto;
                        return i + 1;
                } /* switch */

                break;
            case s_http_H:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_http_H\n";
                switch (ch) {
                    case 'T':
                        this->state = s_http_HT;
                        break;
                    default:
                        this->error = htparse_error_inval_proto;
                        return i + 1;
                }
                break;
            case s_http_HT:
                switch (ch) {
                    case 'T':
                        this->state = s_http_HTT;
                        break;
                    default:
                        this->error = htparse_error_inval_proto;
                        return i + 1;
                }
                break;
            case s_http_HTT:
                switch (ch) {
                    case 'P':
                        this->state = s_http_HTTP;
                        break;
                    default:
                        this->error = htparse_error_inval_proto;
                        return i + 1;
                }
                break;
            case s_http_HTTP:
                switch (ch) {
                    case '/':
                        this->state = s_first_major_digit;
                        break;
                    default:
                        this->error = htparse_error_inval_proto;
                        return i + 1;
                }
                break;
            case s_first_major_digit:
                if (ch < '1' || ch > '9') {
                    this->error = htparse_error_inval_ver;
                    return i + 1;
                }

                this->major_ = ch - '0';
                this->state = s_major_digit;
                break;
            case s_major_digit:
                if (ch == '.') {
                    this->state = s_first_minor_digit;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    this->error = htparse_error_inval_ver;
                    return i + 1;
                }

                this->major_ = this->major_ * 10 + ch - '0';
                break;
            case s_first_minor_digit:
                if (ch < '0' || ch > '9') {
                    this->error = htparse_error_inval_ver;
                    return i + 1;
                }

                this->minor_ = ch - '0';
                this->state = s_minor_digit;
                break;
            case s_minor_digit:
                switch (ch) {
                    case ' ':
                        if (this->type == htp_type_request) {
                            this->state = s_spaces_after_digit;
                        } else if (this->type == htp_type_response) {
                            this->state = s_status;
                        }

                        break;
                    case CR:
                        this->state = s_almost_done;
                        break;
                    case LF:
                        this->state = s_hdrline_start;
                        break;
                    default:
                        if (ch < '0' || ch > '9') {
                            this->error = htparse_error_inval_ver;
                            return i + 1;
                        }

                        this->minor_ = this->minor_ * 10 + ch - '0';
                        break;
                } /* switch */
                break;
            case s_status:
                /* http response status code */
                if (ch == ' ') {
                    break;
                }

                if (ch < '0' || ch > '9') {
                    this->error = htparse_error_generic;
                    return i + 1;
                }

                this->status = this->status * 10 + ch - '0';

                if (++this->status_count == 3) {
                    this->state = s_space_after_status;
                }

                break;
            case s_space_after_status:
                switch (ch) {
                    case ' ':
                        this->state = s_status_text;
                        break;
                    case CR:
                        this->state = s_almost_done;
                        break;
                    case LF:
                        this->state = s_hdrline_start;
                        break;
                    default:
                        this->error = htparse_error_generic;
                        return i + 1;
                }
                break;
            case s_status_text:
                switch (ch) {
                    case CR:
                        this->state = s_almost_done;
                        break;
                    case LF:
                        this->state = s_hdrline_start;
                        break;
                    default:
                        break;
                }
                break;
            case s_spaces_after_digit:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        this->state = s_almost_done;
                        break;
                    case LF:
                        this->state = s_hdrline_start;
                        break;
                    default:
                        this->error = htparse_error_inval_ver;
                        return i + 1;
                }
                break;

            case s_almost_done:
                switch (ch) {
                    case LF:
                        if (this->type == htp_type_response && this->status >= 100 && this->status < 200) {
                            this->status       = 0;
                            this->status_count = 0;
                            this->state        = s_start;
                            break;
                        }

                        this->state = s_done;
                        res      = hook_on_hdrs_begin_run(this, hooks);
                        break;
                    default:
                        this->error = htparse_error_inval_reqline;
                        return i + 1;
                }
                break;
            case s_done:
                switch (ch) {
                    case CR:
                        this->state = s_hdrline_almost_done;
                        break;
                    case LF:
                        return i + 1;
                    default:
                        goto hdrline_start;
                }
                break;
hdrline_start:
            case s_hdrline_start:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_hdrline_start\n";
                this->buf_idx = 0;

                switch (ch) {
                    case CR:
                        this->state             = s_hdrline_hdr_almost_done;
                        break;
                    case LF:
                        this->state             = s_hdrline_hdr_done;
                        break;
                    default:
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';

                        this->state             = s_hdrline_hdr_key;
                        break;
                }

                break;
            case s_hdrline_hdr_key:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_hdrline_hdr_key\n";
                res = 0;
                switch (ch) {
                    case ':':
                        res      = hook_hdr_key_run(this, hooks, this->buf, this->buf_idx);

                        /* figure out if the value of this header is valueable */
                        this->heval = eval_hdr_val_none;

                        switch (this->buf_idx + 1) {
                            case 11:
                                if (!strcasecmp(this->buf, "connection")) {
                                    this->heval = eval_hdr_val_connection;
                                }
                                break;
                            case 15:
                                if (!strcasecmp(this->buf, "content-length")) {
                                    this->heval = eval_hdr_val_content_length;
                                }
                                break;
                            case 17:
                                if (!strcasecmp(this->buf, "proxy-connection")) {
                                    this->heval = eval_hdr_val_proxy_connection;
                                }
                                break;
                            case 18:
                                if (!strcasecmp(this->buf, "transfer-encoding")) {
                                    this->heval = eval_hdr_val_transfer_encoding;
                                }
                                break;
                        } /* switch */

                        this->buf_idx           = 0;
                        this->state             = s_hdrline_hdr_space_before_val;

                        break;
                    case CR:
                        this->state             = s_hdrline_hdr_almost_done;
                        break;
                    case LF:
                        this->state             = s_hdrline_hdr_done;
                        break;
                    default:
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        break;
                } /* switch */

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_hdrline_hdr_space_before_val:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_hdrline_hdr_space_before_val\n";
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                    case LF:
                        /* empty header value, is this legal? */
                        this->error             = htparse_error_inval_hdr;
                        return i + 1;
                    default:
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        this->state             = s_hdrline_hdr_val;
                        break;
                }
                break;
            case s_hdrline_hdr_val:
				//DLOG(INFO)<<"["<<p<<"]"<<"s_hdrline_hdr_val\n";                
                err = 0;
                res = 0;

                switch (ch) {
                    case CR:
                        res = hook_hdr_val_run(this, hooks, this->buf, this->buf_idx);

                        switch (this->heval) {
                            case eval_hdr_val_none:
                                break;
                            case eval_hdr_val_content_length:
                                this->content_len = str_to_uint64(this->buf, this->buf_idx, &err);

                                if (err == 1) {
                                    this->error = htparse_error_too_big;
                                    return i + 1;
                                }

                                break;
                            case eval_hdr_val_connection:
                                switch (this->buf[0]) {
                                    case 'K':
                                    case 'k':
                                        if (_str9cmp((this->buf + 1),
                                                     'e', 'e', 'p', '-', 'A', 'l', 'i', 'v', 'e')) {
                                            this->flags |= parser_flag_connection_keep_alive;
                                        }
                                        break;
                                    case 'c':
                                        if (_str5cmp(this->buf, 'c', 'l', 'o', 's', 'e')) {
                                            this->flags |= parser_flag_connection_close;
                                        }
                                        break;
                                }
                                break;
                            case eval_hdr_val_transfer_encoding:
                                if (_str7_cmp(this->buf, 'c', 'h', 'u', 'n', 'k', 'e', 'd', '\0')) {
                                    this->flags |= parser_flag_chunked;
                                }

                                break;
                            default:
                                break;
                        } /* switch */

                        this->state             = s_hdrline_hdr_almost_done;
                        this->buf_idx           = 0;

                        break;
                    case LF:
                        this->state             = s_hdrline_hdr_done;
                        break;
                    default:
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';
                        break;
                } /* switch */

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_hdrline_hdr_almost_done:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_hdrline_hdr_almost_done\n";
                res = 0;
                switch (ch) {
                    case LF:
                        if (this->flags & parser_flag_trailing) {
                            res      = hook_on_msg_complete_run(this, hooks);
                            this->state = s_start;
                            break;
                        }

                        this->state = s_hdrline_hdr_done;
                        break;
                    default:
                        this->error = htparse_error_inval_hdr;
                        return i + 1;
                }

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_hdrline_hdr_done:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_hdrline_hdr_done\n";
                switch (ch) {
                    case CR:
                        this->state = s_hdrline_almost_done;
                        break;
                    case LF:
                        /* got LFLF? is this valid? */
                        return i + 1;
                    default:
                        this->buf_idx           = 0;
                        this->buf[this->buf_idx++] = ch;
                        this->buf[this->buf_idx]   = '\0';

                        this->state = s_hdrline_hdr_key;
                        break;
                }
                break;
            case s_hdrline_almost_done:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_hdrline_almost_done\n";
                res = 0;

                switch (ch) {
                    case LF:
                        this->buf_idx = 0;                        
						//DLOG(INFO)<<"["<<p<<"]"<<"HERE\n";
                        res        = hook_on_hdrs_complete_run(this, hooks);

                        if (!res) {
                            if (this->flags & parser_flag_trailing) {
                                res      = hook_on_msg_complete_run(this, hooks);
                                this->state = s_start;
                            } else if (this->flags & parser_flag_chunked) {
                                this->state = s_chunk_size_start;
                            } else if (this->content_len > 0) {
                                this->state = s_body_read;
                            } else if (this->content_len == 0) {
                                res      = hook_on_msg_complete_run(this, hooks);
                                this->state = s_start;
                            }
                        } else {
                            this->state = s_hdrline_done;
                        }

                        if (res) {
                            this->error = htparse_error_user;
                            return i + 1;
                        }
                        break;
                    default:
                        this->error = htparse_error_inval_hdr;
                        return i + 1;
                } /* switch */

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_hdrline_done:                
				//DLOG(INFO)<<"["<<p<<"]"<<"s_hdrline_done\n";
                res = 0;
                if (this->flags & parser_flag_trailing) {
                    res      = hook_on_msg_complete_run(this, hooks);
                    this->state = s_start;
                    break;
                } else if (this->flags & parser_flag_chunked) {
                    this->state = s_chunk_size_start;
                    i--;
                } else if (this->content_len > 0) {
                    this->state = s_body_read;
                    i--;
                } else if (this->content_len == 0) {
                    res      = hook_on_msg_complete_run(this, hooks);
                    this->state = s_start;
                }
                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }
                break;

            case s_chunk_size_start:
                c = unhex[(unsigned char)ch];

                if (c == -1) {
                    this->error = htparse_error_inval_chunk_sz;
                    return i + 1;
                }

                this->content_len = c;
                this->state       = s_chunk_size;
                break;
            case s_chunk_size:
                if (ch == CR) {
                    this->state = s_chunk_size_almost_done;
                    break;
                }

                c = unhex[(unsigned char)ch];

                if (c == -1) {
                    this->error = htparse_error_inval_chunk_sz;
                    return i + 1;
                }

                this->content_len *= 16;
                this->content_len += c;
                break;

            case s_chunk_size_almost_done:
                res = 0;

                if (ch != LF) {
                    this->error = htparse_error_inval_chunk_sz;
                    return i + 1;
                }

                if (this->content_len == 0) {
                    res       = hook_on_chunks_complete_run(this, hooks);

                    this->flags |= parser_flag_trailing;
                    this->state  = s_hdrline_start;
                } else {
                    res      = hook_on_new_chunk_run(this, hooks);

                    this->state = s_chunk_data;
                }

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_chunk_data:
                res = 0;
                {
                    const char * pp      = &data[i];
                    const char * pe      = (const char *)(data + len);
                    size_t       to_read = std::min<size_t>(pe - pp, (size_t)this->content_len);

                    if (to_read > 0) {
                        res = hook_body_run(this, hooks, pp, to_read);

                        i  += to_read - 1;
                    }

                    if (to_read == this->content_len) {
                        this->state = s_chunk_data_almost_done;
                    }

                    this->content_len -= to_read;
                }

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_chunk_data_almost_done:
                if (ch != CR) {
                    this->error = htparse_error_inval_chunk;
                    return i + 1;
                }

                this->state = s_chunk_data_done;
                break;

            case s_chunk_data_done:
                if (ch != LF) {
                    this->error = htparse_error_inval_chunk;
                    return i + 1;
                }

                this->state = s_chunk_size_start;

                if (hook_on_chunk_complete_run(this, hooks)) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_body_read:
                res = 0;

                {
                    const char * pp      = &data[i];
                    const char * pe      = (const char *)(data + len);
                    size_t       to_read = std::min<size_t>(pe - pp, (size_t)this->content_len);
                    
					//DLOG(INFO)<<"["<<p<<"]"<<"s_body_read"<<to_read<<"\n";
                    if (to_read > 0) {
                        res = hook_body_run(this, hooks, pp, to_read);

                        i  += to_read - 1;
                        this->content_len -= to_read;

                        if (this->content_len == 0) {
                            res      = hook_on_msg_complete_run(this, hooks);

                            this->state = s_start;
                        }
                    } else {
                        res      = hook_on_msg_complete_run(this, hooks);
                        this->state = s_start;
                    }
                }

                if (res) {
                    this->error = htparse_error_user;
                    return i + 1;
                }

                break;

            default:
				//DLOG(INFO)<<"["<<p<<"]"<<"This is a silly state....\n";                
                this->error = htparse_error_inval_state;
                return i + 1;
        } /* switch */
    }

    return i;
}


void           htparser::init( htp_type t){	
	this->error = htparse_error_none;
	this->type  = t;
}
