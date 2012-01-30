#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "http_status_codes.h"
#include "status_code.h"
#include "evhtp_callback.h"
#include "evhtp_callbacks.h"
#include "evhtp_s.h"
#include "evhtp_connection.h"
#include "evhtp_kv.h"
#include "evhtp_request.h"
#include "htparse.h"
#include "MyHtparseHooks.h"

#include <event2/bufferevent_ssl.h>
#include <stdexcept>
#include <sstream>

#ifndef HAVE_SNPRINTF
#define snprintf _snprintf
#endif

extern void evhtp_send_reply(EvHttpRequest * request, evhtp_res code);

static MyHtparseHooks request_psets ;

static void _evhtp_default_request_cb(EvHttpRequest * request, void * arg) {
    return evhtp_send_reply(request, EVHTP_RES_NOTFOUND);
}

static int _evhtp_run_pre_accept(evhtp * htp, int sock, struct sockaddr * s, int sl) {
	void    * args;
	evhtp_res res;

	if (htp->defaults.pre_accept == NULL) {
		return 0;
	}

	args = htp->defaults.pre_accept_cbarg;
	res  = htp->defaults.pre_accept(sock, s, sl, args);

	if (res != EVHTP_RES_OK) {
		return -1;
	}

	return 0;
}


static int
	_evhtp_run_post_accept(evhtp * htp, evhtp_connection_t * connection) {
		void    * args;
		evhtp_res res;

		if (htp->defaults.post_accept == NULL) {
			return 0;
		}

		args = htp->defaults.post_accept_cbarg;
		res  = htp->defaults.post_accept(connection, args);

		if (res != EVHTP_RES_OK) {
			return -1;
		}

		return 0;
}

static int
_evhtp_create_headers(evhtp_header_t * header, void * arg) {
    evbuf_t * buf = (evbuf_t*)arg;

    evbuffer_add(buf, header->key, header->klen);
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, header->val, header->vlen);
    evbuffer_add(buf, "\r\n", 2);
    return 0;
}

static evbuffer *
_evhtp_create_reply(evhtp_request_t * request, evhtp_res code) {
    evbuffer * buf = evbuffer_new();

    if (evbuffer_get_length(request->buffer_out) && request->chunked == 0) {
        /* add extra headers (like content-length/type) if not already present */

        if (!evhtp_header_find(request->headers_out, "Content-Length")) {
			std::ostringstream oss;
			oss<<evbuffer_get_length(request->buffer_out);
			std::string lstr=oss.str();      

            evhtp_headers_add_header(request->headers_out,
                                     evhtp_header_new("Content-Length", lstr.c_str(), 0, 1));
        }

		if (!evhtp_header_find(request->headers_out, "Server")) {
			  evhtp_headers_add_header(request->headers_out,
                                     evhtp_header_new("Server", "nginx/1.1.0", 0, 0));
		}

        if (!evhtp_header_find(request->headers_out, "Content-Type")) {
            evhtp_headers_add_header(request->headers_out,
                                     evhtp_header_new("Content-Type", "text/plain", 0, 0));
        }
    } else {
        if (!evhtp_header_find(request->headers_out, "Content-Length")) {
            const char * chunked = evhtp_header_find(request->headers_out,
                                                     "transfer-encoding");

            if (!chunked || !strstr(chunked, "chunked")) {
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Content-Length", "0", 0, 0));
            }
        }
    }


    /* add the proper keep-alive type headers based on http version */
    switch (request->proto) {
        case EVHTP_PROTO_11:
            if (request->keepalive == 0) {
                /* protocol is HTTP/1.1 but client wanted to close */
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Connection", "close", 0, 0));
            }
            break;
        case EVHTP_PROTO_10:
            if (request->keepalive == 1) {
                /* protocol is HTTP/1.0 and clients wants to keep established */
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Connection", "keep-alive", 0, 0));
            }
            break;
        default:
            /* this sometimes happens when a response is made but paused before
             * the method has been parsed */
			request->conn->parser->set_major(1);
			request->conn->parser->set_minor(0);
            break;
    } /* switch */

    /* add the status line */
    evbuffer_add_printf(buf, "HTTP/%d.%d %d %s\r\n",
		request->conn->parser->get_major(),
		request->conn->parser->get_minor(),
		code, StatusCodeManager::instance().status_code_to_str(code));

    evhtp_headers_for_each(request->headers_out, _evhtp_create_headers, buf);
    evbuffer_add_reference(buf, "\r\n", 2, NULL, NULL);

    if (evbuffer_get_length(request->buffer_out)) {
        evbuffer_add_buffer(buf, request->buffer_out);
    }

    return buf;
}     /* _evhtp_create_reply */

/**
 * @brief pauses a connection (disables reading)
 *
 * @param c a evhtp_connection_t * structure
 */
void
evhtp_connection_pause(evhtp_connection_t * c) {
    if ((bufferevent_get_enabled(c->bev) & EV_READ)) {
        bufferevent_disable(c->bev, EV_READ);
    }
}


static void _evhtp_connection_readcb(evbev_t * bev, void * arg) {
	evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(arg);
	void               * buf;
	size_t               nread;
	size_t               avail;

	if (c->request) {
		c->request->status = EVHTP_RES_OK;
	}

	avail = evbuffer_get_length(bufferevent_get_input(bev));
	//把bev的前avail个字节整成连续的
	buf   = evbuffer_pullup(bufferevent_get_input(bev), avail);
	if(buf==NULL){
		//不够那么多字节？不该到这里。
		return;
	}
	nread = c->parser->run(&request_psets, (const char *)buf, avail);

	if (avail != nread) {
		if (c->request && c->request->status == EVHTP_RES_PAUSE) {
			evhtp_connection_pause(c->request->conn);
		} else {
			delete c;
			return;
		}
	}

	evbuffer_drain(bufferevent_get_input(bev), nread);
}

static void
_evhtp_connection_resumecb(int fd, short events, void * arg) {
	evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(arg);
    if (c->request) {
        c->request->status = EVHTP_RES_OK;
    }

    return _evhtp_connection_readcb(c->bev, c);
}




static void
_evhtp_connection_writecb(evbev_t * bev, void * arg) {
    evhtp_connection_t * c = reinterpret_cast<evhtp_connection_t*>(arg);

    if (c->request == NULL) {
        return;
    }

    if (c->request->finished == 0 || evbuffer_get_length(bufferevent_get_output(bev))) {
        return;
    }

    if (c->request->keepalive) {
        delete(c->request);
        c->request = NULL;
		c->parser->init(htp_type_request);
		c->parser->set_userdata(c);
    } else {
         delete c;
		 return ;
    }

    return;
}

static void _evhtp_connection_eventcb(evbev_t * bev, short events, void * arg) {

	if ((events & BEV_EVENT_CONNECTED)) {
		/**< connect operation finished. */
		return;
	}

	std::auto_ptr<evhtp_connection> c(reinterpret_cast<evhtp_connection*>(arg));

	if (c->ssl && !(events & BEV_EVENT_EOF)) {
		c->error = 1;

		if (c->request) {
			c->request->error = 1;
		}
	}
}



static int
	_evhtp_connection_accept(evbase_t * evbase, evhtp_connection_t * connection) {

		if (connection->htp->ssl_ctx != NULL) {
			connection->ssl = SSL_new(connection->htp->ssl_ctx);
			connection->bev = bufferevent_openssl_socket_new(evbase,
				connection->sock, connection->ssl,
				BUFFEREVENT_SSL_ACCEPTING,
				BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
			SSL_set_app_data(connection->ssl, connection);
			goto end;
		}

		//创建一个socket-based bufferevent 
		connection->bev = bufferevent_socket_new(evbase, connection->sock,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

end:

		bufferevent_set_timeouts(connection->bev,
			connection->htp->recv_timeo,
			connection->htp->send_timeo);

		connection->resume_ev = event_new(evbase, -1, EV_READ | EV_PERSIST,
			_evhtp_connection_resumecb, connection);
		event_add(connection->resume_ev, NULL);

		bufferevent_enable(connection->bev, EV_READ);
		bufferevent_setcb(connection->bev,
			_evhtp_connection_readcb,
			_evhtp_connection_writecb,
			_evhtp_connection_eventcb,
			connection);

		return 0;
}     /* _evhtp_connection_accept */




static void
	_evhtp_shutdown_eventcb(evbev_t * bev, short events, void * arg) {
}


static void _evhtp_accept_cb(evserv_t * serv, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp            * htp = (evhtp*)arg;
    
    if (_evhtp_run_pre_accept(htp, fd, s, sl) < 0) {
        return;
    }

	evhtp_connection_t * connection=new evhtp_connection_t(htp,fd);

    connection->saddr = (sockaddr*)malloc(sl);
    memcpy(connection->saddr, s, sl);

    /*if (htp->thr_pool != NULL) {
        evthr_pool_defer(htp->thr_pool, _evhtp_run_in_thread, connection);
        return;
    }*/

    connection->evbase = htp->evbase;

    if (_evhtp_connection_accept(htp->evbase, connection) < 0) {
		delete connection;
		return ;
    }

    if (_evhtp_run_post_accept(htp, connection) < 0) {
        delete connection;
		return ;
    }
}

int
	evhtp_bind_sockaddr(evhtp * htp, struct sockaddr * sa, size_t sin_len, int backlog) {
#ifdef SIGPIPE
		signal(SIGPIPE, SIG_IGN);
#endif
		htp->server = evconnlistener_new_bind(htp->evbase, _evhtp_accept_cb, (void *)htp,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
			backlog, sa, sin_len);
		return htp->server ? 0 : -1;
}

int evhtp::bind_socket(const char * baddr, uint16_t port, int backlog){
	struct sockaddr_in  sin;
	struct sockaddr  * sa;
	size_t             sin_len;

	memset(&sin, 0, sizeof(sin));

	sin_len             = sizeof(struct sockaddr_in);
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(port);
	sin.sin_addr.s_addr = inet_addr(baddr);

	sa = (struct sockaddr *)&sin;

	return evhtp_bind_sockaddr(this, sa, sin_len, backlog);
}

evhtp::evhtp(event_base * evbase, void * arg){

	this->server=NULL;
	this->ssl_ctx=NULL;
	this->ssl_cfg=NULL;
	this->recv_timeo=NULL;
	this->send_timeo=NULL;

    if (evbase == NULL) {
		throw std::runtime_error("evbase cannot be NULL");
    }


    this->arg         = arg;
    this->evbase      = evbase;
    this->server_name = strdup("nginx/1.1.0");

    this->defaults.cb    = _evhtp_default_request_cb;
    this->defaults.cbarg = (void*)this;


}

evhtp::~evhtp(){
}

int evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb) {

	switch (cb->type) {
	case evhtp_callback_type_hash:
		cbs->callbacks[cb->path]=cb;            
		break;
	case evhtp_callback_type_regex:
		cbs->regex_callbacks.push_back(cb);
		break;
	default:
		return -1;
	}

	return 0;
}


evhtp_callback_t * evhtp::set_cb(const icu::UnicodeString& path, evhtp_callback_cb cb, void * arg){
	{
		evhtp::mylocktype::scoped_lock l(this->lock);
		evhtp_callback_t * hcb;
		if (!(hcb = new HttpCallback(path, evhtp_callback_type_hash, cb, arg))) {        
			return NULL;
		}

		if (evhtp_callbacks_add_callback(&this->callbacks, hcb)) {
			delete(hcb);
			return NULL;
		}
		return hcb;
	}
	
}
evhtp_callback_t * evhtp::set_regex_cb(const icu::UnicodeString& pattern, evhtp_callback_cb cb, void * arg){	

	{
		evhtp::mylocktype::scoped_lock l(this->lock);
		evhtp_callback_t * hcb;
		if (!(hcb = new HttpCallback(pattern, evhtp_callback_type_regex, cb, arg))) {

			return NULL;
		}

		if (evhtp_callbacks_add_callback(&this->callbacks, hcb)) {
			delete(hcb);
			return NULL;
		}
		return hcb;
	}
}

void
evhtp_send_reply_start(evhtp_request_t * request, evhtp_res code) {    
    evhtp_connection_t * c = request->conn;
	evbuffer * reply_buf=_evhtp_create_reply(request, code);
    if (!reply_buf) {
        delete c;
		return ;
    }

    bufferevent_write_buffer(c->bev, reply_buf);
    evbuffer_free(reply_buf);
}

void
evhtp_send_reply_body(evhtp_request_t * request, evbuf_t * buf) {
    evhtp_connection_t * c;

    c = request->conn;

    bufferevent_write_buffer(c->bev, buf);
}

void
evhtp_send_reply_end(evhtp_request_t * request) {
    request->finished = 1;
    bufferevent_flush(request->conn->bev, EV_WRITE, BEV_FLUSH);
}

void
evhtp_send_reply(evhtp_request_t * request, evhtp_res code) {
    evhtp_connection_t * c= request->conn;
    evbuf_t            * reply_buf;

    request->finished = 1;

    if (!(reply_buf = _evhtp_create_reply(request, code))) {
		delete request->conn;
		return ;
    }

    bufferevent_write_buffer(c->bev, reply_buf);
    evbuffer_free(reply_buf);
}

int
evhtp_response_needs_body(const evhtp_res code, const HttpMethod method) {
    return code != EVHTP_RES_NOCONTENT &&
           code != EVHTP_RES_NOTMOD &&
           (code < 100 || code >= 200) &&
           method != htp_method_HEAD;
}

void
evhtp_send_reply_chunk_start(evhtp_request_t * request, evhtp_res code) {
    evhtp_header_t * content_len;

    if (evhtp_response_needs_body(code, request->method)) {
        content_len = evhtp_headers_find_header(request->headers_out, "Content-Length");

        switch (request->proto) {
            case EVHTP_PROTO_11:

                /*
                 * prefer HTTP/1.1 chunked encoding to closing the connection;
                 * note RFC 2616 section 4.4 forbids it with Content-Length:
                 * and it's not necessary then anyway.
                 */

                evhtp_kv_rm_and_free(request->headers_out, content_len);
                request->chunked = 1;
                break;
            case EVHTP_PROTO_10:
                /*
                 * HTTP/1.0 can be chunked as long as the Content-Length header
                 * is set to 0
                 */
                evhtp_kv_rm_and_free(request->headers_out, content_len);

                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Content-Length", "0", 0, 0));

                request->chunked = 1;
                break;
            default:
                request->chunked = 0;
                break;
        } /* switch */
    } else {
        request->chunked = 0;
    }

    if (request->chunked == 1) {
        evhtp_headers_add_header(request->headers_out,
                                 evhtp_header_new("Transfer-Encoding", "chunked", 0, 0));

        /*
         * if data already exists on the output buffer, we automagically convert
         * it to the first chunk.
         */
        if (evbuffer_get_length(request->buffer_out) > 0) {
            char lstr[128];
            int  sres;

            sres = snprintf(lstr, sizeof(lstr), "%x\r\n",
                            (unsigned)evbuffer_get_length(request->buffer_out));

            if (sres >= sizeof(lstr) || sres < 0) {
                /* overflow condition, shouldn't ever get here, but lets
                 * terminate the connection asap */
                goto end;
            }

            evbuffer_prepend(request->buffer_out, lstr, strlen(lstr));
            evbuffer_add(request->buffer_out, "\r\n", 2);
        }
    }

end:
    evhtp_send_reply_start(request, code);
} /* evhtp_send_reply_chunk_start */

void
evhtp_send_reply_chunk(evhtp_request_t * request, evbuf_t * buf) {
    evbuf_t * output;

    output = bufferevent_get_output(request->conn->bev);

    if (evbuffer_get_length(buf) == 0) {
        return;
    }
    if (request->chunked) {
        evbuffer_add_printf(output, "%x\r\n",
                            (unsigned)evbuffer_get_length(buf));
    }
    evhtp_send_reply_body(request, buf);
    if (request->chunked) {
        evbuffer_add(output, "\r\n", 2);
    }
    bufferevent_flush(request->conn->bev, EV_WRITE, BEV_FLUSH);
}

void
evhtp_send_reply_chunk_end(evhtp_request_t * request) {
    if (request->chunked) {
        evbuffer_add(bufferevent_get_output(request->conn->bev),
                     "0\r\n\r\n", 5);
    }
    evhtp_send_reply_end(request);
}



