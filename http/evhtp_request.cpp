#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "evhtp_request.h"
#include "evhtp_connection.h"
#include "evhtp_kv.h"
#include "myhooks.h"
#include "evhtp_uri.h"


evhtp_request_s::evhtp_request_s(evhtp_connection_s * c){
    this->conn        = c;
    this->htp         = c->htp;
    this->status      = EVHTP_RES_OK;
    this->buffer_in   = evbuffer_new();
    this->buffer_out  = evbuffer_new();
    this->headers_in  = (evhtp_headers_t*)malloc(sizeof(evhtp_headers_t));
    this->headers_out = (evhtp_headers_t*)malloc(sizeof(evhtp_headers_t));

    TAILQ_INIT(this->headers_in);
    TAILQ_INIT(this->headers_out);

	this->hooks=NULL;
	this->uri=NULL;
	this->proto=EVHTP_PROTO_INVALID;
	this->method=htp_method_UNKNOWN;
	this->keepalive=0;
	this->finished=0;
	this->chunked=0;
	this->cb=NULL;
	this->cbarg=NULL;
	this->error=0;
}

evhtp_request_s::~evhtp_request_s(){
	HOOK_REQUEST_RUN_NARGS_NO_RETURN(this, on_request_fini);
    delete this->uri;

    evhtp_headers_free(this->headers_in);
    evhtp_headers_free(this->headers_out);

    if (this->hooks) {
        delete this->hooks;
    }

    if (this->buffer_in) {
        evbuffer_free(this->buffer_in);
    }

    if (this->buffer_out) {
        evbuffer_free(this->buffer_out);
    }
}
