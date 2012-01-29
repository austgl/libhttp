#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "http_status_codes.h"
#include "status_code.h"

#include "evhtp_s.h"

#include <stdexcept>

extern void evhtp_send_reply(evhtp_request_s * request, evhtp_res code);

static void _evhtp_default_request_cb(evhtp_request_s * request, void * arg) {
    return evhtp_send_reply(request, EVHTP_RES_NOTFOUND);
}

evhtp_s::evhtp_s(event_base * evbase, void * arg){

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
    this->server_name = "evhtp, sucka";

	this->defaults.cb    = _evhtp_default_request_cb;
    this->defaults.cbarg = (void*)this;


}

evhtp_s::~evhtp_s(){
}