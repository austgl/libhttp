#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdexcept>

#include "evhtp_connection.h"
#include "htparse.h"
#include "evhtp.h"
#include "evhtp_request.h"

evhtp_connection::evhtp_connection(evhtp * htp, int sock) {
    this->evbase    = NULL;
    this->bev       = NULL;
    //connection->thread    = NULL;
    this->ssl       = NULL;
    this->hooks     = NULL;
    this->request   = NULL;
    this->resume_ev = NULL;
    this->error     = 0;
    this->sock      = sock;
    this->htp       = htp;
    this->parser    = htparser_new();

	if(this->parser==NULL)
		throw std::runtime_error("create parser fail");

	this->parser->init(htp_type_request);
	this->parser->set_userdata(this);
}


evhtp_connection::~evhtp_connection(){
	delete this->request;

    if (this->hooks && this->hooks->on_connection_fini) {
		try{
			(this->hooks->on_connection_fini)(this, this->hooks->on_connection_fini_arg);
		}catch(...){
		}
	}

    if (this->parser) {
        delete this->parser;
    }

    if (this->resume_ev) {
        event_free(this->resume_ev);
    }

    if (this->bev) {
#ifdef LIBEVENT_HAS_SHUTDOWN
        bufferevent_shutdown(connection->bev, _evhtp_shutdown_eventcb);
#else

        if (this->ssl != NULL) {
            SSL_set_shutdown(this->ssl,
                             SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(this->ssl);
        }
        bufferevent_free(this->bev);
#endif
    }

    if (this->hooks) {
        free(this->hooks);
    }

/*    if (connection->thread) {
        evthr_dec_backlog(connection->thread);
    }*/

    if (this->saddr) {
        free(this->saddr);
    }
}
