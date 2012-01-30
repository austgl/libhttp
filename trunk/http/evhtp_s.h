#pragma once

#include "evhtp_defaults.h"
#include "evhtp_callbacks.h"

#include <event2/event.h>
#include <event2/listener.h>
#include <openssl/ssl.h>
#include <tbb/mutex.h>

class evhtp_ssl_cfg;

/**
 * @brief main structure containing all configuration information
 */
class evhtp {
public:
	/**
	* @param evbase the initialized event base
	* @param arg user-defined argument which is evhtp_t specific
	*/
	evhtp(event_base * evbase, void * arg);
	virtual ~evhtp();
    event_base * evbase;            /**< the initialized event_base */
    evconnlistener * server;            /**< the libevent listener struct */
    char     * server_name;       /**< the name included in Host: responses */
    void     * arg;               /**< user-defined evhtp_t specific arguments */

    SSL_CTX * ssl_ctx;    /**< if ssl enabled, this is the servers CTX */
    evhtp_ssl_cfg * ssl_cfg;

	//TODO:
    //evthr_pool_t      * thr_pool; /**< connection threadpool */
	typedef tbb::mutex mylocktype;
	mylocktype lock;     /**< parent lock for add/del cbs in threads */
    evhtp_callbacks_t  callbacks;
    evhtp_defaults_s    defaults;

    struct timeval * recv_timeo;
    struct timeval * send_timeo;
};

/*
int
evhtp_use_threads(evhtp_t * htp, evhtp_thread_init_cb init_cb, int nthreads, void * arg) {
    htp->thread_init_cb    = init_cb;
    htp->thread_init_cbarg = arg;

#ifndef DISABLE_SSL
    evhtp_ssl_use_threads();
#endif
	
    if (!(htp->thr_pool = evthr_pool_new(nthreads, _evhtp_thread_init, htp))) {
        return -1;
    }

    evthr_pool_start(htp->thr_pool);
    return 0;
}*/
