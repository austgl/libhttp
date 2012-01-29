#pragma once

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <openssl/ssl.h>

class evhtp_s;
class evhtp_hooks_s;
class IHTParser;
class evhtp_request_s;

class evhtp_connection_s {
public:
	evhtp_connection_s(evhtp_s * htp, int sock);
	~evhtp_connection_s();
    evhtp_s         * htp;
    event_base        * evbase;
    bufferevent         * bev;
    //evthr_t         * thread;
    SSL     * ssl;
    evhtp_hooks_s   * hooks;
    IHTParser        * parser;
    event         * resume_ev;
    struct sockaddr * saddr;
    int               sock;
    int               error;

	//在_evhtp_request_parser_start时初始化
    evhtp_request_s * request;
};