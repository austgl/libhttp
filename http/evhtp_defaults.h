#pragma once
#include "evhtp_callback_type.h"

class evhtp_defaults_s {
public:
    evhtp_callback_cb    cb;
    evhtp_pre_accept_cb  pre_accept;
    evhtp_post_accept_cb post_accept;
    void               * cbarg;
    void               * pre_accept_cbarg;
    void               * post_accept_cbarg;
	evhtp_defaults_s():cb(NULL),pre_accept(NULL),post_accept(NULL),cbarg(NULL),pre_accept_cbarg(NULL),post_accept_cbarg(NULL){};
	virtual ~evhtp_defaults_s() {} ;
};
