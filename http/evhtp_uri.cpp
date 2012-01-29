#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "evhtp_uri.h"
#include "evhtp_kv.h"


evhtp_uri_s::evhtp_uri_s():authority(NULL),path(NULL),fragment(NULL),query_raw(NULL),query(NULL),scheme(htp_scheme_none){

}

evhtp_uri_s::~evhtp_uri_s(){
	evhtp_query_free(this->query);
    delete this->path;

    if (this->fragment) {
        free(this->fragment);
    }

    if (this->query_raw) {
        free(this->query_raw);
    }
}

