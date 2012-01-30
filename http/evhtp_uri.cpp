#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "evhtp_uri.h"
#include "evhtp_kv.h"
#include <stdlib.h> //free

HttpUri::HttpUri():authority(NULL),path(NULL),fragment(NULL),query_raw(NULL),query(NULL),scheme(htp_scheme_none){

}

HttpUri::~HttpUri(){
	evhtp_query_free(this->query);
    delete this->path;

    if (this->fragment) {
        free(this->fragment);
    }

    if (this->query_raw) {
        free(this->query_raw);
    }
}

