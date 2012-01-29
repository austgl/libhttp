#pragma once

//#include <event2/event.h>
#include <event2/buffer.h>

#include "evhtp_proto.h"
#include "htp_method.h"
#include "evhtp_types.h"
#include "evhtp_callback_type.h"

class evhtp_s;
class evhtp_connection_s;
class evhtp_hooks_s;
class evhtp_uri_s;

/**
 * @brief a structure containing all information for a http request.
 */
class evhtp_request_s {
public:
	evhtp_request_s(evhtp_connection_s * c);
	virtual ~evhtp_request_s();
    evhtp_s            * htp;         /**< the parent evhtp_t structure */
    evhtp_connection_s * conn;        /**< the associated connection */
    evhtp_hooks_s      * hooks;       /**< request specific hooks */
    evhtp_uri_s        * uri;         /**< request URI information */
    evbuffer            * buffer_in;   /**< buffer containing data from client */
    evbuffer            * buffer_out;  /**< buffer containing data to client */
    evhtp_headers_t    * headers_in;  /**< headers from client */
    evhtp_headers_t    * headers_out; /**< headers to client */
    evhtp_proto          proto;       /**< HTTP protocol used */
    htp_method           method;      /**< HTTP method used */
    uint16_t            status;      /**< The HTTP response code or other error conditions */
    int                  keepalive;   /**< set to 1 if the connection is keep-alive */
    int                  finished;    /**< set to 1 if the request is fully processed */
    int                  chunked;     /**< set to 1 if the request is chunked */

    evhtp_callback_cb cb;             /**< the function to call when fully processed */
    void            * cbarg;          /**< argument which is passed to the cb function */
    int               error;
};