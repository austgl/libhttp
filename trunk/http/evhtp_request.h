#pragma once

//#include <event2/event.h>
#include <event2/buffer.h>

#include "evhtp_proto.h"
#include "htp_method.h"
#include "evhtp_types.h"
#include "evhtp_callback_type.h"

class evhtp;
class evhtp_connection;
class evhtp_hooks_s;
class HttpUri;

/**
 * @brief a structure containing all information for a http request.
 */
class EvHttpRequest {
public:
	EvHttpRequest(evhtp_connection * c);
	virtual ~EvHttpRequest();
    evhtp            * htp;         /**< the parent evhtp_t structure */
    evhtp_connection * conn;        /**< the associated connection */
    evhtp_hooks_s      * hooks;       /**< request specific hooks */
    HttpUri        * uri;         /**< request URI information */
    evbuffer            * buffer_in;   /**< buffer containing data from client */
    evbuffer            * buffer_out;  /**< buffer containing data to client */
    evhtp_headers_t    * headers_in;  /**< headers from client */
    evhtp_headers_t    * headers_out; /**< headers to client */
    evhtp_proto          proto;       /**< HTTP protocol used */
    HttpMethod           method;      /**< HTTP method used */
    uint16_t            status;      /**< The HTTP response code or other error conditions */
    int                  keepalive;   /**< set to 1 if the connection is keep-alive */
    int                  finished;    /**< set to 1 if the request is fully processed */
    int                  chunked;     /**< set to 1 if the request is chunked */

    evhtp_callback_cb cb;             /**< the function to call when fully processed */
    void            * cbarg;          /**< argument which is passed to the cb function */
    int               error;
};