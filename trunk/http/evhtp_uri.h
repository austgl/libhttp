#pragma once

#include "evhtp_authority.h"
#include "htp_scheme.h"
#include "evhtp_path.h"

#include "evhtp_types.h"


/**
 * @brief a generic container representing an entire URI strucutre
 */
class HttpUri {
public:
	HttpUri();
	~HttpUri();
    HttpAuthority * authority;
    HttpPath      * path;
    unsigned char     * fragment;     /**< data after '#' in uri */
    unsigned char     * query_raw;    /**< the unparsed query arguments */
    evhtp_query_t     * query;        /**< list of k/v for query arguments */
    htp_scheme          scheme;       /**< set if a scheme is found */
};