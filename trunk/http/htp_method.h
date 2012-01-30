#pragma once


enum HttpMethod {
    htp_method_GET = 0,
    htp_method_HEAD,
    htp_method_POST,
    htp_method_PUT,
    htp_method_DELETE,
    htp_method_MKCOL,
    htp_method_COPY,
    htp_method_MOVE,
    htp_method_OPTIONS,
    htp_method_PROPFIND,
    htp_method_PROPPATCH,
    htp_method_LOCK,
    htp_method_UNLOCK,
    htp_method_TRACE,
    htp_method_UNKNOWN
};
