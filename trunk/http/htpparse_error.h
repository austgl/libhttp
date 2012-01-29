#pragma once


enum htpparse_error {
    htparse_error_none = 0,
    htparse_error_too_big,
    htparse_error_inval_method,
    htparse_error_inval_reqline,
    htparse_error_inval_schema,
    htparse_error_inval_proto,
    htparse_error_inval_ver,
    htparse_error_inval_hdr,
    htparse_error_inval_chunk_sz,
    htparse_error_inval_chunk,
    htparse_error_inval_state,
    htparse_error_user,
    htparse_error_generic
};

