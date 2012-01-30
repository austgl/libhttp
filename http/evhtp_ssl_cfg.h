#pragma once

#include <openssl/ssl.h>
#include "evhtp_ssl_scache_type.h"

typedef int (*evhtp_ssl_verify_cb)(int pre_verify, X509_STORE_CTX * ctx);
typedef int (*evhtp_ssl_chk_issued_cb)(X509_STORE_CTX * ctx, X509 * x, X509 * issuer);


class evhtp_connection;
class evhtp;


typedef int (*evhtp_ssl_scache_add)(evhtp_connection * connection, unsigned char * sid, int sid_len, SSL_SESSION * sess);
typedef void (*evhtp_ssl_scache_del)(evhtp * htp, unsigned char * sid, int sid_len);
typedef SSL_SESSION* (*evhtp_ssl_scache_get)(evhtp_connection * connection, unsigned char * sid, int sid_len);
typedef void * (*evhtp_ssl_scache_init)(evhtp *);

class evhtp_ssl_cfg {
public:
    char                  * pemfile;
    char                  * privfile;
    char                  * cafile;
    char                  * capath;
    char                  * ciphers;
    long                    ssl_opts;
    int                     verify_peer;
    int                     verify_depth;
    evhtp_ssl_verify_cb     x509_verify_cb;
    evhtp_ssl_chk_issued_cb x509_chk_issued_cb;
    long                    store_flags;
    evhtp_ssl_scache_type   scache_type;
    long                    scache_timeout;
    long                    scache_size;
    evhtp_ssl_scache_init   scache_init;
    evhtp_ssl_scache_add    scache_add;
    evhtp_ssl_scache_get    scache_get;
    evhtp_ssl_scache_del    scache_del;
    void                  * args;
};

int       evhtp_ssl_init(evhtp * htp, evhtp_ssl_cfg * ssl_cfg);