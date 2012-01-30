#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "evhtp_s.h"
#include "evhtp_ssl_cfg.h"

#include "evhtp_connection.h"

#include <openssl/rand.h>  //RAND_poll
#include <tbb/mutex.h>
#include <vector>
#include <algorithm>
#include <sstream>
#include <tbb/tbb_thread.h>

static int             session_id_context    = 1;

static std::vector<tbb::mutex*> ssl_locks;
static int             ssl_locks_initialized = 0;


static unsigned long
_evhtp_ssl_get_thread_id(void) {
	auto id=tbb::this_tbb_thread::get_id();
	std::stringstream ss;
	ss<<id;
	int ret;
	ss>>ret;
	return ret; //不知道干嘛用
}

/**
 * \param mode Determines the action that the locking function should take. When the CRYPTO_LOCK flag is set, the lock should be acquired; otherwise, it should be released.
 * \param type The number of the lock that should be acquired or released. The number is zero-based.
 * \param file The name of the source file requesting the locking operation to take place. only for debugging
 * \param line The source line number requesting the locking operation to take place. only for debugging
 *
 */
static void
_evhtp_ssl_thread_lock(int mode, int type, const char * file, int line) {
	if (type < static_cast<int>(ssl_locks.size())) {
        if (mode & CRYPTO_LOCK) {
			ssl_locks.at(type)->lock();            
        } else {
			ssl_locks.at(type)->unlock();            
        }
    }
}


int evhtp_ssl_use_threads(void) {

    if (ssl_locks_initialized == 1) {
        return 0;
    }

    ssl_locks_initialized = 1;

    int ssl_num_locks         = CRYPTO_num_locks();
	for(int i=0;i!=ssl_num_locks;++i){
		ssl_locks.push_back(new tbb::mutex());
	}
	
    CRYPTO_set_id_callback(_evhtp_ssl_get_thread_id);
    CRYPTO_set_locking_callback(_evhtp_ssl_thread_lock);

    return 0;
}


static void
_evhtp_ssl_delete_scache_ent(SSL_CTX * ctx, SSL_SESSION * sess) {
    evhtp         * htp;
    evhtp_ssl_cfg * cfg;
    unsigned char   * sid;
    unsigned int      slen;

    htp  = (evhtp *)SSL_CTX_get_app_data(ctx);
    cfg  = htp->ssl_cfg;

    sid  = sess->session_id;
    slen = sess->session_id_length;

    if (cfg->scache_del) {
        (cfg->scache_del)(htp, sid, slen);
    }
}

static int
_evhtp_ssl_add_scache_ent(SSL * ssl, SSL_SESSION * sess) {
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * cfg;
    unsigned char      * sid;
    int                  slen;

    connection = (evhtp_connection_t *)SSL_get_app_data(ssl);
    cfg        = connection->htp->ssl_cfg;

    sid        = sess->session_id;
    slen       = sess->session_id_length;

    SSL_set_timeout(sess, cfg->scache_timeout);

    if (cfg->scache_add) {
        return (cfg->scache_add)(connection, sid, slen, sess);
    }

    return 0;
}

static SSL_SESSION *
_evhtp_ssl_get_scache_ent(SSL * ssl, unsigned char * sid, int sid_len, int * copy) {
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * cfg;
    SSL_SESSION   * sess;

    connection = (evhtp_connection_t * )SSL_get_app_data(ssl);
    cfg        = connection->htp->ssl_cfg;
    sess       = NULL;

    if (cfg->scache_get) {
        sess = (cfg->scache_get)(connection, sid, sid_len);
    }

    *copy = 0;

    return sess;
}

struct CRYPTO_dynlock_value{
	tbb::mutex mutex;
};

CRYPTO_dynlock_value* my_dyn_create_function(const char *file,
int line){
	return new CRYPTO_dynlock_value();
}

void my_dyn_lock_function(int mode, struct CRYPTO_dynlock_value
*mutex, const char *file, int line){
	if (mode & CRYPTO_LOCK) {
		mutex->mutex.lock();
	} else 
		mutex->mutex.unlock();
}

void my_dyn_destroy_function(struct CRYPTO_dynlock_value *mutex,
const char *file, int line){
	delete mutex;
}

int
evhtp_ssl_init(evhtp * htp, evhtp_ssl_cfg * cfg) {
    long                  cache_mode;
    evhtp_ssl_scache_init init_cb = NULL;
    evhtp_ssl_scache_add  add_cb  = NULL;
    evhtp_ssl_scache_get  get_cb  = NULL;
    evhtp_ssl_scache_del  del_cb  = NULL;

    if (cfg == NULL || htp == NULL || cfg->pemfile == NULL) {
        return -1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    RAND_poll();

    STACK_OF(SSL_COMP) * comp_methods = SSL_COMP_get_compression_methods();
    sk_SSL_COMP_zero(comp_methods);

    htp->ssl_cfg = cfg;
    htp->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    SSL_CTX_set_options(htp->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_timeout(htp->ssl_ctx, 60 * 60 * 48);
#endif

    SSL_CTX_set_options(htp->ssl_ctx, cfg->ssl_opts);

    if (cfg->ciphers != NULL) {
        SSL_CTX_set_cipher_list(htp->ssl_ctx, cfg->ciphers);
    }

    SSL_CTX_load_verify_locations(htp->ssl_ctx, cfg->cafile, cfg->capath);
    X509_STORE_set_flags(SSL_CTX_get_cert_store(htp->ssl_ctx), cfg->store_flags);
    SSL_CTX_set_verify(htp->ssl_ctx, cfg->verify_peer, cfg->x509_verify_cb);

    if (cfg->x509_chk_issued_cb != NULL) {
        htp->ssl_ctx->cert_store->check_issued = cfg->x509_chk_issued_cb;
    }

    if (cfg->verify_depth) {
        SSL_CTX_set_verify_depth(htp->ssl_ctx, cfg->verify_depth);
    }

    switch (cfg->scache_type) {
        case evhtp_ssl_scache_type_disabled:
            cache_mode = SSL_SESS_CACHE_OFF;
            break;
        case evhtp_ssl_scache_type_user:
            cache_mode = SSL_SESS_CACHE_SERVER |
                         SSL_SESS_CACHE_NO_INTERNAL |
                         SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;

            init_cb    = cfg->scache_init;
            add_cb     = cfg->scache_add;
            get_cb     = cfg->scache_get;
            del_cb     = cfg->scache_del;
            break;
        case evhtp_ssl_scache_type_builtin:
            cache_mode = SSL_SESS_CACHE_SERVER |
                         SSL_SESS_CACHE_NO_INTERNAL |
                         SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;

#if 0
            init_cb    = _evhtp_ssl_builtin_init;
            add_cb     = _evhtp_ssl_builtin_add;
            get_cb     = _evhtp_ssl_builtin_get;
            del_cb     = _evhtp_ssl_builtin_del;
#endif
            break;
        case evhtp_ssl_scache_type_internal:
        default:
            cache_mode = SSL_SESS_CACHE_SERVER;
            break;
    }     /* switch */

    SSL_CTX_use_certificate_file(htp->ssl_ctx, cfg->pemfile, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(htp->ssl_ctx, cfg->privfile ? cfg->privfile: cfg->pemfile, SSL_FILETYPE_PEM);

    SSL_CTX_set_session_id_context(htp->ssl_ctx,
                                   (const unsigned char*)&session_id_context,
                                   sizeof(session_id_context));

    SSL_CTX_set_app_data(htp->ssl_ctx, htp);
    SSL_CTX_set_session_cache_mode(htp->ssl_ctx, cache_mode);

    if (cache_mode != SSL_SESS_CACHE_OFF) {
        SSL_CTX_sess_set_cache_size(htp->ssl_ctx,
                                    cfg->scache_size ? cfg->scache_size : 1024);

        if (cfg->scache_type == evhtp_ssl_scache_type_builtin ||
            cfg->scache_type == evhtp_ssl_scache_type_user) {
            SSL_CTX_sess_set_new_cb(htp->ssl_ctx, _evhtp_ssl_add_scache_ent);
            SSL_CTX_sess_set_get_cb(htp->ssl_ctx, _evhtp_ssl_get_scache_ent);
            SSL_CTX_sess_set_remove_cb(htp->ssl_ctx, _evhtp_ssl_delete_scache_ent);

            if (cfg->scache_init) {
                cfg->args = (cfg->scache_init)(htp);
            }
        }
    }

    return 0;
}     /* evhtp_use_ssl */