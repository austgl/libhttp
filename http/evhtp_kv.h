#pragma once

#include "myqueue.h"

/**
 * @brief a generic key/value structure
 */
struct evhtp_kv_s {
    char * key;
    char * val;

    size_t klen;
    size_t vlen;

    char k_heaped; /**< set to 1 if the key can be free()'d */
    char v_heaped; /**< set to 1 if the val can be free()'d */

    TAILQ_ENTRY(evhtp_kv_s) next;
};

TAILQ_HEAD(evhtp_kvs_s, evhtp_kv_s);


/**
 * @brief Allocates a new key/value structure.
 *
 * @param key null terminated string
 * @param val null terminated string
 * @param kalloc if set to 1, the key will be copied, if 0 no copy is done.
 * @param valloc if set to 1, the val will be copied, if 0 no copy is done.
 *
 * @return evhtp_kv_s * on success, NULL on error.
 */
evhtp_kv_s  * evhtp_kv_new(const char * key, const char * val, char kalloc, char valloc);
evhtp_kvs_s * evhtp_kvs_new(void);

void          evhtp_kv_free(evhtp_kv_s * kv);
void          evhtp_kvs_free(evhtp_kvs_s * kvs);
void          evhtp_kv_rm_and_free(evhtp_kvs_s * kvs, evhtp_kv_s * kv);

const char  * evhtp_kv_find(evhtp_kvs_s * kvs, const char * key);
evhtp_kv_s  * evhtp_kvs_find_kv(evhtp_kvs_s * kvs, const char * key);
typedef int (*evhtp_kvs_iterator)(evhtp_kv_t * kv, void * arg);

/**
 * @brief appends a key/val structure to a evhtp_kvs_s tailq
 *
 * @param kvs an evhtp_kvs_s structure
 * @param kv  an evhtp_kv_s structure
 */
void evhtp_kvs_add_kv(evhtp_kvs_s * kvs, evhtp_kv_s * kv);

int  evhtp_kvs_for_each(evhtp_kvs_s * kvs, evhtp_kvs_iterator cb, void * arg);
