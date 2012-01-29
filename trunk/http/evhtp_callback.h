#pragma once

#include "evhtp_callback_type.h"


#include <onigposix.h>

class evhtp_hooks_s;

/**
 * @brief structure containing a single callback and configuration
 *
 * The definition structure which is used within the evhtp_callbacks_t
 * structure. This holds information about what should execute for either
 * a single or regex path.
 *
 * For example, if you registered a callback to be executed on a request
 * for "/herp/derp", your defined callback will be executed.
 *
 * Optionally you can set callback-specific hooks just like per-connection
 * hooks using the same rules.
 *
 */
class evhtp_callback_s {
public:
    evhtp_callback_type type;            /**< the type of callback (regex|path) */
    evhtp_callback_cb   cb;              /**< the actual callback function */
    void              * cbarg;           /**< user-defind arguments passed to the cb */
    evhtp_hooks_s     * hooks;           /**< per-callback hooks */

    union {
        char    * path;
        regex_t * regex;
    } val;

    evhtp_callback_s * next;
};