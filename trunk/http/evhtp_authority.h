#pragma once
#include <stdint.h>
/**
 * @brief structure which represents authority information in a URI
 */
struct evhtp_authority_s {
    char   * username;                /**< the username in URI (scheme://USER:.. */
    char   * password;                /**< the password in URI (scheme://...:PASS.. */
    char   * hostname;                /**< hostname if present in URI */
    uint16_t port;                    /**< port if present in URI */
};
