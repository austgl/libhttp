#pragma once

class evhtp_callback_s;
#include <unordered_map>
#include <list>
/**
 * @brief structure containing all registered evhtp_callbacks_t
 *
 * This structure holds information which correlates either
 * a path string (via a hash) or a regular expression callback.
 *
 */
class evhtp_callbacks_s {
public:
	evhtp_callbacks_s();
	virtual ~evhtp_callbacks_s();
	std::tr1::unordered_map<std::string,evhtp_callback_s*> callbacks; /**< hash of path callbacks */    
    std::list<evhtp_callback_s*>   regex_callbacks; /**< list of regex callbacks */

};
