#pragma once

class HttpCallback;
#include <google/dense_hash_map>
#include <list>
#include <functional>
#include <stdint.h>
#include <unicode/unistr.h>

struct HashString:public std::unary_function<icu::UnicodeString, size_t>{
public:
	size_t operator()(const icu::UnicodeString& _Keyval) const
		{	
		   return _Keyval.hashCode();
		}
};

struct eqstr
{
  bool operator()(const icu::UnicodeString& s1, const icu::UnicodeString& s2) const
  {	  
	  return (s1 == s2)==TRUE;
  }
};


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
	HttpCallback* find(const icu::UnicodeString&   path);
	google::dense_hash_map<icu::UnicodeString,HttpCallback*,HashString,eqstr> callbacks; /**< hash of path callbacks */    
    std::list<HttpCallback*>   regex_callbacks; /**< list of regex callbacks */

};
