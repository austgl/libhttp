#pragma once

class evhtp_callback_s;
#include <google/dense_hash_map>
#include <list>
#include <functional>


struct HashString:public std::unary_function<_STD string, size_t>{
public:
	typedef _STD string _Kty;

	size_t operator()(const _Kty& _Keyval) const
		{	// hash _Keyval to size_t value by pseudorandomizing transform
		size_t _Val = 2166136261U;
		size_t _First = 0;
		size_t _Last = _Keyval.size();
		size_t _Stride = 1 + _Last / 10;

		for(; _First < _Last; _First += _Stride)
			_Val = 16777619U * _Val ^ (size_t)_Keyval[_First];
		return (_Val);
		}
};

struct eqstr
{
  bool operator()(const std::string& s1, const std::string& s2) const
  {	  
	  return s1.compare(s2)==0;
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
	google::dense_hash_map<std::string,evhtp_callback_s*,HashString,eqstr> callbacks; /**< hash of path callbacks */    
    std::list<evhtp_callback_s*>   regex_callbacks; /**< list of regex callbacks */

};
