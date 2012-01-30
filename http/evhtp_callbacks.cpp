#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "evhtp_callbacks.h"
#include "evhtp_callback.h"
#include <stdlib.h>
#include <algorithm>
#include <iostream>
#include <unicode/unistr.h>

evhtp_callbacks_s::evhtp_callbacks_s(){
  this->callbacks.set_empty_key("");
}
evhtp_callbacks_s::~evhtp_callbacks_s(){

	std::for_each(this->regex_callbacks.begin(),this->regex_callbacks.end(),[=] (HttpCallback* iter){
		delete iter;
	});
	std::for_each(this->callbacks.begin(),this->callbacks.end(),[=] (std::pair<icu::UnicodeString,HttpCallback*> value){
		delete value.second;		
	});
}

HttpCallback* evhtp_callbacks_s::find(const icu::UnicodeString&   path){
	{
		auto iter=this->callbacks.find(path);
		if(iter!=this->callbacks.end()){
			return iter->second;
		}
	}
	{
		auto iter=std::find_if(this->regex_callbacks.begin(),this->regex_callbacks.end(),[=] (HttpCallback * callback )->bool {			
			callback->matcher->reset(path);
			if (callback->matcher->find()) {
				return true;
			}			
			return false;
		});
		if(iter!=this->regex_callbacks.end()){
			return *iter;
		}
	}
	//木有找到哇！
	return NULL;
}
