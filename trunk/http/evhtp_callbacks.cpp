#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "evhtp_callbacks.h"
#include "evhtp_callback.h"
#include <stdlib.h>
#include <algorithm>
#include <iostream>

evhtp_callbacks_s::evhtp_callbacks_s(){
  this->callbacks.set_empty_key("");
}
evhtp_callbacks_s::~evhtp_callbacks_s(){

	std::for_each(this->regex_callbacks.begin(),this->regex_callbacks.end(),[=] (HttpCallback* iter){
		delete iter;
	});
	std::for_each(this->callbacks.begin(),this->callbacks.end(),[=] (std::pair<std::string,HttpCallback*> value){
		delete value.second;		
	});
}
