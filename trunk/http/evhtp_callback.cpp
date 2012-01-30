#include "evhtp_callback.h"
#include <stdexcept>

HttpCallback::HttpCallback(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg){
	this->type  = type;
	this->cb    = cb;
	this->cbarg = arg;	
	switch (type) {
	case evhtp_callback_type_hash:
		this->path=icu::UnicodeString::fromUTF8(path);
		this->matcher=NULL;
		break;
	case evhtp_callback_type_regex:
		{
			UErrorCode        status    = U_ZERO_ERROR;
			RegexMatcher *matcher = new RegexMatcher(path, 0, status);
			if (U_FAILURE(status)) {
				delete matcher;
				throw std::runtime_error("compile error");
			}
			this->matcher=matcher;
		}		
		break;
	default:
		throw std::runtime_error("wrong type");
	}
}

HttpCallback::~HttpCallback(){
	if(matcher!=NULL) delete matcher;
}