#include "evhtp_callback.h"
#include <stdexcept>

HttpCallback::HttpCallback(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg){


	this->type  = type;
	this->cb    = cb;
	this->cbarg = arg;

	switch (type) {
	case evhtp_callback_type_hash:
		this->val.path  = strdup(path);
		break;
	case evhtp_callback_type_regex:
		this->val.regex = (regex_t*)malloc(sizeof(regex_t));

		if (regcomp(this->val.regex, (char *)path, REG_EXTENDED) != 0) {
			free(this->val.regex);
			free(this);
			throw std::runtime_error("compile error");
		}
		break;
	default:
		throw std::runtime_error("wrong type");
	}
}

HttpCallback::~HttpCallback(){
	switch (this->type) {
	case evhtp_callback_type_hash:
		if (this->val.path) {
			free(this->val.path);
		}
		break;
	case evhtp_callback_type_regex:
		if (this->val.regex) {
			regfree(this->val.regex);
		}
		break;
	}
}