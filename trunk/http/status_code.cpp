#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>

#include "status_code.h"
#include "http_status_codes.h"

tbb::atomic<StatusCodeManager*> StatusCodeManager::value;
StatusCodeManager::StatusCodeManager(){
	this->status_code_init();
}
void StatusCodeManager::status_code_init(void) {
	 /* 100 codes */
    scode[EVHTP_RES_CONTINUE]= "Continue";
    scode[EVHTP_RES_SWITCH_PROTO]= "Switching Protocols";
    scode[EVHTP_RES_PROCESSING]= "Processing";
    scode[EVHTP_RES_URI_TOOLONG]= "URI Too Long";

    /* 200 codes */
    scode[EVHTP_RES_200]= "OK";
    scode[EVHTP_RES_CREATED]= "Created";
    scode[EVHTP_RES_ACCEPTED]= "Accepted";
    scode[EVHTP_RES_NAUTHINFO]= "No Auth Info";
    scode[EVHTP_RES_NOCONTENT]= "No Content";
    scode[EVHTP_RES_RSTCONTENT]= "Reset Content";
    scode[EVHTP_RES_PARTIAL]= "Partial Content";
    scode[EVHTP_RES_MSTATUS]= "Multi-Status";
    scode[EVHTP_RES_IMUSED]= "IM Used";

    /* 300 codes */
    scode[EVHTP_RES_300]= "Redirect";
    scode[EVHTP_RES_MOVEDPERM]= "Moved Permanently";
    scode[EVHTP_RES_FOUND]= "Found";
    scode[EVHTP_RES_SEEOTHER]= "See Other";
    scode[EVHTP_RES_NOTMOD]= "Not Modified";
    scode[EVHTP_RES_USEPROXY]= "Use Proxy";
    scode[EVHTP_RES_SWITCHPROXY]= "Switch Proxy";
    scode[EVHTP_RES_TMPREDIR]= "Temporary Redirect";

    /* 400 codes */
    scode[EVHTP_RES_400]= "Bad Request";
    scode[EVHTP_RES_UNAUTH]= "Unauthorized";
    scode[EVHTP_RES_PAYREQ]= "Payment Required";
    scode[EVHTP_RES_FORBIDDEN]= "Forbidden";
    scode[EVHTP_RES_NOTFOUND]= "Not Found";
    scode[EVHTP_RES_METHNALLOWED]= "Not Allowed";
    scode[EVHTP_RES_NACCEPTABLE]= "Not Acceptable";
    scode[EVHTP_RES_PROXYAUTHREQ]= "Proxy Authentication Required";
    scode[EVHTP_RES_TIMEOUT]= "Request Timeout";
    scode[EVHTP_RES_CONFLICT]= "Conflict";
    scode[EVHTP_RES_GONE]= "Gone";
    scode[EVHTP_RES_LENREQ]= "Length Required";
    scode[EVHTP_RES_PRECONDFAIL]= "Precondition Failed";
    scode[EVHTP_RES_ENTOOLARGE]= "Entity Too Large";
    scode[EVHTP_RES_URITOOLARGE]= "Request-URI Too Long";
    scode[EVHTP_RES_UNSUPPORTED]= "Unsupported Media Type";
    scode[EVHTP_RES_RANGENOTSC]= "Requested Range Not Satisfiable";
    scode[EVHTP_RES_EXPECTFAIL]= "Expectation Failed";
    scode[EVHTP_RES_IAMATEAPOT]= "I'm a teapot";

    /* 500 codes */
    scode[EVHTP_RES_SERVERR]= "Internal Server Error";
    scode[EVHTP_RES_NOTIMPL]= "Not Implemented";
    scode[EVHTP_RES_BADGATEWAY]= "Bad Gateway";
    scode[EVHTP_RES_SERVUNAVAIL]= "Service Unavailable";
    scode[EVHTP_RES_GWTIMEOUT]= "Gateway Timeout";
    scode[EVHTP_RES_VERNSUPPORT]= "HTTP Version Not Supported";
    scode[EVHTP_RES_BWEXEED]= "Bandwidth Limit Exceeded";

}
const char * StatusCodeManager::status_code_to_str(uint16_t code) {
	auto iter=scode.find(code);
	if(iter==scode.end())
		return "DERP";
	else
		return iter->second;   
}
