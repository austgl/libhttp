#pragma once
#include <stdint.h>

#include "htp_type.h"
#include "htp_scheme.h"
#include "htp_method.h"
#include "htpparse_error.h"
#include "htparse_hooks.h"



class IHTParser{
public:
	virtual size_t         run( htparse_hooks *, const char *, size_t)=0;
	virtual int            should_keep_alive()=0;
	virtual htp_scheme     get_scheme()=0;
	virtual HttpMethod     get_method()=0;
	virtual const char   * get_methodstr()=0;
	virtual void           set_major( unsigned char)=0;
	virtual void           set_minor( unsigned char)=0;
	virtual unsigned char  get_major()=0;
	virtual unsigned char  get_minor()=0;
	virtual unsigned int   get_status()=0;
	virtual uint64_t       get_content_length()=0;
	virtual htpparse_error get_error()=0;
	virtual const char   * get_strerror()=0;
	virtual void         * get_userdata()=0;
	virtual void           set_userdata( void *)=0;
	virtual void           init( HttpMessageType)=0;
};

IHTParser     * htparser_new(void);
