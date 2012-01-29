#pragma once

class IHTParser;

class htparse_hooks {
public:
	virtual int on_msg_begin(IHTParser *) { return 0;}
	
	virtual int method(IHTParser *, const char *, size_t){ return 0;}
	/** \brief called if scheme is found */
	virtual int scheme(IHTParser *, const char *, size_t){ return 0;}
	/** \brief called if a host was in the request scheme */
	virtual int host(IHTParser *, const char *, size_t){ return 0;}
	/** \brief called if a port was in the request scheme */
	virtual int port(IHTParser *, const char *, size_t){ return 0;}
	/** \brief only the path of the uri */
	virtual int path(IHTParser *, const char *, size_t){ return 0;}
	/** \brief only the arguments of the uri */
	virtual int args(IHTParser *, const char *, size_t){ return 0;}
	/** \brief the entire uri including path/args */
	virtual int uri(IHTParser *, const char *, size_t){ return 0;}
	
    virtual int on_hdrs_begin(IHTParser *){ return 0;}
    
	virtual int hdr_key(IHTParser *, const char *, size_t){ return 0;}
	virtual int hdr_val(IHTParser *, const char *, size_t){ return 0;}
	
	virtual int on_hdrs_complete(IHTParser *) { return 0;}
	/** \brief called after parsed chunk octet */
	virtual int on_new_chunk(IHTParser *) { return 0;}
	/** \brief called after single parsed chunk */
	virtual int on_chunk_complete(IHTParser *) { return 0;}
	/** \brief called after all parsed chunks processed */
	virtual int on_chunks_complete(IHTParser *) { return 0;}
	
	virtual int body(IHTParser *, const char *, size_t){ return 0;}

	virtual int on_msg_complete(IHTParser *) { return 0;}
};
