#pragma once


class MyHtparseHooks:public htparse_hooks {
public:
	virtual int on_msg_begin(IHTParser *) ;
	
	/** \brief only the path of the uri */
	virtual int path(IHTParser *, const char *, size_t);
	/** \brief only the arguments of the uri */
	virtual int args(IHTParser *, const char *, size_t);
	
    virtual int on_hdrs_begin(IHTParser *);
    
	virtual int hdr_key(IHTParser *, const char *, size_t);
	virtual int hdr_val(IHTParser *, const char *, size_t);
	
	virtual int on_hdrs_complete(IHTParser *) ;
	/** \brief called after parsed chunk octet */
	virtual int on_new_chunk(IHTParser *) ;
	/** \brief called after single parsed chunk */
	virtual int on_chunk_complete(IHTParser *) ;
	/** \brief called after all parsed chunks processed */
	virtual int on_chunks_complete(IHTParser *) ;
	
	virtual int body(IHTParser *, const char *, size_t);

	virtual int on_msg_complete(IHTParser *) ;
};

