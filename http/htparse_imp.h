#pragma once

#include "htparse.h"
#include "parser_state.h"

enum eval_hdr_val {
  eval_hdr_val_none = 0,
  eval_hdr_val_connection,
  eval_hdr_val_proxy_connection,
  eval_hdr_val_content_length,
  eval_hdr_val_transfer_encoding
};


class htparser :public IHTParser{
 public:
  htparser();
  virtual size_t         run( htparse_hooks *, const char *, size_t);
  virtual int            should_keep_alive();
  virtual htp_scheme     get_scheme();
  virtual HttpMethod     get_method();
  virtual const char   * get_methodstr();
  virtual void           set_major( unsigned char);
  virtual void           set_minor( unsigned char);
  virtual unsigned char  get_major();
  virtual unsigned char  get_minor();
  virtual unsigned int   get_status();
  virtual uint64_t       get_content_length();
  virtual htpparse_error get_error();
  virtual const char   * get_strerror();
  virtual void         * get_userdata();
  virtual void           set_userdata( void *);
  virtual void           init( HttpMessageType);
  uint64_t get_bytes_read();

 private:
  const static size_t PARSER_STACK_MAX=8192;
  htpparse_error error;
  parser_state   state;
  //parser_flags的位或
  int   flags;
  eval_hdr_val   heval;

  HttpMessageType   type;
  htp_scheme scheme;
  HttpMethod method;

  unsigned char major_;
  unsigned char minor_;
  uint64_t      content_len;
  uint64_t      bytes_read;
  unsigned int  status;       /* only for responses */
  unsigned int  status_count; /* only for responses */

  char         buf[PARSER_STACK_MAX];
  unsigned int buf_idx;

  char * scheme_offset;
  char * host_offset;
  char * port_offset;
  char * path_offset;
  char * args_offset;

  void * userdata;
};
