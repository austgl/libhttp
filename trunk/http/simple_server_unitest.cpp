#include <glog/logging.h>
#include <event2/thread.h>
#include "evhtp.h"
#include "evhtp_request.h"
#include "evhtp_s.h"

const char* test_content="<html>\n"
	"<head>\n"
	"<title>hello</title>"
	"<body><h1>我的测试页面</h1></body>"
	"</html>";

static void testcb(evhtp_request_t * req, void * a) {
	evbuffer_add_reference(req->buffer_out, test_content, strlen(test_content), NULL, NULL);
	evhtp_headers_add_header(req->headers_out,evhtp_header_new("Content-Type", "text/html; charset=UTF-8", 0, 0));
	evhtp_send_reply(req, EVHTP_RES_OK);
}

void my_libevent_logger(int severity, const char *msg){
	const char *s;
	switch (severity) {
        case _EVENT_LOG_DEBUG: s = "debug"; break;
        case _EVENT_LOG_MSG:   s = "msg";   break;
        case _EVENT_LOG_WARN:  s = "warn";  break;
        case _EVENT_LOG_ERR:   s = "error"; break;
        default:               s = "?";     break; /* never reached */
    }
	DLOG(INFO)<<"["<<s<<"] "<<msg<<"\n";
}

int main(int argc, char **argv) {
	setlocale(LC_ALL,"");
    google::InitGoogleLogging("myunitest");
	event_set_log_callback(my_libevent_logger);
#ifdef WIN32
	WSADATA wsa_data;
	WSAStartup(0x0201, &wsa_data);
	evthread_use_windows_threads();
#endif
	evthread_enable_lock_debuging();
	event_enable_debug_mode();

    evbase_t * evbase = event_base_new();
    evhtp  * htp    = new evhtp(evbase, NULL);

    evhtp_set_regex_cb(htp, "/([a-z]+)/test", testcb, NULL);
    evhtp_bind_socket(htp, "0.0.0.0", 8388, 1024);
    event_base_loop(evbase, 0);
	return 0;
}
