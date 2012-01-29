#pragma once


#include <stdint.h>
#include <tbb/atomic.h>
#include <unordered_map>

class StatusCodeManager{		
public:
	static StatusCodeManager& instance(){
		if( !value ) {
			StatusCodeManager* tmp = new StatusCodeManager();
			if( value.compare_and_swap(tmp,NULL)!=NULL )
				// Another thread installed the value, so throw away mine.
				delete tmp;
		}
		return *value;
	}
	const char * status_code_to_str(uint16_t code);
protected:
	StatusCodeManager();
private:
	void status_code_init();
	static tbb::atomic<StatusCodeManager*> value;
	std::tr1::unordered_map<uint16_t,const char *> scode;
};

