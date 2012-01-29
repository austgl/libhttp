cmake_minimum_required (VERSION 2.8) 
PROJECT(websocketServer CXX C)

set (VERSION_MAJOR 1)
set (VERSION_MINOR 0)
find_package(OpenSSL REQUIRED)
find_package (Threads)
include (CheckFunctionExists)
include (CheckIncludeFiles)
include (CheckIncludeFileCXX)
include (CheckCXXSourceCompiles)
check_include_file_cxx (hash_map HASH_FUN_H)
check_include_file_cxx (inttypes.h HAVE_INTTYPES_H)
check_include_files (memory.h HAVE_MEMORY_H)
check_include_files (stdint.h HAVE_STDINT_H)
check_include_files (stdlib.h HAVE_STDLIB_H)

check_include_files (strings.h HAVE_STRINGS_H)
check_include_files (string.h HAVE_STRING_H)
check_include_files (sys/resource.h HAVE_SYS_RESOURCE_H)
check_include_files (sys/stat.h HAVE_SYS_STAT_H)
check_include_files (sys/time.h HAVE_SYS_TIME_H)
check_include_files (sys/types.h HAVE_SYS_TYPES_H)
check_include_files (sys/utsname.h HAVE_SYS_UTSNAME_H)

check_include_file_cxx (google/malloc_extension.h HAVE_GOOGLE_MALLOC_EXTENSION_H)


foreach(filename "<tr1/unordered_map>" "<unordered_map>")
  foreach(namespace  "std" "std::tr1")
    check_cxx_source_compiles(
	    "
	        #include ${filename}
	        int main(int argc,char* argv[]) {
	            ${namespace}::unordered_map<int, int> m;
	            return 0;
	        }
	    "
	    UNORDERED_MAP_FOUND_${filename}_${namespace})
		
	if (UNORDERED_MAP_FOUND_${filename}_${namespace})	
       set  (HAVE_HASH_MAP 1)	
	   set  (HAVE_UNORDERED_MAP 1)
	   set (HASH_MAP_H "${filename}")
	   set (HASH_NAMESPACE "${namespace}")
	   break()
	endif(UNORDERED_MAP_FOUND_${filename}_${namespace})    
	endforeach(namespace)	
endforeach(filename)	

foreach(filename "<tr1/unordered_set>" "<unordered_set>")
  foreach(namespace  "std" "std::tr1")
    check_cxx_source_compiles(
	    "
	        #include ${filename}
	        int main(int argc,char* argv[]) {
	            ${namespace}::unordered_set<int, int> m;
	            return 0;
	        }
	    "
	    UNORDERED_SET_FOUND_${filename}_${namespace})
		
	if (UNORDERED_SET_FOUND_${filename}_${namespace})	   
	   set (HAVE_HASH_SET 1)
	   set (HASH_SET_H "${filename}")
	   break()
	endif(UNORDERED_SET_FOUND_${filename}_${namespace})    
	endforeach(namespace)	
endforeach(filename)	

foreach(filename "<functional>" "<xfunctional>" "<tr1/functional>" "<ext/hash_fun.h>" "<ext/stl_hash_fun.h>" "<hash_fun.h>" "<stl_hash_fun.h>" "<stl/_hash_fun.h>")
	check_cxx_source_compiles(
	    "
	        #include ${filename}
	        int main(int argc,char* argv[]) {
	            int x = ${HASH_NAMESPACE}::hash<int>()(5);
	            return 0;
	        }
	    "
	    HASH_FUNC_FOUND_${filename})
	if (HASH_FUNC_FOUND_${filename})	   
	   set (HASH_FUN_H "${filename}")
	   break()
	endif(HASH_FUNC_FOUND_${filename}) 		
endforeach(filename)

#check long long 
 check_cxx_source_compiles(
	    "	        
	        int main(int argc,char* argv[]) {
	            long long v;
	            return 0;
	        }
	    "
	    HAVE_LONG_LONG)

check_cxx_source_compiles(
	    "	        
		    #include <stdint.h>
	        int main(int argc,char* argv[]) {
	            uint16_t v;
	            return 0;
	        }
	    "
	    HAVE_UINT16_T)		
check_function_exists (memcpy HAVE_MEMCPY)		
check_function_exists (memmove HAVE_MEMMOVE)
if(CMAKE_USE_PTHREADS_INIT)
 set(HAVE_PTHREAD 1)
endif()



check_function_exists (strcasecmp HAVE_STRCASECMP)
check_function_exists (snprintf HAVE_SNPRINTF)
configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
 )
configure_file (
  "${PROJECT_SOURCE_DIR}/sparsehash/google/sparsehash/sparseconfig.h.in"
  "${PROJECT_BINARY_DIR}/google/sparsehash/sparseconfig.h"
)

include_directories(${PROJECT_SOURCE_DIR}/gtest/include)
include_directories(${PROJECT_SOURCE_DIR}/sparsehash)

ADD_SUBDIRECTORY(sparsehash) 
ADD_SUBDIRECTORY(gtest) 
ADD_SUBDIRECTORY(http)
ADD_SUBDIRECTORY(src bin)
