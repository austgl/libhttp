#pragma once

#include <stdexcept>
#include <stdint.h> //防止icu的头文件中对某些常量重定义
#include <unicode/unistr.h>

class PathCorruptedException:public std::runtime_error{
public:
	typedef std::runtime_error Mybase_;

	explicit PathCorruptedException(const std::string& _Message)
		: Mybase_(_Message.c_str())
		{	// construct from message string
		}

	explicit PathCorruptedException(const char *_Message)
		: Mybase_(_Message)
		{	// construct from message string
		}
};

class FileCorruptedException:public std::runtime_error{
public:
	typedef std::runtime_error Mybase_;

	explicit FileCorruptedException(const std::string& _Message)
		: Mybase_(_Message.c_str())
		{	// construct from message string
		}

	explicit FileCorruptedException(const char *_Message)
		: Mybase_(_Message)
		{	// construct from message string
		}
};

/**
 * @brief structure which represents a URI path and or file
 */
class HttpPath {
public:
	HttpPath(const char * data, size_t len);
	~HttpPath();
    icu::UnicodeString        full;                /**< the full path+file (/a/b/c.html) */
    char       * path;                /**< the path (/a/b/) */
    char       * file;                /**< the filename if present (c.html) */
};