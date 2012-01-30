#pragma once

#include <stdexcept>


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
    char       * full;                /**< the full path+file (/a/b/c.html) */
    char       * path;                /**< the path (/a/b/) */
    char       * file;                /**< the filename if present (c.html) */
    char       * match_start;
    char       * match_end;
    unsigned int matched_soff;        /**< offset of where the uri starts
                                       *   mainly used for regex matching
                                       */
    unsigned int matched_eoff;        /**< offset of where the uri ends
                                       *   mainly used for regex matching
                                       */
};