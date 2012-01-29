#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "evhtp_path.h"
#include <stdlib.h>
#include <string.h>

char *
my_strndup(const char *str, size_t n)
{
	size_t len;
	char *copy;

	len = strnlen(str, n);
	if ((copy = (char*)malloc(len + 1)) == NULL)
		return (NULL);
	memcpy(copy, str, len);
	copy[len] = '\0';
	return (copy);
}

evhtp_path_s::evhtp_path_s(const char * data, size_t len):full(NULL),match_start(NULL),match_end(NULL),matched_soff(0),matched_eoff(0){
    const char   * data_end = (const char *)(data + len);
    char         * path     = NULL;
    char         * file     = NULL;

    if (len == 0) {
        /*
         * odd situation here, no preceding "/", so just assume the path is "/"
         */
        path = strdup("/");
    } else if (*data != '/') {
        /* request like GET stupid HTTP/1.0, treat stupid as the file, and
         * assume the path is "/"
         */
        path = strdup("/");
        file = my_strndup(data, len);
    } else {
        if (data[len - 1] != '/') {
            /*
             * the last character in data is assumed to be a file, not the end of path
             * loop through the input data backwards until we find a "/"
             */
            size_t i;

            for (i = (len - 1); i != 0; i--) {
                if (data[i] == '/') {
                    /*
                     * we have found a "/" representing the start of the file,
                     * and the end of the path
                     */
                    size_t path_len;
                    size_t file_len;

                    path_len = (size_t)(&data[i] - data) + 1;
                    file_len = (size_t)(data_end - &data[i + 1]);

                    /* check for overflow */
                    if ((const char *)(data + path_len) > data_end) {
						throw PathCorruptedException("PATH Corrupted.. (path_len > len)");
                    }

                    /* check for overflow */
                    if ((const char *)(&data[i + 1] + file_len) > data_end) {
						throw FileCorruptedException("FILE Corrupted.. (file_len > len)");
                    }

                    path = my_strndup(data, path_len);
                    file = my_strndup(&data[i + 1], file_len);

                    break;
                }
            }

            if (i == 0 && data[i] == '/' && !file && !path) {
                /* drops here if the request is something like GET /foo */
                path = strdup("/");

                if (len > 1) {
                    file = my_strndup((const char *)(data + 1), len);
                }
            }
        } else {
            /* the last character is a "/", thus the request is just a path */
            path = my_strndup(data, len);
        }
    }

    if (len != 0) {
        this->full = my_strndup(data, len);
    }

    this->path = path;
    this->file = file;
}

evhtp_path_s::~evhtp_path_s(){
	if (this->full) {
		free(this->full);
	}

	if (this->path) {
		free(this->path);
	}

	if (this->file) {
		free(this->file);
	}

	if (this->match_start) {
		free(this->match_start);
	}

	if (this->match_end) {
		free(this->match_end);
	}
}
