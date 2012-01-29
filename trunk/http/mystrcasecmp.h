#pragma once

namespace scm{
	/** compare strings, ignoring case */
	int strcasecmp(const char *s1, const char *s2);
	/** compare strings, ignoring case , at most n characters*/
	int strncasecmp(const char *s1, const char *s2, size_t n);
}