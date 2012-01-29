#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <locale.h>

#ifndef HAVE_STRCASECMP
namespace scm{
	int
		strcasecmp_l(const char *s1, const char *s2, _locale_t locale)
	{
		const unsigned char
			*us1 = (const unsigned char *)s1,
			*us2 = (const unsigned char *)s2;        

		while (_tolower_l(*us1, locale) == _tolower_l(*us2++, locale))
			if (*us1++ == '\0')
				return (0);
		return (_tolower_l(*us1, locale) - _tolower_l(*--us2, locale));
	}
	int
		strcasecmp(const char *s1, const char *s2)
	{
		return strcasecmp_l(s1, s2, _get_current_locale());
	}

	int
		strncasecmp_l(const char *s1, const char *s2, size_t n, _locale_t locale)
	{
		if (n != 0) {
			const  unsigned char
				*us1 = (const unsigned char *)s1,
				*us2 = (const  unsigned char *)s2;

			do {
				if (_tolower_l(*us1, locale) != _tolower_l(*us2++, locale))
					return (_tolower_l(*us1, locale) - _tolower_l(*--us2, locale));
				if (*us1++ == '\0')
					break;
			} while (--n != 0);
		}
		return (0);
	}

	int strncasecmp(const char *s1, const char *s2, size_t n)
	{
		return strncasecmp_l(s1, s2, n, _get_current_locale());
	}
}
#endif
