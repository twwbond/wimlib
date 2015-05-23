#ifndef _WIMLIB_UNICODE_H
#define _WIMLIB_UNICODE_H

#include <string.h>

#include "wimlib/error.h"
#include "wimlib/util.h"
#include "wimlib/types.h"

/* Unicode parse mode  */
enum ucs_parse_mode {

	/* Fail if not valid Unicode  */
	UCS_STRICT,

	/* Replace bad sequences with replacement character (U+FFFD)  */
	UCS_REPLACE,
};

extern int
utf8_to_utf16le(const char *in, utf16lechar **out_ret,
		size_t *out_nbytes_ret, enum ucs_parse_mode mode);

extern int
utf16le_to_utf8(const utf16lechar *in, char **out_ret,
		size_t *out_nbytes_ret, enum ucs_parse_mode mode);

static inline int
tstr_to_tstr(const tchar *in, tchar **out_ret,
	     size_t *out_nbytes_ret, enum ucs_parse_mode mode)
{
	size_t nbytes = tstrlen(in) * sizeof(tchar);
	*out_ret = memdup(in, nbytes + sizeof(tchar));
	if (unlikely(!*out_ret))
		return WIMLIB_ERR_NOMEM;
	if (out_nbytes_ret)
		*out_nbytes_ret = nbytes;
	return 0;
}

#if TCHAR_IS_UTF16LE

/* tstr(UTF-16LE) <=> UTF-16LE  */
#  define tstr_to_utf16le	tstr_to_tstr
#  define utf16le_to_tstr	tstr_to_tstr

/* tstr(UTF-16LE) <=> UTF-8  */
#  define tstr_to_utf8		utf16le_to_utf8
#  define utf8_to_tstr		utf8_to_utf16le

#else

/* tstr(UTF-8) <=> UTF-16LE  */
#  define tstr_to_utf16le	utf8_to_utf16le
#  define utf16le_to_tstr	utf16le_to_utf8

/* tstr(UTF-8) <=> UTF-8  */
#  define tstr_to_utf8		tstr_to_tstr
#  define utf8_to_tstr		tstr_to_tstr

#endif

/* tstr_get_utf16le() - Convert a string in the platform-dependent encoding to
 * UTF-16LE, but if both encodings are UTF-16LE, simply re-use the string.
 * Release with tstr_put_utf16le() when done.  */
#if TCHAR_IS_UTF16LE
static inline int
tstr_get_utf16le(const tchar *in, utf16lechar **out_ret,
		 size_t *out_nbytes_ret, enum ucs_parse_mode mode);
{
	/* No conversion or copy needed  */
	*out_ret = in;
	if (out_nbytes_ret)
		*out_nbytes_ret = utf16le_len_bytes(in);
	return 0;
}
#else
#  define tstr_get_utf16le utf8_to_utf16le
#endif

/* Release a string acquired with tstr_get_utf16le().  */
static inline void
tstr_put_utf16le(utf16lechar *ustr)
{
#if !TCHAR_IS_UTF16LE
	FREE(ustr);
#endif
}

/* utf16le_get_tstr() - convert a UTF16-LE string to the platform-dependent
 * encoding, but if both encodings are UTF-16LE, simply re-use the string.
 * Release with utf16le_put_tstr() when done.  */
#if TCHAR_IS_UTF16LE
#  define utf16le_get_tstr tstr_get_utf16le
#else
#  define utf16le_get_tstr utf16le_to_utf8
#endif

/* Release a string acquired with utf16le_get_tstr().  */
static inline void
utf16le_put_tstr(tchar *tstr)
{
#if !TCHAR_IS_UTF16LE
	FREE(tstr);
#endif
}


/* UTF-16LE utility functions  */

extern void
init_upcase(void);

extern int
cmp_utf16le_strings(const utf16lechar *s1, size_t n1,
		    const utf16lechar *s2, size_t n2,
		    bool ignore_case);

extern int
cmp_utf16le_strings_z(const utf16lechar *s1, const utf16lechar *s2,
		      bool ignore_case);

extern utf16lechar *
utf16le_dupz(const void *ustr, size_t usize);

extern utf16lechar *
utf16le_dup(const utf16lechar *ustr);

extern size_t
utf16le_len_bytes(const utf16lechar *s);

extern size_t
utf16le_len_chars(const utf16lechar *s);


#endif /* _WIMLIB_UNICODE_H */
