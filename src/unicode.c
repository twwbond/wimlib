/*
 * unicode.c
 *
 * UTF-8 and UTF-16LE conversion and utility functions.
 *
 * Author:  Eric Biggers
 * Year:    2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <string.h>

#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/unicode.h"
#include "wimlib/util.h"

/*****************************************************************************/

static inline int
utf8_decode_codepoint(const void *_in, u32 *c_ret)
{
	const u8 *in = _in;

	if (in[0] < 0x80) {
		/* Single-byte sequence  */
		*c_ret = *in;
		return 1;
	}

	if (unlikely(in[0] < 0xC2))
		goto invalid;

	if (in[0] < 0xE0) {
		/* 2-byte sequence: 11 data bits [0x0000-0x07FF], but 0x00-0x7F
		 * are excluded by in[0] < 0xC2 instead of in[0] < 0xC0  */
		if (unlikely((in[1] & 0xC0) != 0x80))
			goto invalid;

		*c_ret = ((u32)(in[0] & 0x1F) << 6) |	/* 5 bits */
			 ((u32)(in[1] & 0x3F) << 0);	/* 6 bits */

		return 2;
	}
	
	if (in[0] < 0xF0) {
		/* 3-byte sequence: 16 data bits [0x0000-0xFFFF], but anything
		 * below 0x0800 is invalid as it must have been encoded in 2
		 * bytes, and anything in [0xD800-0xDFFF] is invalid as it is
		 * reserved for use in UTF-16.  */
		if (unlikely((in[1] & 0xC0) != 0x80 ||
			     (in[2] & 0xC0) != 0x80))
			goto invalid;

		*c_ret = ((u32)(in[0] & 0x0F) << 12) |	/* 4 bits */
			 ((u32)(in[1] & 0x3F) << 6) |	/* 6 bits */
			 ((u32)(in[2] & 0x3F) << 0);	/* 6 bits */

		if (unlikely(*c_ret <= 0x7FF ||
			     (*c_ret >= 0xD800 && *c_ret <= 0xDFFF)))
			goto invalid;

		return 3;
	}

	if (in[0] < 0xF8) {
		/* 4-byte sequence: 21 data bits [0x000000-0x1FFFFF], but only
		 * [0x010000-0x10FFFF] is allowed  */
		if (unlikely((in[1] & 0xC0) != 0x80 ||
			     (in[2] & 0xC0) != 0x80 ||
			     (in[3] & 0xC0) != 0x80))
			goto invalid;

		*c_ret = ((u32)(in[0] & 0x07) << 18) |	/* 3 bits */
			 ((u32)(in[1] & 0x3F) << 12) |	/* 6 bits */
			 ((u32)(in[2] & 0x3F) << 6);	/* 6 bits */
			 ((u32)(in[3] & 0x3F) << 0);	/* 6 bits */

		if (unlikely(*c_ret <= 0xFFFF || *c_ret > 0x10FFFF))
			goto invalid;

		return 4;
	}

	goto invalid;

invalid:
	*c_ret = 0xFFFFFFFF;
	return 1;
}

static inline void *
utf8_encode_codepoint(u32 c, void *_out)
{
	u8 *out = _out;
	if (c <= 0x7F) {
		*out++ = c;
	} else if (c <= 0x7FF) {
		*out++ = 0xC0 | (c >> 6);
		*out++ = 0x80 | (c & 0x3F);
	} else if (c <= 0xFFFF) {
		*out++ = 0xE0 | (c >> 12);
		*out++ = 0x80 | ((c >> 6) & 0x3F);
		*out++ = 0x80 | (c & 0x3F);
	} else {
		*out++ = 0xF0 | (c >> 18);
		*out++ = 0x80 | ((c >> 12) & 0x3F);
		*out++ = 0x80 | ((c >> 6) & 0x3F);
		*out++ = 0x80 | (c & 0x3F);
	}
	return out;
}

static inline int
utf8_codepoint_length(u32 c)
{
	if (c <= 0x7F)
		return 1;
	if (c <= 0x7FF)
		return 2;
	if (c <= 0xFFFF)
		return 3;
	return 4;
}

/*****************************************************************************/

static inline int
utf16le_decode_codepoint(const void *_in, u32 *c_ret)
{
	const utf16lechar *in = _in;
	u32 c0, c1;

	c0 = le16_to_cpu(in[0]);
	if (likely(c0 < 0xD800 || c0 > 0xDFFF)) {
		*c_ret = c0;
		return 2;
	}

	if (unlikely(c0 >= 0xDC00))
		goto invalid;

	c1 = le16_to_cpu(in[1]);

	if (unlikely(c1 < 0xDC00 || c1 > 0xDFFF))
		goto invalid;

	*c_ret = 0x10000 + (((u32)(c0 - 0xD800) << 10) | (u32)(c1 - 0xDC00));
	return 4;

invalid:
	*c_ret = 0xFFFFFFFF;
	return 2;
}

static inline void *
utf16le_encode_codepoint(u32 c, void *_out)
{
	utf16lechar *out = _out;
	if (c <= 0xFFFF) {
		*out++ = cpu_to_le16(c);
	} else {
		c -= 0x10000;
		*out++ = cpu_to_le16(0xD800 + (c >> 10));
		*out++ = cpu_to_le16(0xDC00 + (c & 0x3FF));
	}
	return out;
}

static inline int
utf16le_codepoint_length(u32 c)
{
	if (c <= 0xFFFF)
		return 2;
	return 4;
}

/*****************************************************************************/

/*
 * Decode the next Unicode codepoint from the string at @in.  Return the number
 * of bytes consumed and write the codepoint to @c_ret.  If invalid, bytes will
 * still be consumed but the codepoint will set to the special value 0xFFFFFFFF.
 */
typedef int (*decode_codepoint_fn)(const void *in, u32 *c_ret);

/* Encode the Unicode codepoint @c, which must be valid, as a byte sequence at
 * @out.  Return a pointer to the next byte to write.  */
typedef void *(*encode_codepoint_fn)(u32 c, void *out);

/* Return the number of bytes needed to encode the Unicode codepoint @c, which
 * must be valid, as a byte sequence.  */
typedef int (*codepoint_length_fn)(u32 c);

static inline ssize_t
compute_output_size(const void *_in, enum ucs_parse_mode mode,
		    decode_codepoint_fn decode_codepoint,
		    codepoint_length_fn get_codepoint_length)
{
	const u8 *in = _in;
	size_t out_nbytes = 0;
	u32 c;
	do {
		in += (*decode_codepoint)(in, &c);
		if (unlikely(c == 0xFFFFFFFF)) {
			/* Invalid  */
			if (mode == UCS_STRICT) {
				errno = EILSEQ;
				return -1;
			}
			c = 0xFFFD; /* replacement character */
		}
		out_nbytes += (*get_codepoint_length)(c);
	} while (c != 0);
	return out_nbytes;
}

static inline void
convert_buf(const void *_in, void *out,
	    decode_codepoint_fn decode_codepoint,
	    encode_codepoint_fn encode_codepoint)
{
	const u8 *in = _in;
	u32 c;
	do {
		in += (*decode_codepoint)(in, &c);
		if (unlikely(c == 0xFFFFFFFF))
			c = 0xFFFD;
		out = (*encode_codepoint)(c, out);
	} while (c != 0);
}

static inline ssize_t
convert(const void *in, void **out_ret, enum ucs_parse_mode mode,
	decode_codepoint_fn decode_codepoint,
	codepoint_length_fn get_codepoint_length,
	encode_codepoint_fn encode_codepoint)
{
	ssize_t out_nbytes;
	void *out;
	
	out_nbytes = compute_output_size(in, mode, decode_codepoint,
					 get_codepoint_length);
	if (unlikely(out_nbytes < 0))
		return out_nbytes;

	out = MALLOC(out_nbytes);
	if (unlikely(!out))
		return -1;

	convert_buf(in, out, decode_codepoint, encode_codepoint);
	*out_ret = out;
	return out_nbytes;
}

/*****************************************************************************/

int
utf8_to_utf16le(const char *in, utf16lechar **out_ret,
		size_t *out_nbytes_ret, enum ucs_parse_mode mode)
{
	void *out;
	ssize_t out_nbytes;
	
	out_nbytes = convert(in, &out, mode, utf8_decode_codepoint,
			     utf16le_codepoint_length, utf16le_encode_codepoint);
	if (unlikely(out_nbytes < 0)) {
		if (errno == EILSEQ)
			return WIMLIB_ERR_INVALID_UTF8_STRING;
		return WIMLIB_ERR_NOMEM;
	}
	*out_ret = out;
	if (out_nbytes_ret)
		*out_nbytes_ret = out_nbytes - sizeof(utf16lechar);
	return 0;
}

int
utf16le_to_utf8(const utf16lechar *in, char **out_ret,
		size_t *out_nbytes_ret, enum ucs_parse_mode mode)
{
	void *out;
	ssize_t out_nbytes;
	
	out_nbytes = convert(in, &out, mode, utf16le_decode_codepoint,
			     utf8_codepoint_length, utf8_encode_codepoint);
	if (unlikely(out_nbytes < 0)) {
		if (errno == EILSEQ)
			return WIMLIB_ERR_INVALID_UTF16_STRING;
		return WIMLIB_ERR_NOMEM;
	}
	*out_ret = out;
	if (out_nbytes_ret)
		*out_nbytes_ret = out_nbytes - sizeof(char);
	return 0;
}

/*****************************************************************************/

/* A table that maps UCS-2 characters to their upper case equivalents.
 * Note: this is only an approximation of real UTF-16 case folding.  */
static u16 upcase[65536];

void
init_upcase(void)
{
	/* This is the table used in NTFS volumes formatted by Windows 10.
	 * It was compressed by tools/compress_upcase_table.c.  */
	static const u16 upcase_compressed[] = {
		0x0000, 0x0000, 0x0060, 0x0000, 0x0000, 0xffe0, 0x0019, 0x0061,
		0x0061, 0x0000, 0x001b, 0x005d, 0x0008, 0x0060, 0x0000, 0x0079,
		0x0000, 0x0000, 0x0000, 0xffff, 0x002f, 0x0100, 0x0002, 0x0000,
		0x0007, 0x012b, 0x0011, 0x0121, 0x002f, 0x0103, 0x0006, 0x0101,
		0x0000, 0x00c3, 0x0006, 0x0131, 0x0007, 0x012e, 0x0004, 0x0000,
		0x0003, 0x012f, 0x0000, 0x0061, 0x0004, 0x0130, 0x0000, 0x00a3,
		0x0003, 0x0000, 0x0000, 0x0082, 0x000b, 0x0131, 0x0006, 0x0189,
		0x0008, 0x012f, 0x0007, 0x012e, 0x0000, 0x0038, 0x0006, 0x0000,
		0x0000, 0xfffe, 0x0007, 0x01c4, 0x000f, 0x0101, 0x0000, 0xffb1,
		0x0015, 0x011e, 0x0004, 0x01cc, 0x002a, 0x0149, 0x0014, 0x0149,
		0x0007, 0x0000, 0x0009, 0x018c, 0x000b, 0x0138, 0x0000, 0x2a1f,
		0x0000, 0x2a1c, 0x0000, 0x0000, 0x0000, 0xff2e, 0x0000, 0xff32,
		0x0000, 0x0000, 0x0000, 0xff33, 0x0000, 0xff33, 0x0000, 0x0000,
		0x0000, 0xff36, 0x0000, 0x0000, 0x0000, 0xff35, 0x0004, 0x0000,
		0x0002, 0x0257, 0x0000, 0x0000, 0x0000, 0xff31, 0x0004, 0x0000,
		0x0000, 0xff2f, 0x0000, 0xff2d, 0x0000, 0x0000, 0x0000, 0x29f7,
		0x0003, 0x0000, 0x0002, 0x0269, 0x0000, 0x29fd, 0x0000, 0xff2b,
		0x0002, 0x0000, 0x0000, 0xff2a, 0x0007, 0x0000, 0x0000, 0x29e7,
		0x0002, 0x0000, 0x0000, 0xff26, 0x0005, 0x027e, 0x0003, 0x027e,
		0x0000, 0xffbb, 0x0000, 0xff27, 0x0000, 0xff27, 0x0000, 0xffb9,
		0x0005, 0x0000, 0x0000, 0xff25, 0x0065, 0x007b, 0x0079, 0x0293,
		0x0008, 0x012d, 0x0003, 0x019c, 0x0002, 0x037b, 0x002e, 0x0000,
		0x0000, 0xffda, 0x0000, 0xffdb, 0x0002, 0x03ad, 0x0012, 0x0060,
		0x000a, 0x0060, 0x0000, 0xffc0, 0x0000, 0xffc1, 0x0000, 0xffc1,
		0x0008, 0x0000, 0x0000, 0xfff8, 0x001a, 0x0118, 0x0000, 0x0007,
		0x0008, 0x018d, 0x0009, 0x0233, 0x0046, 0x0035, 0x0006, 0x0061,
		0x0000, 0xffb0, 0x000f, 0x0450, 0x0025, 0x010e, 0x000a, 0x036b,
		0x0032, 0x048b, 0x000e, 0x0100, 0x0000, 0xfff1, 0x0037, 0x048a,
		0x0026, 0x0465, 0x0034, 0x0000, 0x0000, 0xffd0, 0x0025, 0x0561,
		0x00de, 0x0293, 0x1714, 0x0587, 0x0000, 0x8a04, 0x0003, 0x0000,
		0x0000, 0x0ee6, 0x0087, 0x02ee, 0x0092, 0x1e01, 0x0069, 0x1df7,
		0x0000, 0x0008, 0x0007, 0x1f00, 0x0008, 0x0000, 0x000e, 0x1f02,
		0x0008, 0x1f0e, 0x0010, 0x1f06, 0x001a, 0x1f06, 0x0002, 0x1f0f,
		0x0007, 0x1f50, 0x0017, 0x1f19, 0x0000, 0x004a, 0x0000, 0x004a,
		0x0000, 0x0056, 0x0003, 0x1f72, 0x0000, 0x0064, 0x0000, 0x0064,
		0x0000, 0x0080, 0x0000, 0x0080, 0x0000, 0x0070, 0x0000, 0x0070,
		0x0000, 0x007e, 0x0000, 0x007e, 0x0028, 0x1f1e, 0x000c, 0x1f06,
		0x0000, 0x0000, 0x0000, 0x0009, 0x000f, 0x0000, 0x000d, 0x1fb3,
		0x000d, 0x1f44, 0x0008, 0x1fcd, 0x0006, 0x03f2, 0x0015, 0x1fbb,
		0x014e, 0x0587, 0x0000, 0xffe4, 0x0021, 0x0000, 0x0000, 0xfff0,
		0x000f, 0x2170, 0x000a, 0x0238, 0x0346, 0x0587, 0x0000, 0xffe6,
		0x0019, 0x24d0, 0x0746, 0x0587, 0x0026, 0x0561, 0x000b, 0x057e,
		0x0004, 0x012f, 0x0000, 0xd5d5, 0x0000, 0xd5d8, 0x000c, 0x022e,
		0x000e, 0x03f8, 0x006e, 0x1e33, 0x0011, 0x0000, 0x0000, 0xe3a0,
		0x0025, 0x2d00, 0x17f2, 0x0587, 0x6129, 0x2d26, 0x002e, 0x0201,
		0x002a, 0x1def, 0x0098, 0xa5b7, 0x0040, 0x1dff, 0x000e, 0x0368,
		0x000d, 0x022b, 0x034c, 0x2184, 0x5469, 0x2d26, 0x007f, 0x0061,
		0x0040, 0x0000,
	};

	/* Simple LZ decoder  */
	const u16 *in_next = upcase_compressed;
	for (u32 i = 0; i < ARRAY_LEN(upcase); ) {
		u16 length = *in_next++;
		u16 src_pos = *in_next++;
		if (length == 0) {
			/* Literal */
			upcase[i++] = src_pos;
		} else {
			/* Match */
			do {
				upcase[i++] = upcase[src_pos++];
			} while (--length);
		}
	}

	/* Delta filter  */
	for (u32 i = 0; i < ARRAY_LEN(upcase); i++)
		upcase[i] += i;
}

/* Compare UTF-16LE strings case-sensitively (%ignore_case == false) or
 * case-insensitively (%ignore_case == true).
 *
 * This is implemented using the default upper-case table used by NTFS.  It does
 * not handle all possible cases allowed by UTF-16LE.  For example, different
 * normalizations of the same sequence of "characters" are not considered equal.
 * It hopefully does the right thing most of the time though.  */
int
cmp_utf16le_strings(const utf16lechar *s1, size_t n1,
		    const utf16lechar *s2, size_t n2,
		    bool ignore_case)
{
	size_t n = min(n1, n2);

	if (ignore_case) {
		for (size_t i = 0; i < n; i++) {
			u16 c1 = upcase[le16_to_cpu(s1[i])];
			u16 c2 = upcase[le16_to_cpu(s2[i])];
			if (c1 != c2)
				return (c1 < c2) ? -1 : 1;
		}
	} else {
		for (size_t i = 0; i < n; i++) {
			u16 c1 = le16_to_cpu(s1[i]);
			u16 c2 = le16_to_cpu(s2[i]);
			if (c1 != c2)
				return (c1 < c2) ? -1 : 1;
		}
	}
	if (n1 == n2)
		return 0;
	return (n1 < n2) ? -1 : 1;
}

/* Like cmp_utf16le_strings(), but assumes the strings are null terminated.  */
int
cmp_utf16le_strings_z(const utf16lechar *s1, const utf16lechar *s2,
		      bool ignore_case)
{
	if (ignore_case) {
		for (;;) {
			u16 c1 = upcase[le16_to_cpu(*s1)];
			u16 c2 = upcase[le16_to_cpu(*s2)];
			if (c1 != c2)
				return (c1 < c2) ? -1 : 1;
			if (c1 == 0)
				return 0;
			s1++, s2++;
		}
	} else {
		while (*s1 && *s1 == *s2)
			s1++, s2++;
		if (*s1 == *s2)
			return 0;
		return (le16_to_cpu(*s1) < le16_to_cpu(*s2)) ? -1 : 1;
	}
}

/* Duplicate a UTF-16LE string.  The input string might not be null terminated
 * and might be misaligned, but the returned string is guaranteed to be null
 * terminated and properly aligned.  */
utf16lechar *
utf16le_dupz(const void *ustr, size_t usize)
{
	utf16lechar *dup = MALLOC(usize + sizeof(utf16lechar));
	if (dup) {
		memcpy(dup, ustr, usize);
		dup[usize / sizeof(utf16lechar)] = 0;
	}
	return dup;
}

/* Duplicate a null-terminated UTF-16LE string.  */
utf16lechar *
utf16le_dup(const utf16lechar *ustr)
{
	const utf16lechar *p = ustr;
	while (*p++)
		;
	return memdup(ustr, (const u8 *)p - (const u8 *)ustr);
}

/* Return the length, in bytes, of a UTF-null terminated UTF-16 string,
 * excluding the null terminator.  */
size_t
utf16le_len_bytes(const utf16lechar *s)
{
	const utf16lechar *p = s;
	while (*p)
		p++;
	return (p - s) * sizeof(utf16lechar);
}

/* Return the length, in UTF-16 coding units, of a UTF-null terminated UTF-16
 * string, excluding the null terminator.  */
size_t
utf16le_len_chars(const utf16lechar *s)
{
	return utf16le_len_bytes(s) / sizeof(utf16lechar);
}
