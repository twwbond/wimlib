#ifndef _WIMLIB_TEXTFILE_H_
#define _WIMLIB_TEXTFILE_H_

#include "wimlib/types.h"

struct string_set {
	tchar **strings;
	size_t num_strings;
	size_t num_alloc_strings;
};

#define STRING_SET_INITIALIZER \
	{ .strings = NULL, .num_strings = 0, .num_alloc_strings = 0, }

#define STRING_SET(_strings) \
	struct string_set _strings = STRING_SET_INITIALIZER

typedef int (*line_mangle_t)(tchar *line, const tchar *filename,
			     unsigned long line_no);

struct text_file_section {
	const tchar *name;
	struct string_set *strings;
};

#define LOAD_TEXT_FILE_REMOVE_QUOTES 0x00000001
#define LOAD_TEXT_FILE_NO_WARNINGS   0x00000002

extern int
do_load_text_file(const tchar *path,
		  const void *buf, size_t bufsize, void **mem_ret,
		  const struct text_file_section *pos_sections,
		  int num_pos_sections, int flags,
		  line_mangle_t mangle_line);

static inline int
load_text_file(const tchar *path, void **mem_ret,
	       const struct text_file_section *pos_sections,
	       int num_pos_sections, line_mangle_t mangle_line)
{
	return do_load_text_file(path, NULL, 0, mem_ret,
				 pos_sections, num_pos_sections,
				 LOAD_TEXT_FILE_REMOVE_QUOTES, mangle_line);
}

#endif /* _WIMLIB_TEXTFILE_H_ */
