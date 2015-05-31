#ifndef _WIMLIB_XML_H
#define _WIMLIB_XML_H

#include "wimlib/types.h"

struct wim_info;

/*****************************************************************************/

extern int
xml_parse(const void *xml_data, size_t xml_len, struct wim_info **info_ret);

#define WIM_TOTALBYTES_USE_EXISTING  ((u64)0 - 1)
#define WIM_TOTALBYTES_OMIT          ((u64)0 - 2)

extern int
xml_prepare(struct wim_info *info, int image, u64 total_bytes,
	    void **xml_data_ret, size_t *xml_len_ret);

extern void
xml_free_wim_info(struct wim_info *info);

/*****************************************************************************/

extern int
xml_add_image(struct wim_info *info, int image, const tchar *name);

extern void
xml_delete_image(struct wim_info *info, int image);

extern int
xml_export_image(const struct wim_info *old_wim_info, int image,
		 struct wim_info **new_wim_info_p,
		 const tchar *dest_image_name,
		 const tchar *dest_image_description);

extern void
xml_update_image(struct wim_info *info, int image);

/*****************************************************************************/

extern u64
xml_get_total_bytes(const struct wim_info *info);

extern u64
xml_get_image_hard_link_bytes(const struct wim_info *info, int image);

extern u64
xml_get_image_total_bytes(const struct wim_info *info, int image);

extern bool
xml_get_image_wimboot(const struct wim_info *info, int image);

extern size_t
xml_get_max_image_name_len(const struct wim_info *info);

extern void
xml_set_image_wimboot(struct wim_info *info, int image, bool value);

/*****************************************************************************/

extern void
xml_print_image_info(const struct wim_info *wim_info, int image);

/*****************************************************************************/

extern void
xml_global_init(void);

extern void
xml_global_cleanup(void);

extern void
xml_set_memory_allocator(void *(*malloc_func)(size_t),
			 void (*free_func)(void *),
			 void *(*realloc_func)(void *, size_t));

#endif /* _WIMLIB_XML_H */
