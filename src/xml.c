/*
 * xml.c
 *
 * Deals with the XML information in WIM files.  Uses the C library libxml2.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <libxml/encoding.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlwriter.h>
#include <string.h>

#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/timestamp.h"
#include "wimlib/xml.h"
#include "wimlib/write.h"

/* Wrapper around the XML data for a WIM file  */
struct wim_info {
	xmlDocPtr doc;
};

/* Architecture constants are from w64 mingw winnt.h  */
#define PROCESSOR_ARCHITECTURE_INTEL 0
#define PROCESSOR_ARCHITECTURE_MIPS 1
#define PROCESSOR_ARCHITECTURE_ALPHA 2
#define PROCESSOR_ARCHITECTURE_PPC 3
#define PROCESSOR_ARCHITECTURE_SHX 4
#define PROCESSOR_ARCHITECTURE_ARM 5
#define PROCESSOR_ARCHITECTURE_IA64 6
#define PROCESSOR_ARCHITECTURE_ALPHA64 7
#define PROCESSOR_ARCHITECTURE_MSIL 8
#define PROCESSOR_ARCHITECTURE_AMD64 9
#define PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 10

/* Returns a statically allocated string that is a string representation of the
 * architecture number. */
static const tchar *
get_arch(int arch)
{
	switch (arch) {
	case PROCESSOR_ARCHITECTURE_INTEL:
		return T("x86");
	case PROCESSOR_ARCHITECTURE_MIPS:
		return T("MIPS");
	case PROCESSOR_ARCHITECTURE_ARM:
		return T("ARM");
	case PROCESSOR_ARCHITECTURE_IA64:
		return T("ia64");
	case PROCESSOR_ARCHITECTURE_AMD64:
		return T("x86_64");
	default:
		return T("unknown");
	}
}


/* Iterate through the children of an xmlNode. */
#define for_node_child(parent, child)	\
	for (child = parent->children; child != NULL; child = child->next)

/* Utility functions for xmlNodes */
static inline bool
node_is_element(xmlNode *node)
{
	return node->type == XML_ELEMENT_NODE;
}

static inline bool
node_is_text(xmlNode *node)
{
	return node->type == XML_TEXT_NODE;
}

static inline bool
node_name_is(xmlNode *node, const char *name)
{
	/* For now, both upper case and lower case element names are accepted. */
	return strcasecmp((const char *)node->name, name) == 0;
}

static u64
node_get_number(const xmlNode *u64_node, int base)
{
	xmlNode *child;
	for_node_child(u64_node, child)
		if (node_is_text(child))
			return strtoull(child->content, NULL, base);
	return 0;
}

/* Finds the text node that is a child of an element node and returns its
 * content converted to a 64-bit unsigned integer.  Returns 0 if no text node is
 * found. */
static u64
node_get_u64(const xmlNode *u64_node)
{
	return node_get_number(u64_node, 10);
}

/* Like node_get_u64(), but expects a number in base 16. */
static u64
node_get_hex_u64(const xmlNode *u64_node)
{
	return node_get_number(u64_node, 16);
}

static int
node_get_string(const xmlNode *string_node, tchar **tstr_ret)
{
	xmlNode *child;

	if (*tstr_ret)
		return 0;

	for_node_child(string_node, child)
		if (node_is_text(child) && child->content)
			return utf8_to_tstr_simple(child->content, tstr_ret);
	return 0;
}

/* Returns the timestamp from a time node.  It has child elements <HIGHPART> and
 * <LOWPART> that are then used to construct a 64-bit timestamp. */
static u64
node_get_timestamp(const xmlNode *time_node)
{
	u32 high_part = 0;
	u32 low_part = 0;
	xmlNode *child;
	for_node_child(time_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "HIGHPART"))
			high_part = node_get_hex_u64(child);
		else if (node_name_is(child, "LOWPART"))
			low_part = node_get_hex_u64(child);
	}
	return (u64)low_part | ((u64)high_part << 32);
}

u64
wim_info_get_total_bytes(const struct wim_info *info)
{
#if 0
	if (info)
		return info->total_bytes;
#endif
	return 0;
}

u64
wim_info_get_image_hard_link_bytes(const struct wim_info *info, int image)
{
#if 0
	if (info)
		return info->images[image - 1].hard_link_bytes;
#endif
	return 0;
}

u64
wim_info_get_image_total_bytes(const struct wim_info *info, int image)
{
#if 0
	if (info)
		return info->images[image - 1].total_bytes;
#endif
	return 0;
}

unsigned
wim_info_get_num_images(const struct wim_info *info)
{
#if 0
	if (info)
		return info->num_images;
#endif
	return 0;
}

void
wim_info_set_wimboot(struct wim_info *info, int image, bool value)
{
#if 0
	info->images[image - 1].wimboot = value;
#endif
}

bool
wim_info_get_wimboot(const struct wim_info *info, int image)
{
	return false;
#if 0
	return info->images[image - 1].wimboot;
#endif
}


/* Copies the XML information for an image between WIM files.
 *
 * @dest_image_name and @dest_image_description are ignored if they are NULL;
 * otherwise, they are used to override the image name and/or image description
 * from the XML data in the source WIM file.
 *
 * On failure, WIMLIB_ERR_NOMEM is returned and no changes are made.  Otherwise,
 * 0 is returned and the WIM information at *new_wim_info_p is modified.
 */
int
xml_export_image(const struct wim_info *old_wim_info,
		 int image,
		 struct wim_info **new_wim_info_p,
		 const tchar *dest_image_name,
		 const tchar *dest_image_description)
{
	return WIMLIB_ERR_UNSUPPORTED;
#if 0
	struct wim_info *new_wim_info;
	struct image_info *image_info;
	int ret;

	DEBUG("Copying XML data between WIM files for source image %d.", image);

	wimlib_assert(old_wim_info != NULL);
	wimlib_assert(image >= 1 && image <= old_wim_info->num_images);

	if (*new_wim_info_p) {
		new_wim_info = *new_wim_info_p;
	} else {
		new_wim_info = CALLOC(1, sizeof(struct wim_info));
		if (!new_wim_info)
			goto err;
	}

	image_info = add_image_info_struct(new_wim_info);
	if (!image_info)
		goto err;

	ret = clone_image_info(&old_wim_info->images[image - 1], image_info);
	if (ret != 0)
		goto err_destroy_image_info;

	image_info->index = new_wim_info->num_images;

	if (dest_image_name) {
		FREE(image_info->name);
		image_info->name = TSTRDUP(dest_image_name);
		if (!image_info->name)
			goto err_destroy_image_info;
	}
	if (dest_image_description) {
		FREE(image_info->description);
		image_info->description = TSTRDUP(dest_image_description);
		if (!image_info->description)
			goto err_destroy_image_info;
	}
	*new_wim_info_p = new_wim_info;
	return 0;
err_destroy_image_info:
	destroy_image_info(image_info);
err:
	if (new_wim_info != *new_wim_info_p)
		free_wim_info(new_wim_info);
	return WIMLIB_ERR_NOMEM;
#endif
}

/* Removes an image from the XML information. */
void
xml_delete_image(struct wim_info **wim_info_p, int image)
{
	return;
#if 0
	struct wim_info *wim_info;

	wim_info = *wim_info_p;
	wimlib_assert(image >= 1 && image <= wim_info->num_images);
	DEBUG("Deleting image %d from the XML data.", image);

	destroy_image_info(&wim_info->images[image - 1]);

	memmove(&wim_info->images[image - 1],
		&wim_info->images[image],
		(wim_info->num_images - image) * sizeof(struct image_info));

	if (--wim_info->num_images == 0) {
		free_wim_info(wim_info);
		*wim_info_p = NULL;
	} else {
		for (int i = image - 1; i < wim_info->num_images; i++)
			wim_info->images[i].index--;
	}
#endif
}

size_t
xml_get_max_image_name_len(const WIMStruct *wim)
{
	return 0;
#if 0
	size_t max_len = 0;
	for (u32 i = 0; i < wim->hdr.image_count; i++)
		max_len = max(max_len, tstrlen(wim->wim_info->images[i].name));
	return max_len;
#endif
}

#if 0
static int
calculate_dentry_statistics(struct wim_dentry *dentry, void *_info)
{
	struct image_info *info = _info;
	const struct wim_inode *inode = dentry->d_inode;

	if (inode_is_directory(inode))
		info->dir_count++;
	else
		info->file_count++;

	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		const struct blob_descriptor *blob;

		blob = stream_blob(&inode->i_streams[i], info->blob_table);
		if (!blob)
			continue;
		info->total_bytes += blob->size;
		if (!dentry_is_first_in_inode(dentry))
			info->hard_link_bytes += blob->size;
	}
	return 0;
}
#endif

/*
 * Calculate what to put in the <FILECOUNT>, <DIRCOUNT>, <TOTALBYTES>, and
 * <HARDLINKBYTES> elements of the specified WIM image.
 *
 * Note: since these stats are likely to be used for display purposes only, we
 * no longer attempt to duplicate WIMGAPI's weird bugs when calculating them.
 */
void
xml_update_image_info(WIMStruct *wim, int image)
{
	return;
#if 0
	struct image_info *image_info;

	DEBUG("Updating the image info for image %d", image);

	image_info = &wim->wim_info->images[image - 1];

	image_info->file_count      = 0;
	image_info->dir_count       = 0;
	image_info->total_bytes     = 0;
	image_info->hard_link_bytes = 0;
	image_info->blob_table = wim->blob_table;

	for_dentry_in_tree(wim->image_metadata[image - 1]->root_dentry,
			   calculate_dentry_statistics,
			   image_info);
	image_info->last_modification_time = now_as_wim_timestamp();
#endif
}

/* Adds an image to the XML information. */
int
xml_add_image(struct wim_info *info, int image, const tchar *name)
{
	return WIMLIB_ERR_UNSUPPORTED;
#if 0
	struct wim_info *wim_info;
	struct image_info *image_info;

	wimlib_assert(name != NULL);

	/* If this is the first image, allocate the struct wim_info.  Otherwise
	 * use the existing struct wim_info. */
	if (wim->wim_info) {
		wim_info = wim->wim_info;
	} else {
		wim_info = CALLOC(1, sizeof(struct wim_info));
		if (!wim_info)
			return WIMLIB_ERR_NOMEM;
	}

	image_info = add_image_info_struct(wim_info);
	if (!image_info)
		goto out_free_wim_info;

	if (!(image_info->name = TSTRDUP(name)))
		goto out_destroy_image_info;

	wim->wim_info = wim_info;
	image_info->index = wim_info->num_images;
	image_info->creation_time = now_as_wim_timestamp();
	xml_update_image_info(wim, image_info->index);
	return 0;

out_destroy_image_info:
	destroy_image_info(image_info);
	wim_info->num_images--;
out_free_wim_info:
	if (wim_info != wim->wim_info)
		FREE(wim_info);
	return WIMLIB_ERR_NOMEM;
#endif
}

/* Prints information about the specified image from struct wim_info structure.
 * */
void
print_image_info(const struct wim_info *wim_info, int image)
{
#if 0
	const struct image_info *image_info;
	const tchar *desc;
	tchar buf[50];

	wimlib_assert(image >= 1 && image <= wim_info->num_images);

	image_info = &wim_info->images[image - 1];

	tprintf(T("Index:                  %d\n"), image_info->index);
	tprintf(T("Name:                   %"TS"\n"), image_info->name);

	/* Always print the Description: part even if there is no
	 * description. */
	if (image_info->description)
		desc = image_info->description;
	else
		desc = T("");
	tprintf(T("Description:            %"TS"\n"), desc);

	if (image_info->display_name) {
		tprintf(T("Display Name:           %"TS"\n"),
			image_info->display_name);
	}

	if (image_info->display_description) {
		tprintf(T("Display Description:    %"TS"\n"),
			image_info->display_description);
	}

	tprintf(T("Directory Count:        %"PRIu64"\n"), image_info->dir_count);
	tprintf(T("File Count:             %"PRIu64"\n"), image_info->file_count);
	tprintf(T("Total Bytes:            %"PRIu64"\n"), image_info->total_bytes);
	tprintf(T("Hard Link Bytes:        %"PRIu64"\n"), image_info->hard_link_bytes);

	wim_timestamp_to_str(image_info->creation_time, buf, sizeof(buf));
	tprintf(T("Creation Time:          %"TS"\n"), buf);

	wim_timestamp_to_str(image_info->last_modification_time, buf, sizeof(buf));
	tprintf(T("Last Modification Time: %"TS"\n"), buf);
	if (image_info->windows_info_exists)
		print_windows_info(&image_info->windows_info);
	if (image_info->flags)
		tprintf(T("Flags:                  %"TS"\n"), image_info->flags);
	tprintf(T("WIMBoot compatible:     %"TS"\n"),
		image_info->wimboot ? T("yes") : T("no"));
	tputchar('\n');
#endif
}

/* Reads the XML data from a WIM file.  */
int
read_wim_xml_data(WIMStruct *wim)
{
	struct wim_info *info;
	void *buf;
	size_t bufsize;
	xmlDocPtr doc;
	int ret;

	ret = wimlib_get_xml_data(wim, &buf, &bufsize);
	if (ret)
		return ret;

	doc = xmlReadMemory(buf, bufsize, NULL, "UTF-16LE", 0);
	FREE(buf);
	if (!doc) {
		ERROR("Unable to parse the WIM XML document");
		return WIMLIB_ERR_XML;
	}

	/* TODO: validate */

	wim->wim_info = MALLOC(sizeof(struct wim_info));
	if (!wim->wim_info) {
		xmlFreeDoc(doc);
		return WIMLIB_ERR_NOMEM;
	}

	wim->wim_info->doc = doc;
	return 0;
}

void
free_wim_info(struct wim_info *info)
{
	if (info) {
		xmlFreeDoc(info->doc);
		FREE(info);
	}
}

/* Prepares an in-memory buffer containing the UTF-16LE XML data for a WIM file.
 *
 * total_bytes is the number to write in <TOTALBYTES>, or
 * WIM_TOTALBYTES_USE_EXISTING to use the existing value in memory, or
 * WIM_TOTALBYTES_OMIT to omit <TOTALBYTES> entirely.
 */
static int
prepare_wim_xml_data(const struct wim_info *info, int image, u64 total_bytes,
		     void **xml_data_ret, size_t *xml_len_ret)
{
	xmlChar *doc_text = NULL;
	int doc_text_len = 0;

	xmlDocDumpMemoryEnc(info->doc, &doc_text, &doc_text_len, "UTF-16LE");

	if (doc_text_len <= 0) {
		ERROR("xmlDocDumpMemoryEnc() failed");
		return WIMLIB_ERR_XML;
	}

	*xml_data_ret = doc_text;
	*xml_len_ret = doc_text_len;
	return 0;
}

/* Writes the XML data to a WIM file.  */
int
write_wim_xml_data(WIMStruct *wim, int image, u64 total_bytes,
		   struct wim_reshdr *out_reshdr,
		   int write_resource_flags)
{
	int ret;
	void *xml_data;
	size_t xml_len;

	ret = prepare_wim_xml_data(wim->wim_info, image, total_bytes,
				   &xml_data, &xml_len);
	if (ret)
		return ret;

	/* Write the XML data uncompressed.  Although wimlib can handle
	 * compressed XML data, MS software cannot.  */
	ret = write_wim_resource_from_buffer(xml_data,
					     xml_len,
					     true,
					     &wim->out_fd,
					     WIMLIB_COMPRESSION_TYPE_NONE,
					     0,
					     out_reshdr,
					     NULL,
					     write_resource_flags);
	FREE(xml_data);
	return ret;
}

void
xml_set_memory_allocator(void *(*malloc_func)(size_t),
			 void (*free_func)(void *),
			 void *(*realloc_func)(void *, size_t))
{
	xmlMemSetup(free_func, malloc_func, realloc_func, STRDUP);
}

void
xml_global_init(void)
{
	xmlInitParser();
	xmlInitCharEncodingHandlers();
}

void
xml_global_cleanup(void)
{
	xmlCleanupParser();
	xmlCleanupCharEncodingHandlers();
}

/*****************************************************************************/

/* API function documented in wimlib.h  */
WIMLIBAPI const tchar *
wimlib_get_image_name(const WIMStruct *wim, int image)
{
	if (image < 1 || image > wim->hdr.image_count)
		return NULL;
	return T("");
#if 0
	return wim->wim_info->images[image - 1].name;
#endif
}

/* API function documented in wimlib.h  */
WIMLIBAPI const tchar *
wimlib_get_image_description(const WIMStruct *wim, int image)
{
	if (image < 1 || image > wim->hdr.image_count)
		return NULL;
	return NULL;
#if 0
	return wim->wim_info->images[image - 1].description;
#endif
}

/* API function documented in wimlib.h  */
WIMLIBAPI bool
wimlib_image_name_in_use(const WIMStruct *wim, const tchar *name)
{
	if (!name || !*name)
		return false;
#if 0
	for (int i = 1; i <= wim->hdr.image_count; i++)
		if (!tstrcmp(wim->wim_info->images[i - 1].name, name))
			return true;
#endif
	return false;
}


/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_get_xml_data(WIMStruct *wim, void **buf_ret, size_t *bufsize_ret)
{
	const struct wim_reshdr *xml_reshdr;

	if (wim->filename == NULL && filedes_is_seekable(&wim->in_fd))
		return WIMLIB_ERR_NO_FILENAME;

	if (buf_ret == NULL || bufsize_ret == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	xml_reshdr = &wim->hdr.xml_data_reshdr;

	DEBUG("Reading XML data.");
	*bufsize_ret = xml_reshdr->uncompressed_size;
	return wim_reshdr_to_data(xml_reshdr, wim, buf_ret);
}

WIMLIBAPI int
wimlib_extract_xml_data(WIMStruct *wim, FILE *fp)
{
	int ret;
	void *buf;
	size_t bufsize;

	ret = wimlib_get_xml_data(wim, &buf, &bufsize);
	if (ret)
		return ret;

	if (fwrite(buf, 1, bufsize, fp) != bufsize) {
		ERROR_WITH_ERRNO("Failed to extract XML data");
		ret = WIMLIB_ERR_WRITE;
	}
	FREE(buf);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_name(WIMStruct *wim, int image, const tchar *name)
{

	if (name == NULL)
		name = T("");

	if (image < 1 || image > wim->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;

	return WIMLIB_ERR_UNSUPPORTED;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_descripton(WIMStruct *wim, int image,
			    const tchar *description)
{
	return WIMLIB_ERR_UNSUPPORTED;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_flags(WIMStruct *wim, int image, const tchar *flags)
{
	return WIMLIB_ERR_UNSUPPORTED;
}
