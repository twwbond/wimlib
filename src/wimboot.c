/*
 * wimboot.c
 *
 * Support for creating WIMBoot pointer files.
 *
 * See http://technet.microsoft.com/en-us/library/dn594399.aspx for general
 * information about WIMBoot.
 *
 * Note that WIMBoot pointer files are actually implemented on top of the
 * Windows Overlay File System Filter (WOF).  See wof.h for more info.
 */

/*
 * Copyright (C) 2014 Eric Biggers
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

#ifdef __WIN32__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/win32_common.h"

#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/error.h"
#include "wimlib/wimboot.h"
#include "wimlib/wof.h"

/* Try to attach an instance of the Windows Overlay File System Filter Driver to
 * the specified drive (such as C:)  */
static bool
try_to_attach_wof(const wchar_t *drive)
{
	HMODULE fltlib;
	bool retval = false;

	/* Use FilterAttach() from Fltlib.dll.  */

	fltlib = LoadLibrary(L"Fltlib.dll");

	if (!fltlib) {
		WARNING("Failed to load Fltlib.dll");
		return retval;
	}

	HRESULT (WINAPI *func_FilterAttach)(LPCWSTR lpFilterName,
					    LPCWSTR lpVolumeName,
					    LPCWSTR lpInstanceName,
					    DWORD dwCreatedInstanceNameLength,
					    LPWSTR lpCreatedInstanceName);

	func_FilterAttach = (void *)GetProcAddress(fltlib, "FilterAttach");

	if (func_FilterAttach) {
		HRESULT res;

		res = (*func_FilterAttach)(L"WoF", drive, NULL, 0, NULL);

		if (res == S_OK)
			retval = true;
	} else {
		WARNING("FilterAttach() does not exist in Fltlib.dll");
	}

	FreeLibrary(fltlib);

	return retval;
}

/*
 * Allocate a WOF data source ID for a WIM file.
 *
 * @wim_path
 *	Absolute path to the WIM file.  This must include a drive letter and use
 *	backslash path separators.
 * @wim_guid
 *	GUID of the WIM, from the WIM header.
 * @image
 *	Number of the image in the WIM being applied.
 * @target
 *	Path to the target directory.
 * @data_source_id_ret
 *	On success, an identifier for the backing WIM file will be returned
 *	here.
 *
 * Returns 0 on success, or a positive error code on failure.
 */
int
wimboot_alloc_data_source_id(const wchar_t *wim_path,
			     const u8 wim_guid[GUID_SIZE],
			     int image, const wchar_t *target,
			     u64 *data_source_id_ret)
{
	tchar drive_path[7];
	size_t wim_path_nchars;
	size_t wim_file_name_length;
	void *in;
	size_t insize;
	struct wof_external_info *wof_info;
	struct wim_provider_add_overlay_input *wim_info;
	HANDLE h;
	u64 data_source_id;
	DWORD bytes_returned;
	int ret;
	const wchar_t *prefix = L"\\??\\";
	const size_t prefix_nchars = 4;
	bool tried_to_attach_wof = false;

	ret = win32_get_drive_path(target, drive_path);
	if (ret)
		return ret;

	wimlib_assert(!wcschr(wim_path, L'/'));
	wimlib_assert(wim_path[0] != L'\0' && wim_path[1] == L':');

	wim_path_nchars = wcslen(wim_path);
	wim_file_name_length = sizeof(wchar_t) *
			       (wim_path_nchars + prefix_nchars);

	insize = sizeof(struct wof_external_info) +
		 sizeof(struct wim_provider_add_overlay_input) +
		 wim_file_name_length;

	in = MALLOC(insize);
	if (!in) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	wof_info = (struct wof_external_info *)in;
	wof_info->version = WOF_CURRENT_VERSION;
	wof_info->provider = WOF_PROVIDER_WIM;

	wim_info = (struct wim_provider_add_overlay_input *)(wof_info + 1);
	wim_info->wim_type = WIM_BOOT_NOT_OS_WIM;
	wim_info->wim_index = image;
	wim_info->wim_file_name_offset = offsetof(struct wim_provider_add_overlay_input,
						  wim_file_name);
	wim_info->wim_file_name_length = wim_file_name_length;
	wmemcpy(&wim_info->wim_file_name[0], prefix, prefix_nchars);
	wmemcpy(&wim_info->wim_file_name[prefix_nchars], wim_path, wim_path_nchars);

retry_ioctl:
	h = CreateFile(drive_path, GENERIC_WRITE,
		       FILE_SHARE_VALID_FLAGS, NULL, OPEN_EXISTING,
		       FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		win32_error(GetLastError(),
			    L"Failed to open \"%ls\"", drive_path + 4);
		ret = WIMLIB_ERR_OPEN;
		goto out_free_in;
	}

	if (!DeviceIoControl(h, FSCTL_ADD_OVERLAY,
			     in, insize,
			     &data_source_id, sizeof(data_source_id),
			     &bytes_returned, NULL))
	{
		DWORD err = GetLastError();
		if (err == ERROR_INVALID_FUNCTION) {
			if (!tried_to_attach_wof) {
				CloseHandle(h);
				h = INVALID_HANDLE_VALUE;
				tried_to_attach_wof = true;
				if (try_to_attach_wof(drive_path + 4))
					goto retry_ioctl;
			}
			WARNING("The Windows Overlay File System Filter Driver "
				"is unavailable, so it's not possible on this "
				"system to apply a WIM image in WIMBoot mode. "
				"This is only available on Windows 8.1 "
				"Update 1 and later.");
			ret = WIMLIB_ERR_UNSUPPORTED;
			goto out_close_handle;
		} else {
			win32_error(err, L"Failed to add overlay source \"%ls\" "
				    "to volume \"%ls\"", wim_path, drive_path + 4);
			ret = WIMLIB_ERR_WIMBOOT;
			goto out_close_handle;
		}
	}

	if (bytes_returned != sizeof(data_source_id)) {
		ret = WIMLIB_ERR_WIMBOOT;
		ERROR("Unexpected result size when adding "
		      "overlay source \"%ls\" to volume \"%ls\"",
		      wim_path, drive_path + 4);
		goto out_close_handle;
	}

	*data_source_id_ret = data_source_id;
	ret = 0;
out_close_handle:
	CloseHandle(h);
out_free_in:
	FREE(in);
out:
	return ret;
}


/*
 * Set WIMBoot information on the specified file.
 *
 * This turns it into a reparse point that redirects accesses to it, to the
 * corresponding resource in the WIM archive.
 *
 * @h
 *	Open handle to the file, with GENERIC_WRITE access.
 * @blob
 *	The blob for the unnamed data stream of the file.
 * @data_source_id
 *	Allocated identifier for the WIM data source on the destination volume.
 *
 * Returns %true on success, or %false on failure with GetLastError() set.
 */
bool
wimboot_set_pointer(HANDLE h, const struct blob_descriptor *blob,
		    u64 data_source_id)
{
	DWORD bytes_returned;
	unsigned int max_retries = 4;
	struct {
		struct wof_external_info wof_info;
		struct wim_provider_external_info wim_info;
	} in;

retry:
	memset(&in, 0, sizeof(in));

	in.wof_info.version = WOF_CURRENT_VERSION;
	in.wof_info.provider = WOF_PROVIDER_WIM;

	in.wim_info.version = WIM_PROVIDER_CURRENT_VERSION;
	in.wim_info.flags = 0;
	in.wim_info.data_source_id = data_source_id;
	copy_hash(in.wim_info.unnamed_data_stream_hash, blob->hash);

	if (!DeviceIoControl(h, FSCTL_SET_EXTERNAL_BACKING, &in, sizeof(in),
			     NULL, 0, &bytes_returned, NULL))
	{
		/* Try to track down sporadic errors  */
		if (wimlib_print_errors) {
			WARNING("FSCTL_SET_EXTERNAL_BACKING failed (err=%u); data was %zu bytes:",
				(u32)GetLastError(), sizeof(in));
			print_byte_field((const u8 *)&in, sizeof(in), wimlib_error_file);
			putc('\n', wimlib_error_file);
		}
		if (--max_retries) {
			WARNING("Retrying after 100ms...");
			Sleep(100);
			goto retry;
		}
		WARNING("Too many retries; returning failure");
		return false;
	}

	return true;
}

#endif /* __WIN32__ */
