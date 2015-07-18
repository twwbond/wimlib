/*
 * lzx_common.h
 *
 * Declarations shared between LZX compression and decompression.
 */

#ifndef _LZX_COMMON_H
#define _LZX_COMMON_H

#include "wimlib/bitops.h"
#include "wimlib/lzx_constants.h"
#include "wimlib/types.h"

//#define ENABLE_LZX_DEBUG
#ifdef ENABLE_LZX_DEBUG
#  include "wimlib/assert.h"
#  define LZX_ASSERT wimlib_assert
#else
#  define LZX_ASSERT(...)
#endif

extern const u32 lzx_offset_slot_base[LZX_MAX_OFFSET_SLOTS + 1];

extern u8 lzx_extra_offset_bits[LZX_MAX_OFFSET_SLOTS];

/*
 * Return the offset slot for the specified match offset.
 *
 * This returns the smallest i such that:
 *
 *	offset + LZX_OFFSET_ADJUSTMENT >= lzx_offset_slot_base[i]
 *
 * However, the actual implementation below takes advantage of the regularity of
 * the offset slot bases to calculate the slot directly from the adjusted offset
 * without actually looking at the array.
 */
static inline unsigned
lzx_get_offset_slot(u32 offset)
{
	u32 slot = 0;
	while (offset + LZX_OFFSET_ADJUSTMENT >= lzx_offset_slot_base[slot + 1])
		slot++;
	return slot;
}

static inline unsigned
lzx_main_symbol_for_literal(unsigned literal)
{
	return literal;
}

static inline unsigned
lzx_main_symbol_for_match(unsigned offset_slot, unsigned len_header)
{
	return LZX_NUM_CHARS + (offset_slot * LZX_NUM_LEN_HEADERS) + len_header;
}

extern unsigned
lzx_get_window_order(size_t max_bufsize);

extern unsigned
lzx_get_num_offset_slots(unsigned window_order);

extern unsigned
lzx_get_num_main_syms(unsigned window_order);

extern void
lzx_do_e8_preprocessing(u8 *data, u32 size);

extern void
lzx_undo_e8_preprocessing(u8 *data, u32 size);

#endif /* _LZX_COMMON_H */
