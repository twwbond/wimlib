/*
 * lzx_compress.c
 *
 * A compressor for the LZX compression format, as used in WIM files.
 */

/*
 * Copyright (C) 2012, 2013, 2014, 2015 Eric Biggers
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


/*
 * This file contains a compressor for the LZX ("Lempel-Ziv eXtended")
 * compression format, as used in the WIM (Windows IMaging) file format.
 *
 * Two different parsing algorithms are implemented: "near-optimal" and "lazy".
 * "Near-optimal" is significantly slower than "lazy", but results in a better
 * compression ratio.  The "near-optimal" algorithm is used at the default
 * compression level.
 *
 * This file may need some slight modifications to be used outside of the WIM
 * format.  In particular, in other situations the LZX block header might be
 * slightly different, and sliding window support might be required.
 *
 * Note: LZX is a compression format derived from DEFLATE, the format used by
 * zlib and gzip.  Both LZX and DEFLATE use LZ77 matching and Huffman coding.
 * Certain details are quite similar, such as the method for storing Huffman
 * codes.  However, the main differences are:
 *
 * - LZX preprocesses the data to attempt to make x86 machine code slightly more
 *   compressible before attempting to compress it further.
 *
 * - LZX uses a "main" alphabet which combines literals and matches, with the
 *   match symbols containing a "length header" (giving all or part of the match
 *   length) and an "offset slot" (giving, roughly speaking, the order of
 *   magnitude of the match offset).
 *
 * - LZX does not have static Huffman blocks (that is, the kind with preset
 *   Huffman codes); however it does have two types of dynamic Huffman blocks
 *   ("verbatim" and "aligned").
 *
 * - LZX has a minimum match length of 2 rather than 3.  Length 2 matches can be
 *   useful, but generally only if the parser is smart about choosing them.
 *
 * - In LZX, offset slots 0 through 2 actually represent entries in an LRU queue
 *   of match offsets.  This is very useful for certain types of files, such as
 *   binary files that have repeating records.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/*
 * Start a new LZX block (with new Huffman codes) after this many bytes.
 *
 * Note: actual block sizes may slightly exceed this value.
 *
 * TODO: recursive splitting and cost evaluation might be good for an extremely
 * high compression mode, but otherwise it is almost always far too slow for how
 * much it helps.  Perhaps some sort of heuristic would be useful?
 */
#define LZX_DIV_BLOCK_SIZE	32768

/*
 * LZX_CACHE_PER_POS is the number of lz_match structures to reserve in the
 * match cache for each byte position.  This value should be high enough so that
 * nearly the time, all matches found in a given block can fit in the match
 * cache.  However, fallback behavior (immediately terminating the block) on
 * cache overflow is still required.
 */
#define LZX_CACHE_PER_POS	7

/*
 * LZX_CACHE_LENGTH is the number of lz_match structures in the match cache,
 * excluding the extra "overflow" entries.  The per-position multiplier is '1 +
 * LZX_CACHE_PER_POS' instead of 'LZX_CACHE_PER_POS' because there is an
 * overhead of one lz_match per position, used to hold the match count at that
 * position.
 */
#define LZX_CACHE_LENGTH	(LZX_DIV_BLOCK_SIZE * (1 + LZX_CACHE_PER_POS))

/*
 * LZX_MAX_MATCHES_PER_POS is an upper bound on the number of matches that can
 * ever be saved in the match cache for a single position.  Since each match we
 * save for a single position has a distinct length, we can use the number of
 * possible match lengths in LZX as this bound.  This bound is guaranteed to be
 * valid in all cases, although if 'nice_match_length < LZX_MAX_MATCH_LEN', then
 * it will never actually be reached.
 */
#define LZX_MAX_MATCHES_PER_POS	LZX_NUM_LENS

/*
 * LZX_BIT_COST is a scaling factor that represents the cost to output one bit.
 * This makes it possible to consider fractional bit costs.
 *
 * Note: this is only useful as a statistical trick for when the true costs are
 * unknown.  In reality, each token in LZX requires a whole number of bits to
 * output.
 */
#define LZX_BIT_COST		16

/*
 * Consideration of aligned offset costs is disabled for now, due to
 * insufficient benefit gained from the time spent.
 */
#define LZX_CONSIDER_ALIGNED_COSTS	0

/*
 * LZX_MAX_FAST_LEVEL is the maximum compression level at which we use the
 * faster algorithm.
 */
#define LZX_MAX_FAST_LEVEL	34

/*
 * LZX_HASH2_ORDER is the log base 2 of the number of entries in the hash table
 * for finding length 2 matches.  This can be as high as 16 (in which case the
 * hash function is trivial), but using a smaller hash table speeds up
 * compression due to reduced cache pressure.
 */
#define LZX_HASH2_ORDER		12
#define LZX_HASH2_LENGTH	(1UL << LZX_HASH2_ORDER)

#include "wimlib/lzx_common.h"

/*
 * The maximum allowed window order for the matchfinder.
 */
#define MATCHFINDER_MAX_WINDOW_ORDER	16

#include <string.h>

#include "wimlib/bt_matchfinder.h"
#include "wimlib/compress_common.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/error.h"
#include "wimlib/hc_matchfinder.h"
#include "wimlib/lz_extend.h"
#include "wimlib/unaligned.h"
#include "wimlib/util.h"

struct lzx_output_bitstream;

/* Codewords for the LZX Huffman codes.  */
struct lzx_codewords {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Codeword lengths (in bits) for the LZX Huffman codes.
 * A zero length means the corresponding codeword has zero frequency.  */
struct lzx_lens {
	u8 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u8 len[LZX_LENCODE_NUM_SYMBOLS];
	u8 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Cost model for near-optimal parsing  */
struct lzx_costs {

	/* 'match_cost[offset_slot][len - LZX_MIN_MATCH_LEN]' is the cost for a
	 * length 'len' match that has an offset belonging to 'offset_slot'.  */
	u32 match_cost[LZX_MAX_OFFSET_SLOTS][LZX_NUM_LENS];

	/* Cost for each symbol in the main code  */
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];

	/* Cost for each symbol in the length code  */
	u32 len[LZX_LENCODE_NUM_SYMBOLS];

#if LZX_CONSIDER_ALIGNED_COSTS
	/* Cost for each symbol in the aligned code  */
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
#endif
};

/* Codewords and lengths for the LZX Huffman codes.  */
struct lzx_codes {
	struct lzx_codewords codewords;
	struct lzx_lens lens;
};

/* Symbol frequency counters for the LZX Huffman codes.  */
struct lzx_freqs {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Intermediate LZX match/literal format  */
struct lzx_item {
	u16 litrunlen;
	u8 match_hdr;
	u8 adjusted_length;
	u32 offset_slot_and_adjusted_offset;
};

/*
 * This structure represents a byte position in the input buffer and a node in
 * the graph of possible match/literal choices.
 *
 * Logically, each incoming edge to this node is labeled with a literal or a
 * match that can be taken to reach this position from an earlier position; and
 * each outgoing edge from this node is labeled with a literal or a match that
 * can be taken to advance from this position to a later position.
 */
struct lzx_optimum_node {

	/* The cost, in bits, of the lowest-cost path that has been found to
	 * reach this position.  This can change as progressively lower cost
	 * paths are found to reach this position.  */
	u32 cost;

	/*
	 * The match or literal that was taken to reach this position.  This can
	 * change as progressively lower cost paths are found to reach this
	 * position.
	 *
	 * This variable is divided into two bitfields.
	 *
	 * Literals:
	 *	Low bits are 1, high bits are the literal.
	 *
	 * Explicit offset matches:
	 *	Low bits are the match length, high bits are the offset plus 2.
	 *
	 * Repeat offset matches:
	 *	Low bits are the match length, high bits are the queue index.
	 */
	u32 item;
#define OPTIMUM_OFFSET_SHIFT 9
#define OPTIMUM_LEN_MASK ((1 << OPTIMUM_OFFSET_SHIFT) - 1)
} _aligned_attribute(8);

/*
 * Least-recently-used queue for match offsets.
 *
 * This is represented as a 64-bit integer for efficiency.  There are three
 * offsets of 21 bits each.  Bit 64 is garbage.
 */
struct lzx_lru_queue {
	u64 R;
};

#define LZX_QUEUE64_OFFSET_SHIFT 21
#define LZX_QUEUE64_OFFSET_MASK	(((u64)1 << LZX_QUEUE64_OFFSET_SHIFT) - 1)

#define LZX_QUEUE64_R0_SHIFT (0 * LZX_QUEUE64_OFFSET_SHIFT)
#define LZX_QUEUE64_R1_SHIFT (1 * LZX_QUEUE64_OFFSET_SHIFT)
#define LZX_QUEUE64_R2_SHIFT (2 * LZX_QUEUE64_OFFSET_SHIFT)

#define LZX_QUEUE64_R0_MASK (LZX_QUEUE64_OFFSET_MASK << LZX_QUEUE64_R0_SHIFT)
#define LZX_QUEUE64_R1_MASK (LZX_QUEUE64_OFFSET_MASK << LZX_QUEUE64_R1_SHIFT)
#define LZX_QUEUE64_R2_MASK (LZX_QUEUE64_OFFSET_MASK << LZX_QUEUE64_R2_SHIFT)

static inline void
lzx_lru_queue_init(struct lzx_lru_queue *queue)
{
	queue->R = ((u64)1 << LZX_QUEUE64_R0_SHIFT) |
		   ((u64)1 << LZX_QUEUE64_R1_SHIFT) |
		   ((u64)1 << LZX_QUEUE64_R2_SHIFT);
}

static inline u64
lzx_lru_queue_R0(struct lzx_lru_queue queue)
{
	return (queue.R >> LZX_QUEUE64_R0_SHIFT) & LZX_QUEUE64_OFFSET_MASK;
}

static inline u64
lzx_lru_queue_R1(struct lzx_lru_queue queue)
{
	return (queue.R >> LZX_QUEUE64_R1_SHIFT) & LZX_QUEUE64_OFFSET_MASK;
}

static inline u64
lzx_lru_queue_R2(struct lzx_lru_queue queue)
{
	return (queue.R >> LZX_QUEUE64_R2_SHIFT) & LZX_QUEUE64_OFFSET_MASK;
}

/* Push a match offset onto the front (most recently used) end of the queue.  */
static inline struct lzx_lru_queue
lzx_lru_queue_push(struct lzx_lru_queue queue, u32 offset)
{
	return (struct lzx_lru_queue) {
		.R = (queue.R << LZX_QUEUE64_OFFSET_SHIFT) | offset,
	};
}

/* Pop a match offset off the front (most recently used) end of the queue.  */
static inline u32
lzx_lru_queue_pop(struct lzx_lru_queue *queue_p)
{
	u32 offset = queue_p->R & LZX_QUEUE64_OFFSET_MASK;
	queue_p->R >>= LZX_QUEUE64_OFFSET_SHIFT;
	return offset;
}

/* Swap a match offset to the front of the queue.  */
static inline struct lzx_lru_queue
lzx_lru_queue_swap(struct lzx_lru_queue queue, unsigned idx)
{
	if (idx == 0)
		return queue;

	if (idx == 1)
		return (struct lzx_lru_queue) {
			.R = (lzx_lru_queue_R1(queue) << LZX_QUEUE64_R0_SHIFT) |
			     (lzx_lru_queue_R0(queue) << LZX_QUEUE64_R1_SHIFT) |
			     (queue.R & LZX_QUEUE64_R2_MASK),
		};

	return (struct lzx_lru_queue) {
		.R = (lzx_lru_queue_R2(queue) << LZX_QUEUE64_R0_SHIFT) |
		     (queue.R & LZX_QUEUE64_R1_MASK) |
		     (lzx_lru_queue_R0(queue) << LZX_QUEUE64_R2_SHIFT),
	};
}

/* The main LZX compressor structure  */
struct lzx_compressor {

	/* The "nice" match length: if a match of this length is found, then
	 * choose it immediately without further consideration.  */
	unsigned nice_match_length;

	/* The maximum search depth: consider at most this many potential
	 * matches at each position.  */
	unsigned max_search_depth;

	/* The log base 2 of the LZX window size for LZ match offset encoding
	 * purposes.  This will be >= LZX_MIN_WINDOW_ORDER and <=
	 * LZX_MAX_WINDOW_ORDER.  */
	unsigned window_order;

	/* The number of symbols in the main alphabet.  This depends on
	 * @window_order, since @window_order determines the maximum possible
	 * offset.  */
	unsigned num_main_syms;

	/* Number of optimization passes per block  */
	unsigned num_optim_passes;

	/* The preprocessed buffer of data being compressed  */
	u8 *in_buffer;

	/* The number of bytes of data to be compressed, which is the number of
	 * bytes of data in @in_buffer that are actually valid.  */
	size_t in_nbytes;

	/* Pointer to the compress() implementation chosen at allocation time */
	void (*impl)(struct lzx_compressor *, struct lzx_output_bitstream *);

	/* If true, the compressor need not preserve the input buffer if it
	 * compresses the data successfully.  */
	bool destructive;

	/* The Huffman symbol frequency counters for the current block.  */
	struct lzx_freqs freqs;

	/* The Huffman codes for the current and previous blocks.  The one with
	 * index 'codes_index' is for the current block, and the other one is
	 * for the previous block.  */
	struct lzx_codes codes[2];
	unsigned codes_index;

	/*
	 * The match/literal sequence the algorithm chose for the current block.
	 *
	 * Notes on how large this array actually needs to be:
	 *
	 * - In lzx_compress_near_optimal(), the maximum block size is
	 *   'LZX_DIV_BLOCK_SIZE + LZX_MAX_MATCH_LEN - 1' bytes.  This occurs if
	 *   a match of the maximum length is found on the last byte.  Although
	 *   it is impossible for this particular case to actually result in a
	 *   parse of all literals, we reserve this many spaces anyway.
	 *
	 * - The worst case for lzx_compress_lazy() is a block of almost all
	 *   literals that ends with a series of matches of increasing scores,
	 *   causing a sequence of literals to be chosen before the last match
	 *   is finally chosen.  The number of items actually chosen in this
	 *   scenario is limited by the number of distinct match scores that
	 *   exist for matches shorter than 'nice_match_length'.  Having
	 *   'LZX_MAX_MATCH_LEN - 1' extra spaces is plenty for now.
	 */
	struct lzx_item chosen_items[LZX_DIV_BLOCK_SIZE + LZX_MAX_MATCH_LEN - 1];

	/* Table mapping match offset => offset slot for small offsets  */
#define LZX_NUM_FAST_OFFSETS 32768
	u8 offset_slot_fast[LZX_NUM_RECENT_OFFSETS + LZX_NUM_FAST_OFFSETS];

	union {
		/* Data for greedy or lazy parsing  */
		struct {
			/* Hash chains matchfinder (MUST BE LAST!!!)  */
			struct hc_matchfinder hc_mf;
		};

		/* Data for near-optimal parsing  */
		struct {
			/*
			 * The graph nodes for the current block.
			 *
			 * We need at least 'LZX_DIV_BLOCK_SIZE +
			 * LZX_MAX_MATCH_LEN - 1' nodes because that is the
			 * maximum block size that may be used.  Add 1 because
			 * we need a node to represent end-of-block.
			 *
			 * It is possible that nodes past end-of-block are
			 * accessed during match consideration, but this can
			 * only occur if the block was truncated at
			 * LZX_DIV_BLOCK_SIZE.  So the same bound still applies.
			 * Note that since nodes past the end of the block will
			 * never actually have an effect on the items that are
			 * chosen for the block, it makes no difference what
			 * their costs are initialized to (if anything).
			 */
			struct lzx_optimum_node optimum_nodes[LZX_DIV_BLOCK_SIZE +
							      LZX_MAX_MATCH_LEN - 1 + 1];

			/* The cost model for the current block  */
			struct lzx_costs costs;

			/*
			 * Cached matches for the current block.  This array
			 * contains the matches that were found at each position
			 * in the block.  Specifically, for each position, there
			 * is a special 'struct lz_match' whose 'length' field
			 * contains the number of matches that were found at
			 * that position; this is followed by the matches
			 * themselves, if any, sorted by strictly increasing
			 * length.
			 *
			 * Note: in rare cases, there will be a very high number
			 * of matches in the block and this array will overflow.
			 * If this happens, we force the end of the current
			 * block.  LZX_CACHE_LENGTH is the length at which we
			 * actually check for overflow.  The extra slots beyond
			 * this are enough to absorb the worst case overflow,
			 * which occurs if starting at
			 * &match_cache[LZX_CACHE_LENGTH - 1], we write the
			 * match count header, then write
			 * LZX_MAX_MATCHES_PER_POS matches, then skip searching
			 * for matches at 'LZX_MAX_MATCH_LEN - 1' positions and
			 * write the match count header for each.
			 */
			struct lz_match match_cache[LZX_CACHE_LENGTH +
						    LZX_MAX_MATCHES_PER_POS +
						    LZX_MAX_MATCH_LEN - 1];

			/* Hash table for finding length 2 matches  */
			pos_t hash2_tab[LZX_HASH2_LENGTH]
				_aligned_attribute(MATCHFINDER_ALIGNMENT);

			/* Binary trees matchfinder (MUST BE LAST!!!)  */
			struct bt_matchfinder bt_mf;
		};
	};
};

/*
 * Structure to keep track of the current state of sending bits to the
 * compressed output buffer.
 *
 * The LZX bitstream is encoded as a sequence of 16-bit coding units.
 */
struct lzx_output_bitstream {

	/* Bits that haven't yet been written to the output buffer.  */
	machine_word_t bitbuf;

	/* Number of bits currently held in @bitbuf.  */
	u32 bitcount;

	/* Pointer to the start of the output buffer.  */
	u8 *start;

	/* Pointer to the position in the output buffer at which the next coding
	 * unit should be written.  */
	u8 *next;

	/* Pointer just past the end of the output buffer, rounded down to a
	 * 2-byte boundary.  */
	u8 *end;
};

#define BITBUF_NBITS (8 * sizeof(machine_word_t))

/*
 * Initialize the output bitstream.
 *
 * @os
 *	The output bitstream structure to initialize.
 * @buffer
 *	The buffer being written to.
 * @size
 *	Size of @buffer, in bytes.
 */
static void
lzx_init_output(struct lzx_output_bitstream *os, void *buffer, size_t size)
{
	os->bitbuf = 0;
	os->bitcount = 0;
	os->start = buffer;
	os->next = os->start;
	os->end = os->start + (size & ~1);
}

#define CAN_BUFFER(n) ((n) < BITBUF_NBITS - 16)

static inline void
lzx_flush_bits_impl(struct lzx_output_bitstream *os, int level)
{
	if (level >= 1 && os->bitcount >= 16) {
		os->bitcount -= 16;
		if (os->next != os->end) {
			put_unaligned_u16_le(os->bitbuf >> os->bitcount, os->next);
			os->next += 2;
		}
		if (level >= 2 && os->bitcount >= 16) {
			os->bitcount -= 16;
			if (os->next != os->end) {
				put_unaligned_u16_le(os->bitbuf >> os->bitcount, os->next);
				os->next += 2;
			}
			if (level >= 3 && os->bitcount >= 16) {
				os->bitcount -= 16;
				if (os->next != os->end) {
					put_unaligned_u16_le(os->bitbuf >> os->bitcount, os->next);
					os->next += 2;
				}
				if (level >= 4 && os->bitcount >= 16) {
					os->bitcount -= 16;
					if (os->next != os->end) {
						put_unaligned_u16_le(os->bitbuf >> os->bitcount, os->next);
						os->next += 2;
					}
				}
			}
		}
	}
}

static inline void
lzx_flush_bits(struct lzx_output_bitstream *os)
{
	lzx_flush_bits_impl(os, 3);
}

static inline void
lzx_add_bits(struct lzx_output_bitstream *os, u32 bits, unsigned num_bits)
{
	os->bitcount += num_bits;
	os->bitbuf = (os->bitbuf << num_bits) | bits;
}

/*
 * Flush the last coding unit to the output buffer if needed.  Return the total
 * number of bytes written to the output buffer, or 0 if an overflow occurred.
 */
static u32
lzx_flush_output(struct lzx_output_bitstream *os)
{
	lzx_flush_bits(os);

	if (os->next == os->end)
		return 0;

	if (os->bitcount != 0) {
		put_unaligned_u16_le(os->bitbuf << (16 - os->bitcount), os->next);
		os->next += 2;
	}

	return os->next - os->start;
}

/* Build the main, length, and aligned offset Huffman codes used in LZX.
 *
 * This takes as input the frequency tables for each code and produces as output
 * a set of tables that map symbols to codewords and codeword lengths.  */
static void
lzx_make_huffman_codes(struct lzx_compressor *c)
{
	const struct lzx_freqs *freqs = &c->freqs;
	struct lzx_codes *codes = &c->codes[c->codes_index];

	make_canonical_huffman_code(c->num_main_syms,
				    12,
				    freqs->main,
				    codes->lens.main,
				    codes->codewords.main);

	make_canonical_huffman_code(LZX_LENCODE_NUM_SYMBOLS,
				    9,
				    freqs->len,
				    codes->lens.len,
				    codes->codewords.len);

	make_canonical_huffman_code(LZX_ALIGNEDCODE_NUM_SYMBOLS,
				    7,
				    freqs->aligned,
				    codes->lens.aligned,
				    codes->codewords.aligned);
}

/* Reset the symbol frequencies for the LZX Huffman codes.  */
static void
lzx_reset_symbol_frequencies(struct lzx_compressor *c)
{
	memset(&c->freqs, 0, sizeof(c->freqs));
}

static unsigned
lzx_compute_precode_items(const u8 lens[restrict],
			  const u8 prev_lens[restrict],
			  const unsigned num_lens,
			  u32 precode_freqs[restrict],
			  unsigned precode_items[restrict])
{
	unsigned *itemptr;
	unsigned run_start;
	unsigned run_end;
	unsigned extra_bits;
	int delta;
	u8 len;

	itemptr = precode_items;
	run_start = 0;
	do {
		/* Find the next run of codeword lengths.  */

		/* len = the length being repeated  */
		len = lens[run_start];

		run_end = run_start + 1;

		/* Fast case for a single length.  */
		if (likely(run_end == num_lens || len != lens[run_end])) {
			delta = prev_lens[run_start] - len;
			if (delta < 0)
				delta += 17;
			precode_freqs[delta]++;
			*itemptr++ = delta;
			run_start++;
			continue;
		}

		/* Extend the run.  */
		do {
			run_end++;
		} while (run_end != num_lens && len == lens[run_end]);

		if (len == 0) {
			/* Run of zeroes.  */

			/* Symbol 18: RLE 20 to 51 zeroes at a time.  */
			while ((run_end - run_start) >= 20) {
				extra_bits = min((run_end - run_start) - 20, 0x1f);
				precode_freqs[18]++;
				*itemptr++ = 18 | (extra_bits << 5);
				run_start += 20 + extra_bits;
			}

			/* Symbol 17: RLE 4 to 19 zeroes at a time.  */
			if ((run_end - run_start) >= 4) {
				extra_bits = min((run_end - run_start) - 4, 0xf);
				precode_freqs[17]++;
				*itemptr++ = 17 | (extra_bits << 5);
				run_start += 4 + extra_bits;
			}
		} else {

			/* A run of nonzero lengths. */

			/* Symbol 19: RLE 4 to 5 of any length at a time.  */
			while ((run_end - run_start) >= 4) {
				extra_bits = (run_end - run_start) > 4;
				delta = prev_lens[run_start] - len;
				if (delta < 0)
					delta += 17;
				precode_freqs[19]++;
				precode_freqs[delta]++;
				*itemptr++ = 19 | (extra_bits << 5) | (delta << 6);
				run_start += 4 + extra_bits;
			}
		}

		/* Output any remaining lengths without RLE.  */
		while (run_start != run_end) {
			delta = prev_lens[run_start] - len;
			if (delta < 0)
				delta += 17;
			precode_freqs[delta]++;
			*itemptr++ = delta;
			run_start++;
		}
	} while (run_start != num_lens);

	return itemptr - precode_items;
}

/*
 * Output a Huffman code in the compressed form used in LZX.
 *
 * The Huffman code is represented in the output as a logical series of codeword
 * lengths from which the Huffman code, which must be in canonical form, can be
 * reconstructed.
 *
 * The codeword lengths are themselves compressed using a separate Huffman code,
 * the "precode", which contains a symbol for each possible codeword length in
 * the larger code as well as several special symbols to represent repeated
 * codeword lengths (a form of run-length encoding).  The precode is itself
 * constructed in canonical form, and its codeword lengths are represented
 * literally in 20 4-bit fields that immediately precede the compressed codeword
 * lengths of the larger code.
 *
 * Furthermore, the codeword lengths of the larger code are actually represented
 * as deltas from the codeword lengths of the corresponding code in the previous
 * block.
 *
 * @os:
 *	Bitstream to which to write the compressed Huffman code.
 * @lens:
 *	The codeword lengths, indexed by symbol, in the Huffman code.
 * @prev_lens:
 *	The codeword lengths, indexed by symbol, in the corresponding Huffman
 *	code in the previous block, or all zeroes if this is the first block.
 * @num_lens:
 *	The number of symbols in the Huffman code.
 */
static void
lzx_write_compressed_code(struct lzx_output_bitstream *os,
			  const u8 lens[restrict],
			  const u8 prev_lens[restrict],
			  unsigned num_lens)
{
	u32 precode_freqs[LZX_PRECODE_NUM_SYMBOLS];
	u8 precode_lens[LZX_PRECODE_NUM_SYMBOLS];
	u32 precode_codewords[LZX_PRECODE_NUM_SYMBOLS];
	unsigned precode_items[num_lens];
	unsigned num_precode_items;
	unsigned precode_item;
	unsigned precode_sym;
	unsigned i;

	for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++)
		precode_freqs[i] = 0;

	/* Compute the "items" (RLE / literal tokens and extra bits) with which
	 * the codeword lengths in the larger code will be output.  */
	num_precode_items = lzx_compute_precode_items(lens,
						      prev_lens,
						      num_lens,
						      precode_freqs,
						      precode_items);

	/* Build the precode.  */
	make_canonical_huffman_code(LZX_PRECODE_NUM_SYMBOLS,
				    LZX_MAX_PRE_CODEWORD_LEN,
				    precode_freqs, precode_lens,
				    precode_codewords);

	/* Output the lengths of the codewords in the precode.  */
	for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++) {
		lzx_add_bits(os, precode_lens[i], LZX_PRECODE_ELEMENT_SIZE);
		lzx_flush_bits(os);
	}

	/* Output the encoded lengths of the codewords in the larger code.  */
	for (i = 0; i < num_precode_items; i++) {
		precode_item = precode_items[i];
		precode_sym = precode_item & 0x1F;
		lzx_add_bits(os, precode_codewords[precode_sym],
			     precode_lens[precode_sym]);
		if (precode_sym >= 17) {
			if (precode_sym == 17) {
				lzx_add_bits(os, precode_item >> 5, 4);
			} else if (precode_sym == 18) {
				lzx_add_bits(os, precode_item >> 5, 5);
			} else {
				lzx_add_bits(os, (precode_item >> 5) & 1, 1);
				precode_sym = precode_item >> 6;
				lzx_add_bits(os, precode_codewords[precode_sym],
					     precode_lens[precode_sym]);
			}
		}
		lzx_flush_bits(os);
	}
}

static void
lzx_write_items_impl(struct lzx_output_bitstream * restrict __os,
		     int block_type,
		     const u8 * restrict block_data,
		     const struct lzx_item * restrict item,
		     const struct lzx_codes * restrict codes)
{
	struct lzx_output_bitstream _os = *__os;
	struct lzx_output_bitstream *os = &_os;

	for (;;) {
		unsigned litrunlen = item->litrunlen;
		unsigned match_hdr;
		unsigned main_symbol;
		unsigned adjusted_length;
		u32 adjusted_offset;
		unsigned offset_slot;
		unsigned num_extra_bits;
		u32 extra_bits;

		if (litrunlen) {

			while (litrunlen >= 4) {
				unsigned lit0 = block_data[0];
				unsigned lit1 = block_data[1];
				unsigned lit2 = block_data[2];
				unsigned lit3 = block_data[3];

				lzx_add_bits(os, codes->codewords.main[lit0], codes->lens.main[lit0]);
				lzx_add_bits(os, codes->codewords.main[lit1], codes->lens.main[lit1]);
				lzx_add_bits(os, codes->codewords.main[lit2], codes->lens.main[lit2]);
				lzx_add_bits(os, codes->codewords.main[lit3], codes->lens.main[lit3]);

				lzx_flush_bits_impl(os, 4);

				block_data += 4;
				litrunlen -= 4;
			}

			if (litrunlen--) {
				unsigned lit = *block_data++;
				lzx_add_bits(os, codes->codewords.main[lit], codes->lens.main[lit]);
				if (litrunlen--) {
					unsigned lit = *block_data++;
					lzx_add_bits(os, codes->codewords.main[lit], codes->lens.main[lit]);
					if (litrunlen--) {
						unsigned lit = *block_data++;
						lzx_add_bits(os, codes->codewords.main[lit], codes->lens.main[lit]);
					}
				}
				lzx_flush_bits_impl(os, 3);
			}
		}

		match_hdr = item->match_hdr;

		if (match_hdr == 0xFF) {
			*__os = *os;
			return;
		}

		main_symbol = LZX_NUM_CHARS + match_hdr;

		lzx_add_bits(os, codes->codewords.main[main_symbol], codes->lens.main[main_symbol]);

		adjusted_length = item->adjusted_length;
		adjusted_offset = item->offset_slot_and_adjusted_offset >> 8;

		block_data += adjusted_length + LZX_MIN_MATCH_LEN;

		if (adjusted_length >= LZX_NUM_PRIMARY_LENS) {
			lzx_add_bits(os, codes->codewords.len[adjusted_length - LZX_NUM_PRIMARY_LENS],
				     codes->lens.len[adjusted_length - LZX_NUM_PRIMARY_LENS]);
		}

		offset_slot = item->offset_slot_and_adjusted_offset & 0xFF;

		num_extra_bits = lzx_extra_offset_bits[offset_slot];
		extra_bits = adjusted_offset - lzx_offset_slot_base[offset_slot];

		if (block_type == LZX_BLOCKTYPE_ALIGNED && offset_slot >= 8) {

			/* Aligned offset blocks: The low 3 bits of the extra offset
			 * bits are Huffman-encoded using the aligned offset code.  The
			 * remaining bits are output literally.  */

			lzx_add_bits(os, extra_bits >> LZX_NUM_ALIGNED_OFFSET_BITS,
					num_extra_bits - LZX_NUM_ALIGNED_OFFSET_BITS);

			lzx_add_bits(os, codes->codewords.aligned[adjusted_offset & LZX_ALIGNED_OFFSET_BITMASK],
				     codes->lens.aligned[adjusted_offset & LZX_ALIGNED_OFFSET_BITMASK]);
		} else {
			/* Verbatim blocks, or fewer than 3 extra bits:  All extra
			 * offset bits are output literally.  */
			lzx_add_bits(os, extra_bits, num_extra_bits);
		}
		lzx_flush_bits_impl(os, 3);
		item++;
	}
}

/*
 * Write all matches and literal bytes (which were precomputed) in an LZX
 * compressed block to the output bitstream in the final compressed
 * representation.
 *
 * @os
 *	The output bitstream.
 * @block_type
 *	The chosen type of the LZX compressed block (LZX_BLOCKTYPE_ALIGNED or
 *	LZX_BLOCKTYPE_VERBATIM).
 * @items
 *	The array of matches/literals to output.
 * @num_items
 *	Number of matches/literals to output (length of @items).
 * @codes
 *	The main, length, and aligned offset Huffman codes for the current
 *	LZX compressed block.
 */
static void
lzx_write_items(struct lzx_output_bitstream *os, int block_type, const u8 *block_data,
		const struct lzx_item *items, const struct lzx_codes *codes)
{
	if (block_type == LZX_BLOCKTYPE_ALIGNED)
		lzx_write_items_impl(os, LZX_BLOCKTYPE_ALIGNED, block_data, items, codes);
	else
		lzx_write_items_impl(os, LZX_BLOCKTYPE_VERBATIM, block_data, items, codes);
}

static void
lzx_write_compressed_block(const u8 *block_begin,
			   int block_type,
			   u32 block_size,
			   unsigned window_order,
			   unsigned num_main_syms,
			   const struct lzx_item chosen_items[],
			   const struct lzx_codes * codes,
			   const struct lzx_lens * prev_lens,
			   struct lzx_output_bitstream * os)
{
	LZX_ASSERT(block_type == LZX_BLOCKTYPE_ALIGNED ||
		   block_type == LZX_BLOCKTYPE_VERBATIM);

	/* The first three bits indicate the type of block and are one of the
	 * LZX_BLOCKTYPE_* constants.  */
	lzx_add_bits(os, block_type, 3);

	/* Output the block size.
	 *
	 * The original LZX format seemed to always encode the block size in 3
	 * bytes.  However, the implementation in WIMGAPI, as used in WIM files,
	 * uses the first bit to indicate whether the block is the default size
	 * (32768) or a different size given explicitly by the next 16 bits.
	 *
	 * By default, this compressor uses a window size of 32768 and therefore
	 * follows the WIMGAPI behavior.  However, this compressor also supports
	 * window sizes greater than 32768 bytes, which do not appear to be
	 * supported by WIMGAPI.  In such cases, we retain the default size bit
	 * to mean a size of 32768 bytes but output non-default block size in 24
	 * bits rather than 16.  The compatibility of this behavior is unknown
	 * because WIMs created with chunk size greater than 32768 can seemingly
	 * only be opened by wimlib anyway.  */
	if (block_size == LZX_DEFAULT_BLOCK_SIZE) {
		lzx_add_bits(os, 1, 1);
	} else {
		lzx_add_bits(os, 0, 1);

		if (window_order >= 16)
			lzx_add_bits(os, block_size >> 16, 8);

		lzx_add_bits(os, block_size & 0xFFFF, 16);
	}
	lzx_flush_bits(os);

	/* If it's an aligned offset block, output the aligned offset code.  */
	if (block_type == LZX_BLOCKTYPE_ALIGNED) {
		for (int i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
			lzx_add_bits(os, codes->lens.aligned[i],
				     LZX_ALIGNEDCODE_ELEMENT_SIZE);
		}
		lzx_flush_bits(os);
	}

	/* Output the main code (two parts).  */
	lzx_write_compressed_code(os, codes->lens.main,
				  prev_lens->main,
				  LZX_NUM_CHARS);
	lzx_write_compressed_code(os, codes->lens.main + LZX_NUM_CHARS,
				  prev_lens->main + LZX_NUM_CHARS,
				  num_main_syms - LZX_NUM_CHARS);

	/* Output the length code.  */
	lzx_write_compressed_code(os, codes->lens.len,
				  prev_lens->len,
				  LZX_LENCODE_NUM_SYMBOLS);

	/* Output the compressed matches and literals.  */
	lzx_write_items(os, block_type, block_begin, chosen_items, codes);
}

/* Given the frequencies of symbols in an LZX-compressed block and the
 * corresponding Huffman codes, return LZX_BLOCKTYPE_ALIGNED or
 * LZX_BLOCKTYPE_VERBATIM if an aligned offset or verbatim block, respectively,
 * will take fewer bits to output.  */
static int
lzx_choose_verbatim_or_aligned(const struct lzx_freqs * freqs,
			       const struct lzx_codes * codes)
{
	u32 aligned_cost = 0;
	u32 verbatim_cost = 0;

	/* A verbatim block requires 3 bits in each place that an aligned symbol
	 * would be used in an aligned offset block.  */
	for (unsigned i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
		verbatim_cost += LZX_NUM_ALIGNED_OFFSET_BITS * freqs->aligned[i];
		aligned_cost += codes->lens.aligned[i] * freqs->aligned[i];
	}

	/* Account for output of the aligned offset code.  */
	aligned_cost += LZX_ALIGNEDCODE_ELEMENT_SIZE * LZX_ALIGNEDCODE_NUM_SYMBOLS;

	if (aligned_cost < verbatim_cost)
		return LZX_BLOCKTYPE_ALIGNED;
	else
		return LZX_BLOCKTYPE_VERBATIM;
}

/*
 * Finish an LZX block:
 *
 * - build the Huffman codes
 * - decide whether to output the block as VERBATIM or ALIGNED
 * - output the block
 * - swap the indices of the current and previous Huffman codes
 */
static void
lzx_finish_block(struct lzx_compressor *c, struct lzx_output_bitstream *os,
		 const u8 *block_begin, u32 block_size,
		 struct lzx_item *chosen_items)
{
	struct lzx_output_bitstream _os = *os;
	int block_type;

	lzx_make_huffman_codes(c);

	block_type = lzx_choose_verbatim_or_aligned(&c->freqs,
						    &c->codes[c->codes_index]);
	lzx_write_compressed_block(block_begin,
				   block_type,
				   block_size,
				   c->window_order,
				   c->num_main_syms,
				   chosen_items,
				   &c->codes[c->codes_index],
				   &c->codes[c->codes_index ^ 1].lens,
				   &_os);
	c->codes_index ^= 1;
	*os = _os;
}

/* Tally, and optionally record, the specified literal byte.  */
static inline void
lzx_declare_literal(struct lzx_compressor *c, unsigned literal,
		    struct lzx_item **next_chosen_item)
{
	return;
#if 0
	unsigned main_symbol = lzx_main_symbol_for_literal(literal);

	c->freqs.main[main_symbol]++;

	if (next_chosen_item) {
		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = main_symbol,
		};
	}
#endif
}

/* Tally, and optionally record, the specified repeat offset match.  */
static inline void
lzx_declare_repeat_offset_match(struct lzx_compressor *c,
				unsigned len, unsigned rep_index,
				struct lzx_item **next_chosen_item)
{
	return;
#if 0
	unsigned len_header;
	unsigned len_symbol;
	unsigned main_symbol;

	if (len - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS) {
		len_header = len - LZX_MIN_MATCH_LEN;
		len_symbol = LZX_LENCODE_NUM_SYMBOLS;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_symbol = len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS;
		c->freqs.len[len_symbol]++;
	}

	main_symbol = lzx_main_symbol_for_match(rep_index, len_header);

	c->freqs.main[main_symbol]++;

	if (next_chosen_item) {
		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = (u64)main_symbol | ((u64)len_symbol << 10),
		};
	}
#endif
}

/* Tally, and optionally record, the specified explicit offset match.  */
static inline void
lzx_declare_explicit_offset_match(struct lzx_compressor *c, unsigned len, u32 offset,
				  struct lzx_item **next_chosen_item)
{
#if 0
	unsigned len_header;
	unsigned len_symbol;
	unsigned main_symbol;
	unsigned offset_slot;
	unsigned num_extra_bits;
	u32 extra_bits;

	if (len - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS) {
		len_header = len - LZX_MIN_MATCH_LEN;
		len_symbol = LZX_LENCODE_NUM_SYMBOLS;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_symbol = len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS;
		c->freqs.len[len_symbol]++;
	}

	offset_slot = lzx_get_offset_slot_fast(c, offset + LZX_OFFSET_ADJUSTMENT);

	main_symbol = lzx_main_symbol_for_match(offset_slot, len_header);

	c->freqs.main[main_symbol]++;

	num_extra_bits = lzx_extra_offset_bits[offset_slot];

	if (num_extra_bits >= LZX_NUM_ALIGNED_OFFSET_BITS)
		c->freqs.aligned[(offset + LZX_OFFSET_ADJUSTMENT) &
				 LZX_ALIGNED_OFFSET_BITMASK]++;

	if (next_chosen_item) {

		extra_bits = (offset + LZX_OFFSET_ADJUSTMENT) -
			     lzx_offset_slot_base[offset_slot];

		BUILD_BUG_ON(LZX_MAINCODE_MAX_NUM_SYMBOLS > (1 << 10));
		BUILD_BUG_ON(LZX_LENCODE_NUM_SYMBOLS > (1 << 8));
		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = (u64)main_symbol |
				((u64)len_symbol << 10) |
				((u64)num_extra_bits << 18) |
				((u64)extra_bits << 23),
		};
	}
#endif
}

static void
lzx_tally_item_list(struct lzx_compressor *c, u32 block_size)
{
	u32 node_idx = block_size;
	u32 len;
	u32 offset_data;
	for (;;) {

		for (;;) {
			len = c->optimum_nodes[node_idx].item & OPTIMUM_LEN_MASK;
			offset_data = c->optimum_nodes[node_idx].item >> OPTIMUM_OFFSET_SHIFT;

			if (len != 0)
				break;
			c->freqs.main[offset_data]++;
			if (!--node_idx)
				return;
		}

		unsigned offset_slot;
		unsigned main_symbol;

		node_idx -= len;

		main_symbol = len - LZX_MIN_MATCH_LEN;;

		if (main_symbol >= LZX_NUM_PRIMARY_LENS) {
			c->freqs.len[main_symbol - LZX_NUM_PRIMARY_LENS]++;
			main_symbol = LZX_NUM_PRIMARY_LENS;
		}

		offset_slot = c->offset_slot_fast[offset_data];
		main_symbol |= offset_slot << 3;
		main_symbol |= 256;

		c->freqs.main[main_symbol]++;

		if (offset_slot >= 8)
			c->freqs.aligned[offset_data & LZX_ALIGNED_OFFSET_BITMASK]++;
	}
}

static struct lzx_item *
lzx_record_item_list(struct lzx_compressor *c, u32 block_size)
{
	u32 node_idx = block_size;
	u32 item_idx = block_size;
	unsigned litrunlen = 0;

	c->chosen_items[item_idx].match_hdr = 0xFF;

	u32 len;
	u32 offset_data;
	for (;;) {

		for (;;) {
			len = c->optimum_nodes[node_idx].item & OPTIMUM_LEN_MASK;
			offset_data = c->optimum_nodes[node_idx].item >> OPTIMUM_OFFSET_SHIFT;

			if (len != 0)
				break;
			c->freqs.main[offset_data]++;
			litrunlen++;
			if (--node_idx == 0)
				goto out;
		}

		unsigned offset_slot;
		unsigned main_symbol;

		node_idx -= len;

		main_symbol = len - LZX_MIN_MATCH_LEN;;
		offset_slot = c->offset_slot_fast[offset_data];

		c->chosen_items[item_idx].litrunlen = litrunlen;
		item_idx--;
		c->chosen_items[item_idx].adjusted_length = main_symbol;
		c->chosen_items[item_idx].offset_slot_and_adjusted_offset =
			(offset_data << 8) | offset_slot;
		litrunlen = 0;

		if (main_symbol >= LZX_NUM_PRIMARY_LENS) {
			c->freqs.len[main_symbol - LZX_NUM_PRIMARY_LENS]++;
			main_symbol = LZX_NUM_PRIMARY_LENS;
		}

		main_symbol |= (offset_slot << 3);
		c->freqs.main[256 | main_symbol]++;
		c->chosen_items[item_idx].match_hdr = main_symbol;

		if (offset_slot >= 8)
			c->freqs.aligned[offset_data & LZX_ALIGNED_OFFSET_BITMASK]++;
	}

out:
	c->chosen_items[item_idx].litrunlen = litrunlen;

	return &c->chosen_items[item_idx];
}

/*
 * Find an inexpensive path through the graph of possible match/literal choices
 * for the current block.  The nodes of the graph are
 * c->optimum_nodes[0...block_size].  They correspond directly to the bytes in
 * the current block, plus one extra node for end-of-block.  The edges of the
 * graph are matches and literals.  The goal is to find the minimum cost path
 * from 'c->optimum_nodes[0]' to 'c->optimum_nodes[block_size]'.
 *
 * The algorithm works forwards, starting at 'c->optimum_nodes[0]' and
 * proceeding forwards one node at a time.  At each node, a selection of matches
 * (len >= 2), as well as the literal byte (len = 1), is considered.  An item of
 * length 'len' provides a new path to reach the node 'len' bytes later.  If
 * such a path is the lowest cost found so far to reach that later node, then
 * that later node is updated with the new path.
 *
 * Note that although this algorithm is based on minimum cost path search, due
 * to various simplifying assumptions the result is not guaranteed to be the
 * true minimum cost, or "optimal", path over the graph of all valid LZX
 * representations of this block.
 *
 * Also, note that because of the presence of the recent offsets queue (which is
 * a type of adaptive state), the algorithm cannot work backwards and compute
 * "cost to end" instead of "cost to beginning".  Furthermore, the way the
 * algorithm handles this adaptive state in the "minimum cost" parse is actually
 * only an approximation.  It's possible for the globally optimal, minimum cost
 * path to contain a prefix, ending at a position, where that path prefix is
 * *not* the minimum cost path to that position.  This can happen if such a path
 * prefix results in a different adaptive state which results in lower costs
 * later.  The algorithm does not solve this problem; it only considers the
 * lowest cost to reach each individual position.
 */
static inline struct lzx_lru_queue
lzx_find_min_cost_path(struct lzx_compressor * const restrict c,
		       const u8 * const restrict block_begin,
		       const u32 block_size,
		       const struct lzx_lru_queue initial_queue)
{
	struct lzx_optimum_node *cur_node = c->optimum_nodes;
	struct lzx_optimum_node * const end_node = &c->optimum_nodes[block_size];
	struct lz_match *cache_ptr = c->match_cache;
	const u8 *in_next = block_begin;
	const u8 * const block_end = block_begin + block_size;

	/* Instead of storing the match offset LRU queues in the
	 * 'lzx_optimum_node' structures, we save memory (and cache lines) by
	 * storing them in a smaller array.  This works because the algorithm
	 * only requires a limited history of the adaptive state.  Once a given
	 * state is more than LZX_MAX_MATCH_LEN bytes behind the current node,
	 * it is no longer needed.  */
	struct lzx_lru_queue queues[512];

	BUILD_BUG_ON(ARRAY_LEN(queues) < LZX_MAX_MATCH_LEN + 1);
#define QUEUE(in) (queues[(uintptr_t)(in) % ARRAY_LEN(queues)])

	/* Initially, the cost to reach each node is "infinity".  */
	memset(c->optimum_nodes, 0xFF,
	       (block_size + 1) * sizeof(c->optimum_nodes[0]));

	QUEUE(block_begin) = initial_queue;

	/* The following loop runs 'block_size' iterations, one per node.  */
	do {
		unsigned num_matches;
		unsigned literal;
		u32 cost;

		/*
		 * A selection of matches for the block was already saved in
		 * memory so that we don't have to run the uncompressed data
		 * through the matchfinder on every optimization pass.  However,
		 * we still search for repeat offset matches during each
		 * optimization pass because we cannot predict the state of the
		 * recent offsets queue.  But as a heuristic, we don't bother
		 * searching for repeat offset matches if the general-purpose
		 * matchfinder failed to find any matches.
		 *
		 * Note that a match of length n at some offset implies there is
		 * also a match of length l for LZX_MIN_MATCH_LEN <= l <= n at
		 * that same offset.  In other words, we don't necessarily need
		 * to use the full length of a match.  The key heuristic that
		 * saves a significicant amount of time is that for each
		 * distinct length, we only consider the smallest offset for
		 * which that length is available.  This heuristic also applies
		 * to repeat offsets, which we order specially: R0 < R1 < R2 <
		 * any explicit offset.  Of course, this heuristic may be
		 * produce suboptimal results because offset slots in LZX are
		 * subject to entropy encoding, but in practice this is a useful
		 * heuristic.
		 */

		num_matches = cache_ptr->length;
		cache_ptr++;

		if (num_matches) {
			struct lz_match *end_matches = cache_ptr + num_matches;
			unsigned next_len = LZX_MIN_MATCH_LEN;
			unsigned max_len = min(block_end - in_next, LZX_MAX_MATCH_LEN);
			const u8 *matchptr;
			u64 R = QUEUE(in_next).R;

			/* Consider R0 match  */
			matchptr = in_next - (R & LZX_QUEUE64_OFFSET_MASK);
			R >>= LZX_QUEUE64_OFFSET_SHIFT;
			if (load_u16_unaligned(matchptr) != load_u16_unaligned(in_next))
				goto R0_done;
			BUILD_BUG_ON(LZX_MIN_MATCH_LEN != 2);
			do {
				u32 cost = cur_node->cost +
					   c->costs.match_cost[0][
							next_len - LZX_MIN_MATCH_LEN];
				if (cost <= (cur_node + next_len)->cost) {
					(cur_node + next_len)->cost = cost;
					(cur_node + next_len)->item =
						(0 << OPTIMUM_OFFSET_SHIFT) | next_len;
				}
				if (unlikely(++next_len > max_len)) {
					cache_ptr = end_matches;
					goto done_matches;
				}
			} while (in_next[next_len - 1] == matchptr[next_len - 1]);

		R0_done:

			/* Consider R1 match  */
			matchptr = in_next - (R & LZX_QUEUE64_OFFSET_MASK);
			R >>= LZX_QUEUE64_OFFSET_SHIFT;
			if (load_u16_unaligned(matchptr) != load_u16_unaligned(in_next))
				goto R1_done;
			if (matchptr[next_len - 1] != in_next[next_len - 1])
				goto R1_done;
			for (unsigned len = 2; len < next_len - 1; len++)
				if (matchptr[len] != in_next[len])
					goto R1_done;
			do {
				u32 cost = cur_node->cost +
					   c->costs.match_cost[1][
							next_len - LZX_MIN_MATCH_LEN];
				if (cost <= (cur_node + next_len)->cost) {
					(cur_node + next_len)->cost = cost;
					(cur_node + next_len)->item =
						(1 << OPTIMUM_OFFSET_SHIFT) | next_len;
				}
				if (unlikely(++next_len > max_len)) {
					cache_ptr = end_matches;
					goto done_matches;
				}
			} while (in_next[next_len - 1] == matchptr[next_len - 1]);

		R1_done:

			/* Consider R2 match  */
			matchptr = in_next - (R & LZX_QUEUE64_OFFSET_MASK);
			if (load_u16_unaligned(matchptr) != load_u16_unaligned(in_next))
				goto R2_done;
			if (matchptr[next_len - 1] != in_next[next_len - 1])
				goto R2_done;
			for (unsigned len = 2; len < next_len - 1; len++)
				if (matchptr[len] != in_next[len])
					goto R2_done;
			do {
				u32 cost = cur_node->cost +
					   c->costs.match_cost[2][
							next_len - LZX_MIN_MATCH_LEN];
				if (cost <= (cur_node + next_len)->cost) {
					(cur_node + next_len)->cost = cost;
					(cur_node + next_len)->item =
						(2 << OPTIMUM_OFFSET_SHIFT) | next_len;
				}
				if (unlikely(++next_len > max_len)) {
					cache_ptr = end_matches;
					goto done_matches;
				}
			} while (in_next[next_len - 1] == matchptr[next_len - 1]);

		R2_done:

			while (next_len > cache_ptr->length)
				if (++cache_ptr == end_matches)
					goto done_matches;

			/* Consider explicit offset matches  */
			do {
				u32 offset = cache_ptr->offset;
				u32 offset_data = offset + LZX_OFFSET_ADJUSTMENT;
				unsigned offset_slot = c->offset_slot_fast[offset_data];
				do {
					u32 cost = cur_node->cost +
						   c->costs.match_cost[offset_slot][
								next_len - LZX_MIN_MATCH_LEN];
				#if LZX_CONSIDER_ALIGNED_COSTS
					if (lzx_extra_offset_bits[offset_slot] >=
					    LZX_NUM_ALIGNED_OFFSET_BITS)
						cost += c->costs.aligned[offset_data &
									 LZX_ALIGNED_OFFSET_BITMASK];
				#endif
					if (cost < (cur_node + next_len)->cost) {
						(cur_node + next_len)->cost = cost;
						(cur_node + next_len)->item =
							(offset_data << OPTIMUM_OFFSET_SHIFT) | next_len;
					}
				} while (++next_len <= cache_ptr->length);
			} while (++cache_ptr != end_matches);
		}

	done_matches:

		/* Consider coding a literal.

		 * To avoid an extra branch, actually checking the preferability
		 * of coding the literal is integrated into the queue update
		 * code below.  */
		literal = *in_next++;
		cost = cur_node->cost +
		       c->costs.main[lzx_main_symbol_for_literal(literal)];

		/* Advance to the next position.  */
		cur_node++;

		/* The lowest-cost path to the current position is now known.
		 * Finalize the recent offsets queue that results from taking
		 * this lowest-cost path.  */

		if (cost <= cur_node->cost) {
			/* Literal: queue remains unchanged.  */
			cur_node->cost = cost;
			cur_node->item = (literal << OPTIMUM_OFFSET_SHIFT);
			QUEUE(in_next) = QUEUE(in_next - 1);
		} else {
			/* Match: queue update is needed.  */
			unsigned len = cur_node->item & OPTIMUM_LEN_MASK;
			u32 offset_data = cur_node->item >> OPTIMUM_OFFSET_SHIFT;
			if (offset_data >= LZX_NUM_RECENT_OFFSETS) {
				/* Explicit offset match: insert offset at front  */
				QUEUE(in_next) =
					lzx_lru_queue_push(QUEUE(in_next - len),
							   offset_data - LZX_OFFSET_ADJUSTMENT);
			} else {
				/* Repeat offset match: swap offset to front  */
				QUEUE(in_next) =
					lzx_lru_queue_swap(QUEUE(in_next - len),
							   offset_data);
			}
		}
	} while (cur_node != end_node);

	/* Return the match offset queue at the end of the minimum cost path. */
	return QUEUE(block_end);
}

/* Given the costs for the main and length codewords, compute 'match_costs'.  */
static void
lzx_compute_match_costs(struct lzx_compressor *c)
{
	unsigned num_offset_slots = lzx_get_num_offset_slots(c->window_order);
	struct lzx_costs *costs = &c->costs;

	for (unsigned offset_slot = 0; offset_slot < num_offset_slots; offset_slot++) {

		u32 extra_cost = (u32)lzx_extra_offset_bits[offset_slot] * LZX_BIT_COST;
		unsigned main_symbol = lzx_main_symbol_for_match(offset_slot, 0);
		unsigned i;

	#if LZX_CONSIDER_ALIGNED_COSTS
		if (lzx_extra_offset_bits[offset_slot] >= LZX_NUM_ALIGNED_OFFSET_BITS)
			extra_cost -= LZX_NUM_ALIGNED_OFFSET_BITS * LZX_BIT_COST;
	#endif

		for (i = 0; i < LZX_NUM_PRIMARY_LENS; i++)
			costs->match_cost[offset_slot][i] =
				costs->main[main_symbol++] + extra_cost;

		extra_cost += costs->main[main_symbol];

		for (; i < LZX_NUM_LENS; i++)
			costs->match_cost[offset_slot][i] =
				costs->len[i - LZX_NUM_PRIMARY_LENS] + extra_cost;
	}
}

/* Set default LZX Huffman symbol costs to bootstrap the iterative optimization
 * algorithm.  */
static void
lzx_set_default_costs(struct lzx_compressor *c, const u8 *block, u32 block_size)
{
	u32 i;
	bool have_byte[256];
	unsigned num_used_bytes;

	/* The costs below are hard coded to use a scaling factor of 16.  */
	BUILD_BUG_ON(LZX_BIT_COST != 16);

	/*
	 * Heuristics:
	 *
	 * - Use smaller initial costs for literal symbols when the input buffer
	 *   contains fewer distinct bytes.
	 *
	 * - Assume that match symbols are more costly than literal symbols.
	 *
	 * - Assume that length symbols for shorter lengths are less costly than
	 *   length symbols for longer lengths.
	 */

	for (i = 0; i < 256; i++)
		have_byte[i] = false;

	for (i = 0; i < block_size; i++)
		have_byte[block[i]] = true;

	num_used_bytes = 0;
	for (i = 0; i < 256; i++)
		num_used_bytes += have_byte[i];

	for (i = 0; i < 256; i++)
		c->costs.main[i] = 140 - (256 - num_used_bytes) / 4;

	for (; i < c->num_main_syms; i++)
		c->costs.main[i] = 170;

	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		c->costs.len[i] = 103 + (i / 4);

#if LZX_CONSIDER_ALIGNED_COSTS
	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		c->costs.aligned[i] = LZX_NUM_ALIGNED_OFFSET_BITS * LZX_BIT_COST;
#endif

	lzx_compute_match_costs(c);
}

/* Update the current cost model to reflect the computed Huffman codes.  */
static void
lzx_update_costs(struct lzx_compressor *c)
{
	unsigned i;
	const struct lzx_lens *lens = &c->codes[c->codes_index].lens;

	for (i = 0; i < c->num_main_syms; i++)
		c->costs.main[i] = (lens->main[i] ? lens->main[i] : 15) * LZX_BIT_COST;

	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		c->costs.len[i] = (lens->len[i] ? lens->len[i] : 15) * LZX_BIT_COST;

#if LZX_CONSIDER_ALIGNED_COSTS
	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		c->costs.aligned[i] = (lens->aligned[i] ? lens->aligned[i] : 7) * LZX_BIT_COST;
#endif

	lzx_compute_match_costs(c);
}

static struct lzx_lru_queue
lzx_optimize_and_write_block(struct lzx_compressor *c,
			     struct lzx_output_bitstream *os,
			     const u8 *block_begin, const u32 block_size,
			     const struct lzx_lru_queue initial_queue)
{
	unsigned num_passes_remaining = c->num_optim_passes;
	struct lzx_item *chosen_items;
	struct lzx_lru_queue new_queue;

	/* The first optimization pass uses a default cost model.  Each
	 * additional optimization pass uses a cost model derived from the
	 * Huffman code computed in the previous pass.  */

	lzx_set_default_costs(c, block_begin, block_size);
	lzx_reset_symbol_frequencies(c);
	do {
		new_queue = lzx_find_min_cost_path(c, block_begin, block_size,
						   initial_queue);
		if (num_passes_remaining > 1) {
			lzx_tally_item_list(c, block_size);
			lzx_make_huffman_codes(c);
			lzx_update_costs(c);
			lzx_reset_symbol_frequencies(c);
		}
	} while (--num_passes_remaining);

	chosen_items = lzx_record_item_list(c, block_size);
	lzx_finish_block(c, os, block_begin, block_size, chosen_items);
	return new_queue;
}

/*
 * This is the "near-optimal" LZX compressor.
 *
 * For each block, it performs a relatively thorough graph search to find an
 * inexpensive (in terms of compressed size) way to output that block.
 *
 * Note: there are actually many things this algorithm leaves on the table in
 * terms of compression ratio.  So although it may be "near-optimal", it is
 * certainly not "optimal".  The goal is not to produce the optimal compression
 * ratio, which for LZX is probably impossible within any practical amount of
 * time, but rather to produce a compression ratio significantly better than a
 * simpler "greedy" or "lazy" parse while still being relatively fast.
 */
static void
lzx_compress_near_optimal(struct lzx_compressor *c,
			  struct lzx_output_bitstream *os)
{
	const u8 * const in_begin = c->in_buffer;
	const u8 *	 in_next = in_begin;
	const u8 * const in_end  = in_begin + c->in_nbytes;
	unsigned max_len = LZX_MAX_MATCH_LEN;
	unsigned nice_len = min(c->nice_match_length, max_len);
	u32 next_hash;
	struct lzx_lru_queue queue;

	bt_matchfinder_init(&c->bt_mf);
	matchfinder_init(c->hash2_tab, LZX_HASH2_LENGTH);
	next_hash = bt_matchfinder_hash_3_bytes(in_next);
	lzx_lru_queue_init(&queue);

	do {
		/* Starting a new block  */
		const u8 * const in_block_begin = in_next;
		const u8 * const in_block_end =
			in_next + min(LZX_DIV_BLOCK_SIZE, in_end - in_next);

		/* Run the block through the matchfinder and cache the matches. */
		struct lz_match *cache_ptr = c->match_cache;
		do {
			struct lz_match *lz_matchptr;
			u32 hash2;
			pos_t cur_match;
			unsigned best_len;

			/* If approaching the end of the input buffer, adjust
			 * 'max_len' and 'nice_len' accordingly.  */
			if (unlikely(max_len > in_end - in_next)) {
				max_len = in_end - in_next;
				nice_len = min(max_len, nice_len);

				/* This extra check is needed to ensure that we
				 * never output a length 2 match of the very
				 * last two bytes with the very first two bytes,
				 * since such a match has an offset too large to
				 * be represented.  */
				if (unlikely(max_len < 3)) {
					in_next++;
					cache_ptr->length = 0;
					cache_ptr++;
					continue;
				}
			}

			lz_matchptr = cache_ptr + 1;

			/* Check for a length 2 match.  */
			hash2 = lz_hash_2_bytes(in_next, LZX_HASH2_ORDER);
			cur_match = c->hash2_tab[hash2];
			c->hash2_tab[hash2] = in_next - in_begin;
			if (matchfinder_node_valid(cur_match) &&
			    (LZX_HASH2_ORDER == 16 ||
			     load_u16_unaligned(&in_begin[cur_match]) ==
			     load_u16_unaligned(in_next)))
			{
				lz_matchptr->length = 2;
				lz_matchptr->offset = in_next - &in_begin[cur_match];
				lz_matchptr++;
			}

			/* Check for matches of length >= 3.  */
			lz_matchptr = bt_matchfinder_get_matches(&c->bt_mf,
								 in_begin,
								 in_next,
								 3,
								 max_len,
								 nice_len,
								 c->max_search_depth,
								 &next_hash,
								 &best_len,
								 lz_matchptr);
			in_next++;
			cache_ptr->length = lz_matchptr - (cache_ptr + 1);
			cache_ptr = lz_matchptr;

			/*
			 * If there was a very long match found, then don't
			 * cache any matches for the bytes covered by that
			 * match.  This avoids degenerate behavior when
			 * compressing highly redundant data, where the number
			 * of matches can be very large.
			 *
			 * This heuristic doesn't actually hurt the compression
			 * ratio very much.  If there's a long match, then the
			 * data must be highly compressible, so it doesn't
			 * matter as much what we do.
			 */
			if (best_len >= nice_len) {
				--best_len;
				do {
					if (unlikely(max_len > in_end - in_next)) {
						max_len = in_end - in_next;
						nice_len = min(max_len, nice_len);
						if (unlikely(max_len < 3)) {
							in_next++;
							cache_ptr->length = 0;
							cache_ptr++;
							continue;
						}
					}
					c->hash2_tab[lz_hash_2_bytes(in_next, LZX_HASH2_ORDER)] =
						in_next - in_begin;
					bt_matchfinder_skip_position(&c->bt_mf,
								     in_begin,
								     in_next,
								     in_end,
								     nice_len,
								     c->max_search_depth,
								     &next_hash);
					in_next++;
					cache_ptr->length = 0;
					cache_ptr++;
				} while (--best_len);
			}
		} while (in_next < in_block_end &&
			 likely(cache_ptr < &c->match_cache[LZX_CACHE_LENGTH]));

		/* We've finished running the block through the matchfinder.
		 * Now choose a match/literal sequence and write the block.  */

		queue = lzx_optimize_and_write_block(c, os, in_block_begin,
						     in_next - in_block_begin,
						     queue);
	} while (in_next != in_end);
}

/*
 * Given a pointer to the current byte sequence and the current list of recent
 * match offsets, find the longest repeat offset match.
 *
 * If no match of at least 2 bytes is found, then return 0.
 *
 * If a match of at least 2 bytes is found, then return its length and set
 * *rep_max_idx_ret to the index of its offset in @queue.
*/
static unsigned
lzx_find_longest_repeat_offset_match(const u8 * const in_next,
				     const u32 bytes_remaining,
				     struct lzx_lru_queue queue,
				     unsigned *rep_max_idx_ret)
{
	BUILD_BUG_ON(LZX_NUM_RECENT_OFFSETS != 3);
	LZX_ASSERT(bytes_remaining >= 2);

	const unsigned max_len = min(bytes_remaining, LZX_MAX_MATCH_LEN);
	const u16 next_2_bytes = load_u16_unaligned(in_next);
	const u8 *matchptr;
	unsigned rep_max_len;
	unsigned rep_max_idx;
	unsigned rep_len;

	matchptr = in_next - lzx_lru_queue_pop(&queue);
	if (load_u16_unaligned(matchptr) == next_2_bytes)
		rep_max_len = lz_extend(in_next, matchptr, 2, max_len);
	else
		rep_max_len = 0;
	rep_max_idx = 0;

	matchptr = in_next - lzx_lru_queue_pop(&queue);
	if (load_u16_unaligned(matchptr) == next_2_bytes) {
		rep_len = lz_extend(in_next, matchptr, 2, max_len);
		if (rep_len > rep_max_len) {
			rep_max_len = rep_len;
			rep_max_idx = 1;
		}
	}

	matchptr = in_next - lzx_lru_queue_pop(&queue);
	if (load_u16_unaligned(matchptr) == next_2_bytes) {
		rep_len = lz_extend(in_next, matchptr, 2, max_len);
		if (rep_len > rep_max_len) {
			rep_max_len = rep_len;
			rep_max_idx = 2;
		}
	}

	*rep_max_idx_ret = rep_max_idx;
	return rep_max_len;
}

/* Fast heuristic scoring for lazy parsing: how "good" is this match?  */
static inline unsigned
lzx_explicit_offset_match_score(unsigned len, u32 adjusted_offset)
{
	unsigned score = len;

	if (adjusted_offset < 4096)
		score++;

	if (adjusted_offset < 256)
		score++;

	return score;
}

static inline unsigned
lzx_repeat_offset_match_score(unsigned rep_len, unsigned rep_idx)
{
	return rep_len + 3;
}

/* This is the "lazy" LZX compressor.  */
static void
lzx_compress_lazy(struct lzx_compressor *c, struct lzx_output_bitstream *os)
{
	const u8 * const in_begin = c->in_buffer;
	const u8 *	 in_next = in_begin;
	const u8 * const in_end  = in_begin + c->in_nbytes;
	unsigned max_len = LZX_MAX_MATCH_LEN;
	unsigned nice_len = min(c->nice_match_length, max_len);
	struct lzx_lru_queue queue;

	hc_matchfinder_init(&c->hc_mf);
	lzx_lru_queue_init(&queue);

	do {
		/* Starting a new block  */

		const u8 * const in_block_begin = in_next;
		const u8 * const in_block_end =
			in_next + min(LZX_DIV_BLOCK_SIZE, in_end - in_next);
		struct lzx_item *next_chosen_item = c->chosen_items;
		unsigned cur_len;
		u32 cur_offset;
		u32 cur_offset_data;
		unsigned cur_score;
		unsigned next_len;
		u32 next_offset;
		u32 next_offset_data;
		unsigned next_score;
		unsigned rep_max_len;
		unsigned rep_max_idx;
		unsigned rep_score;
		unsigned skip_len;

		lzx_reset_symbol_frequencies(c);

		do {
			if (unlikely(max_len > in_end - in_next)) {
				max_len = in_end - in_next;
				nice_len = min(max_len, nice_len);
			}

			/* Find the longest match at the current position.  */

			cur_len = hc_matchfinder_longest_match(&c->hc_mf,
							       in_begin,
							       in_next,
							       2,
							       max_len,
							       nice_len,
							       c->max_search_depth,
							       &cur_offset);
			if (cur_len < 3 ||
			    (cur_len == 3 &&
			     cur_offset >= 8192 - LZX_OFFSET_ADJUSTMENT &&
			     cur_offset != lzx_lru_queue_R0(queue) &&
			     cur_offset != lzx_lru_queue_R1(queue) &&
			     cur_offset != lzx_lru_queue_R2(queue)))
			{
				/* There was no match found, or the only match found
				 * was a distant length 3 match.  Output a literal.  */
				lzx_declare_literal(c, *in_next++,
						    &next_chosen_item);
				continue;
			}

			if (cur_offset == lzx_lru_queue_R0(queue)) {
				in_next++;
				cur_offset_data = 0;
				skip_len = cur_len - 1;
				goto choose_cur_match;
			}

			cur_offset_data = cur_offset + LZX_OFFSET_ADJUSTMENT;
			cur_score = lzx_explicit_offset_match_score(cur_len, cur_offset_data);

			/* Consider a repeat offset match  */
			rep_max_len = lzx_find_longest_repeat_offset_match(in_next,
									   in_end - in_next,
									   queue,
									   &rep_max_idx);
			in_next++;

			if (rep_max_len >= 3 &&
			    (rep_score = lzx_repeat_offset_match_score(rep_max_len,
								       rep_max_idx)) >= cur_score)
			{
				cur_len = rep_max_len;
				cur_offset_data = rep_max_idx;
				skip_len = rep_max_len - 1;
				goto choose_cur_match;
			}

		have_cur_match:

			/* We have a match at the current position.  */

			/* If we have a very long match, choose it immediately.  */
			if (cur_len >= nice_len) {
				skip_len = cur_len - 1;
				goto choose_cur_match;
			}

			/* See if there's a better match at the next position.  */

			if (unlikely(max_len > in_end - in_next)) {
				max_len = in_end - in_next;
				nice_len = min(max_len, nice_len);
			}

			next_len = hc_matchfinder_longest_match(&c->hc_mf,
								in_begin,
								in_next,
								cur_len - 2,
								max_len,
								nice_len,
								c->max_search_depth / 2,
								&next_offset);

			if (next_len <= cur_len - 2) {
				in_next++;
				skip_len = cur_len - 2;
				goto choose_cur_match;
			}

			next_offset_data = next_offset + LZX_OFFSET_ADJUSTMENT;
			next_score = lzx_explicit_offset_match_score(next_len, next_offset_data);

			rep_max_len = lzx_find_longest_repeat_offset_match(in_next,
									   in_end - in_next,
									   queue,
									   &rep_max_idx);
			in_next++;

			if (rep_max_len >= 3 &&
			    (rep_score = lzx_repeat_offset_match_score(rep_max_len,
								       rep_max_idx)) >= next_score)
			{

				if (rep_score > cur_score) {
					/* The next match is better, and it's a
					 * repeat offset match.  */
					lzx_declare_literal(c, *(in_next - 2),
							    &next_chosen_item);
					cur_len = rep_max_len;
					cur_offset_data = rep_max_idx;
					skip_len = cur_len - 1;
					goto choose_cur_match;
				}
			} else {
				if (next_score > cur_score) {
					/* The next match is better, and it's an
					 * explicit offset match.  */
					lzx_declare_literal(c, *(in_next - 2),
							    &next_chosen_item);
					cur_len = next_len;
					cur_offset_data = next_offset_data;
					cur_score = next_score;
					goto have_cur_match;
				}
			}

			/* The original match was better.  */
			skip_len = cur_len - 2;

		choose_cur_match:
			if (cur_offset_data < LZX_NUM_RECENT_OFFSETS) {
				lzx_declare_repeat_offset_match(c, cur_len,
								cur_offset_data,
								&next_chosen_item);
				queue = lzx_lru_queue_swap(queue, cur_offset_data);
			} else {
				lzx_declare_explicit_offset_match(c, cur_len,
								  cur_offset_data - LZX_OFFSET_ADJUSTMENT,
								  &next_chosen_item);
				queue = lzx_lru_queue_push(queue, cur_offset_data - LZX_OFFSET_ADJUSTMENT);
			}

			hc_matchfinder_skip_positions(&c->hc_mf,
						      in_begin,
						      in_next,
						      in_end,
						      skip_len);
			in_next += skip_len;
		} while (in_next < in_block_end);

		lzx_finish_block(c, os, in_block_begin, in_next - in_block_begin,
				 c->chosen_items);
	} while (in_next != in_end);
}

static void
lzx_init_offset_slot_fast(struct lzx_compressor *c)
{
	u8 slot = 0;

	for (u32 adjusted_offset = 0;
	     adjusted_offset < LZX_NUM_FAST_OFFSETS + LZX_NUM_RECENT_OFFSETS;
	     adjusted_offset++)
	{
		while (adjusted_offset >= lzx_offset_slot_base[slot + 1])
			slot++;
		c->offset_slot_fast[adjusted_offset] = slot;
	}
}

static size_t
lzx_get_compressor_size(size_t max_bufsize, unsigned compression_level)
{
	if (compression_level <= LZX_MAX_FAST_LEVEL) {
		return offsetof(struct lzx_compressor, hc_mf) +
			hc_matchfinder_size(max_bufsize);
	} else {
		return offsetof(struct lzx_compressor, bt_mf) +
			bt_matchfinder_size(max_bufsize);
	}
}

static u64
lzx_get_needed_memory(size_t max_bufsize, unsigned compression_level,
		      bool destructive)
{
	u64 size = 0;

	if (max_bufsize > LZX_MAX_WINDOW_SIZE)
		return 0;

	size += lzx_get_compressor_size(max_bufsize, compression_level);
	if (!destructive)
		size += max_bufsize; /* in_buffer */
	return size;
}

static int
lzx_create_compressor(size_t max_bufsize, unsigned compression_level,
		      bool destructive, void **c_ret)
{
	unsigned window_order;
	struct lzx_compressor *c;

	window_order = lzx_get_window_order(max_bufsize);
	if (window_order == 0)
		return WIMLIB_ERR_INVALID_PARAM;

	c = ALIGNED_MALLOC(lzx_get_compressor_size(max_bufsize,
						   compression_level),
			   MATCHFINDER_ALIGNMENT);
	if (!c)
		goto oom0;

	c->destructive = destructive;

	c->num_main_syms = lzx_get_num_main_syms(window_order);
	c->window_order = window_order;

	if (!c->destructive) {
		c->in_buffer = MALLOC(max_bufsize);
		if (!c->in_buffer)
			goto oom1;
	}

	if (compression_level <= LZX_MAX_FAST_LEVEL) {

		/* Fast compression: Use lazy parsing.  */

		c->impl = lzx_compress_lazy;
		c->max_search_depth = (36 * compression_level) / 20;
		c->nice_match_length = (72 * compression_level) / 20;

		/* lzx_compress_lazy() needs max_search_depth >= 2 because it
		 * halves the max_search_depth when attempting a lazy match, and
		 * max_search_depth cannot be 0.  */
		if (c->max_search_depth < 2)
			c->max_search_depth = 2;
	} else {

		/* Normal / high compression: Use near-optimal parsing.  */

		c->impl = lzx_compress_near_optimal;

		/* Scale nice_match_length and max_search_depth with the
		 * compression level.  */
		c->max_search_depth = (24 * compression_level) / 50;
		c->nice_match_length = (32 * compression_level) / 50;

		/* Set a number of optimization passes appropriate for the
		 * compression level.  */

		c->num_optim_passes = 1;

		if (compression_level >= 45)
			c->num_optim_passes++;

		/* Use more optimization passes for higher compression levels.
		 * But the more passes there are, the less they help --- so
		 * don't add them linearly.  */
		if (compression_level >= 70) {
			c->num_optim_passes++;
			if (compression_level >= 100)
				c->num_optim_passes++;
			if (compression_level >= 150)
				c->num_optim_passes++;
			if (compression_level >= 200)
				c->num_optim_passes++;
			if (compression_level >= 300)
				c->num_optim_passes++;
		}
	}

	/* max_search_depth == 0 is invalid.  */
	if (c->max_search_depth < 1)
		c->max_search_depth = 1;

	if (c->nice_match_length > LZX_MAX_MATCH_LEN)
		c->nice_match_length = LZX_MAX_MATCH_LEN;

	lzx_init_offset_slot_fast(c);
	*c_ret = c;
	return 0;

oom1:
	ALIGNED_FREE(c);
oom0:
	return WIMLIB_ERR_NOMEM;
}

static size_t
lzx_compress(const void *restrict in, size_t in_nbytes,
	     void *restrict out, size_t out_nbytes_avail, void *restrict _c)
{
	struct lzx_compressor *c = _c;
	struct lzx_output_bitstream os;
	size_t result;

	/* Don't bother trying to compress very small inputs.  */
	if (in_nbytes < 100)
		return 0;

	/* Copy the input data into the internal buffer and preprocess it.  */
	if (c->destructive)
		c->in_buffer = (void *)in;
	else
		memcpy(c->in_buffer, in, in_nbytes);
	c->in_nbytes = in_nbytes;
	lzx_do_e8_preprocessing(c->in_buffer, in_nbytes);

	/* Initially, the previous Huffman codeword lengths are all zeroes.  */
	c->codes_index = 0;
	memset(&c->codes[1].lens, 0, sizeof(struct lzx_lens));

	/* Initialize the output bitstream.  */
	lzx_init_output(&os, out, out_nbytes_avail);

	/* Call the compression level-specific compress() function.  */
	(*c->impl)(c, &os);

	/* Flush the output bitstream and return the compressed size or 0.  */
	result = lzx_flush_output(&os);
	if (!result && c->destructive)
		lzx_undo_e8_preprocessing(c->in_buffer, c->in_nbytes);
	return result;
}

static void
lzx_free_compressor(void *_c)
{
	struct lzx_compressor *c = _c;

	if (!c->destructive)
		FREE(c->in_buffer);
	ALIGNED_FREE(c);
}

const struct compressor_ops lzx_compressor_ops = {
	.get_needed_memory  = lzx_get_needed_memory,
	.create_compressor  = lzx_create_compressor,
	.compress	    = lzx_compress,
	.free_compressor    = lzx_free_compressor,
};
