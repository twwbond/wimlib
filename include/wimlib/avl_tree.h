/*
 * avl_tree.h
 *
 * Intrusive, nonrecursive AVL tree data structure (self-balancing binary search
 * tree), header file.
 *
 * Author:  Eric Biggers
 * Year:    2014
 *
 * This file is placed into the public domain.  You can do whatever you want
 * with it.
 */

#ifndef _AVL_TREE_H_
#define _AVL_TREE_H_

#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h> /* for uintptr_t */

#ifdef __GNUC__
#  define AVL_INLINE inline __attribute__((always_inline))
#else
#  define AVL_INLINE inline
#  warning "AVL tree functions may not be inlined as intended"
#endif

/* Node in an AVL tree.  Embed this in some other data structure.  */
struct avl_tree_node {

	/* Pointer to left child or NULL  */
	struct avl_tree_node *left;

	/* Pointer to right child or NULL  */
	struct avl_tree_node *right;

	/* Pointer to parent combined with the balance factor.  This saves 4 or
	 * 8 bytes of memory depending on the CPU architecture.
	 *
	 * Low 2 bits:  One greater than the balance factor of this subtree,
	 * which is equal to height(right) - height(left).  The mapping is:
	 *
	 * 00 => -1
	 * 01 =>  0
	 * 10 => +1
	 * 11 => undefined
	 *
	 * The rest of the bits are the pointer to the parent node.  It must be
	 * 4-byte aligned, and it will be NULL if this is the root node and
	 * therefore has no parent.  */
	uintptr_t parent_balance;
};

/* Cast an AVL tree node to the containing data structure.  */
#define avl_tree_entry(entry, type, member) \
	((type*) ((char *)(entry) - offsetof(type, member)))

/* Returns a pointer to the parent of the specified AVL tree node, or NULL if it
 * is already the root of the tree.  */
static AVL_INLINE struct avl_tree_node *
avl_get_parent(const struct avl_tree_node *node)
{
	return (struct avl_tree_node *)(node->parent_balance & ~3);
}

/* Marks the specified AVL tree node as unlinked from any tree.  */
static AVL_INLINE void
avl_tree_node_set_unlinked(struct avl_tree_node *node)
{
	node->parent_balance = (uintptr_t)node;
}

/* Returns true iff the specified AVL tree node has been marked with
 * avl_tree_node_set_unlinked() and has not subsequently been inserted into a
 * tree.  */
static AVL_INLINE bool
avl_tree_node_is_unlinked(const struct avl_tree_node *node)
{
	return node->parent_balance == (uintptr_t)node;
}

/* (Internal use only)  */
extern void
avl_tree_rebalance_after_insert(struct avl_tree_node **root_ptr,
				struct avl_tree_node *inserted);

/*
 * Looks up an item in the specified AVL tree.
 *
 * @root
 *	Pointer to the root of the AVL tree.  (This can be NULL --- that just
 *	means the tree is empty.)
 *
 * @cmp_ctx
 *	First argument to pass to the comparison callback.  This generally
 *	should be a pointer to an object equal to the one being searched for.
 *
 * @cmp
 *	Comparison callback.  Must return < 0, 0, or > 0 if the first argument
 *	is less than, equal to, or greater than the second argument,
 *	respectively.  The first argument will be @cmp_ctx and the second
 *	argument will be a pointer to the AVL tree node of an item in the tree.
 *
 * Returns a pointer to the AVL tree node of the resulting item, or NULL if the
 * item was not found.
 */
static AVL_INLINE struct avl_tree_node *
avl_tree_lookup(const struct avl_tree_node *root,
		const void *cmp_ctx,
		int (*cmp)(const void *, const struct avl_tree_node *))
{
	const struct avl_tree_node *cur = root;

	while (cur) {
		int res = (*cmp)(cmp_ctx, cur);
		if (res < 0)
			cur = cur->left;
		else if (res > 0)
			cur = cur->right;
		else
			break;
	}
	return (struct avl_tree_node*)cur;
}

/* Same as avl_tree_lookup(), but uses a more specific type for the comparison
 * function.  Specifically, with this function the item being searched for is
 * expected to be in the same format as those already in the tree, with an
 * embedded 'struct avl_tree_node'.  */
static AVL_INLINE struct avl_tree_node *
avl_tree_lookup_node(const struct avl_tree_node *root,
		     const struct avl_tree_node *node,
		     int (*cmp)(const struct avl_tree_node *,
				const struct avl_tree_node *))
{
	return avl_tree_lookup(root,
			       (const void *)node,
			       (int (*) (const void *,
					 const struct avl_tree_node *))cmp);
}

/*
 * Inserts an item into the specified AVL tree.
 *
 * @root_ptr
 *	Location of the AVL tree's root pointer.  Indirection is needed because
 *	the root node may change as a result of rotations caused by the
 *	insertion.  Initialize *root_ptr to NULL for an empty tree.
 *
 * @item
 *	Pointer to the `struct avl_tree_node' embedded in the item to insert.
 *	No members in it need be pre-initialized, although members in the
 *	containing structure should be pre-initialized so that @cmp can use them
 *	in comparisons.
 *
 * @cmp
 *	Comparison callback.  Must return < 0, 0, or > 0 if the first argument
 *	is less than, equal to, or greater than the second argument,
 *	respectively.  The first argument will be @item and the second
 *	argument will be a pointer to an AVL tree node embedded in some
 *	previously-inserted item to which @item is being compared.
 *
 * If no item in the tree is comparatively equal (via @cmp) to @item, inserts
 * @item and returns NULL.  Otherwise does nothing and returns a pointer to the
 * AVL tree node embedded in the previously-inserted item which compared equal
 * to @item.
 */
static AVL_INLINE struct avl_tree_node *
avl_tree_insert(struct avl_tree_node **root_ptr,
		struct avl_tree_node *item,
		int (*cmp)(const struct avl_tree_node *,
			   const struct avl_tree_node *))
{
	struct avl_tree_node **cur_ptr = root_ptr, *cur = NULL;
	int res;

	while (*cur_ptr) {
		cur = *cur_ptr;
		res = (*cmp)(item, cur);
		if (res < 0)
			cur_ptr = &cur->left;
		else if (res > 0)
			cur_ptr = &cur->right;
		else
			return cur;
	}
	*cur_ptr = item;
	item->parent_balance = (uintptr_t)cur | 1;
	avl_tree_rebalance_after_insert(root_ptr, item);
	return NULL;
}

/* Removes an item from the specified AVL tree.
 * See implementation for details.  */
extern void
avl_tree_remove(struct avl_tree_node **root_ptr, struct avl_tree_node *node);

/* Nonrecursive AVL tree traversal functions  */

extern struct avl_tree_node *
avl_tree_first_in_order(const struct avl_tree_node *root);

extern struct avl_tree_node *
avl_tree_next_in_order(const struct avl_tree_node *prev);

extern struct avl_tree_node *
avl_tree_first_in_postorder(const struct avl_tree_node *root);

extern struct avl_tree_node *
avl_tree_next_in_postorder(const struct avl_tree_node *prev,
			   const struct avl_tree_node *prev_parent);

#endif /* _AVL_TREE_H_ */
