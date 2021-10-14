/*
 * Copyright (c) 2017-2021, Alibaba Group Holding Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>

#include "pfs_avl.h"
#include "pfs_impl.h"

#define	PFS_AVL_BEFORE	(0)
#define	PFS_AVL_AFTER	(1)

#define PFS_CHILD_SHIFT		(2)
#define PFS_PARENT_SHIFT	(3)
#define PFS_PARENT_MASK		((uintptr_t)((1 << PFS_PARENT_SHIFT) - 1))
#define PFS_BALANCE_MASK	((uintptr_t)((1 << PFS_CHILD_SHIFT) - 1))

static const int child2balance[2] = {-1, 1};
/* [0]= left child, [2]= right child */
static const int balance2child[] = {0, 0, 1};

static inline pfs_avl_node_t *
pfs_avl_node_parent(const pfs_avl_node_t *node)
{
	return (pfs_avl_node_t *)(node->avl_pcb & ~PFS_PARENT_MASK);
}

static inline void
pfs_avl_node_setparent(pfs_avl_node_t *node, const pfs_avl_node_t *parent)
{
	node->avl_pcb = (node->avl_pcb & PFS_PARENT_MASK) | (uintptr_t)parent;
}

static inline int
pfs_avl_node_child(const pfs_avl_node_t *node)
{
	return (node->avl_pcb >> PFS_CHILD_SHIFT) & (uintptr_t)1;
}

static inline void
pfs_avl_node_setchild(pfs_avl_node_t *node, int child)
{
	node->avl_pcb = (uintptr_t)((node->avl_pcb &
	    ~(uintptr_t)(1 << PFS_CHILD_SHIFT)) | (child << PFS_CHILD_SHIFT));
}

static inline void *
pfs_avl_node2data(pfs_avl_node_t *node, size_t off)
{
	return (void *)((uintptr_t)node - off);
}

static inline pfs_avl_node_t *
pfs_avl_data2node(void *data, size_t off)
{
	return (pfs_avl_node_t *)((uintptr_t)data + off);
}

static inline int
pfs_avl_node_balance(const pfs_avl_node_t *node)
{
	return (int)((node->avl_pcb & PFS_BALANCE_MASK) - 1);
}

static inline void
pfs_avl_node_setbalance(pfs_avl_node_t *node, int balance)
{
	node->avl_pcb = (uintptr_t)((node->avl_pcb & ~PFS_BALANCE_MASK) |
	    (balance + 1));
}

static inline uintptr_t
pfs_avl_mkindex(pfs_avl_node_t *node, int direction)
{
	return (uintptr_t)node | direction;
}

static inline int
pfs_avl_index2child(uintptr_t where)
{
	return where & (uintptr_t)1;
}

static inline pfs_avl_node_t *
pfs_avl_index2node(uintptr_t where)
{
	return (pfs_avl_node_t *)(where & ~(uintptr_t)1);
}

static void *
pfs_avl_walk(pfs_avl_tree_t *tree, void *data, int left)
{
	int child;
	int right = 1 - left;
	size_t off = tree->avl_offset;
	pfs_avl_node_t *node = pfs_avl_data2node(data, off);

	if (!node)
		return NULL;

	if (node->avl_child[left]) {
		node = node->avl_child[left];
		while (node->avl_child[right])
			node = node->avl_child[right];
		return pfs_avl_node2data(node, off);
	}

	for (;;) {
		child = pfs_avl_node_child(node);
		node = pfs_avl_node_parent(node);
		if (node == NULL)
			return NULL;
		if (child == right)
			break;
	}

	return pfs_avl_node2data(node, off);
}

static void *
pfs_avl_outermost(pfs_avl_tree_t *tree, const int direction)
{
	pfs_avl_node_t *node, *prev = NULL;
	size_t off = tree->avl_offset;

	/* keep advancing node towards direction-most position */
	for (node = tree->avl_root; node; node = node->avl_child[direction])
		prev = node;

	return prev ? pfs_avl_node2data(prev, off) : NULL;
}

static int
pfs_avl_rotation(pfs_avl_tree_t *tree, pfs_avl_node_t *node, int balance)
{
	int left = !(balance < 0); /* when balance = -2, left will be 0 */
	int right = 1 - left;
	int lheavy = balance >> 1;
	int rheavy = -lheavy;
	pfs_avl_node_t *parent = pfs_avl_node_parent(node);
	pfs_avl_node_t *child = node->avl_child[left];
	pfs_avl_node_t *cright, *gchild, *gright, *gleft;
	int which_child = pfs_avl_node_child(node);
	int child_bal = pfs_avl_node_balance(child);

	if (child_bal != rheavy) {
		child_bal += rheavy;

		cright = child->avl_child[right];
		node->avl_child[left] = cright;
		if (cright) {
			pfs_avl_node_setparent(cright, node);
			pfs_avl_node_setchild(cright, left);
		}

		child->avl_child[right] = node;
		pfs_avl_node_setbalance(node, -child_bal);
		pfs_avl_node_setchild(node, right);
		pfs_avl_node_setparent(node, child);

		pfs_avl_node_setbalance(child, child_bal);
		pfs_avl_node_setchild(child, which_child);
		pfs_avl_node_setparent(child, parent);
		if (parent)
			parent->avl_child[which_child] = child;
		else
			tree->avl_root = child;

		return child_bal == 0;
	}

	gchild = child->avl_child[right];
	gleft = gchild->avl_child[left];
	gright = gchild->avl_child[right];

	node->avl_child[left] = gright;
	if (gright) {
		pfs_avl_node_setparent(gright, node);
		pfs_avl_node_setchild(gright, left);
	}

	child->avl_child[right] = gleft;
	if (gleft) {
		pfs_avl_node_setparent(gleft, child);
		pfs_avl_node_setchild(gleft, right);
	}

	balance = pfs_avl_node_balance(gchild);
	gchild->avl_child[left] = child;
	pfs_avl_node_setbalance(child, (balance == rheavy ? lheavy : 0));
	pfs_avl_node_setparent(child, gchild);
	pfs_avl_node_setchild(child, left);

	gchild->avl_child[right] = node;
	pfs_avl_node_setbalance(node, (balance == lheavy ? rheavy : 0));
	pfs_avl_node_setparent(node, gchild);
	pfs_avl_node_setchild(node, right);

	pfs_avl_node_setbalance(gchild, 0);
	pfs_avl_node_setparent(gchild, parent);
	pfs_avl_node_setchild(gchild, which_child);
	if (parent)
		parent->avl_child[which_child] = gchild;
	else
		tree->avl_root = gchild;

	return 1;
}

static void
pfs_avl_insert(pfs_avl_tree_t *tree, void *data, uintptr_t where)
{
	size_t off = tree->avl_offset;
	int obalance, nbalance;
	int child = pfs_avl_index2child(where);
	pfs_avl_node_t *node = pfs_avl_data2node(data, off);
	pfs_avl_node_t *parent = pfs_avl_index2node(where);

	PFS_ASSERT(((uintptr_t)data & 0x7) == 0);

	node->avl_child[0] = node->avl_child[1] = NULL;
	pfs_avl_node_setparent(node, parent);
	pfs_avl_node_setchild(node, child);
	pfs_avl_node_setbalance(node, 0);
	++tree->avl_numnodes;

	/* empty tree */
	if (parent == NULL) {
		PFS_ASSERT(tree->avl_root == NULL);
		tree->avl_root = node;
		return;
	}

	/* insert node */
	PFS_ASSERT(parent->avl_child[child] == NULL);
	parent->avl_child[child] = node;

	/* follow parent ptrs upwards, updating the balances along the way */
	for (node = parent; node; node = parent) {
		obalance = pfs_avl_node_balance(node);
		nbalance = obalance + child2balance[child];
		if (nbalance == 0) {
			pfs_avl_node_setbalance(node, 0);
			return;
		}
		if (obalance != 0) {
			/* unbalanced and rotate */
			pfs_avl_rotation(tree, node, nbalance);
			return;
		}
		pfs_avl_node_setbalance(node, nbalance);
		child = pfs_avl_node_child(node);
		parent = pfs_avl_node_parent(node);
	}
}

static void
pfs_detach_noninterior(pfs_avl_tree_t *tree, const pfs_avl_node_t *node)
{
	pfs_avl_node_t *parent = pfs_avl_node_parent(node), *child = NULL;
	int b = pfs_avl_node_balance(node);
	int childidx = pfs_avl_node_child(node);
	if (b == 0) {
		PFS_ASSERT(node->avl_child[0] == NULL);
		PFS_ASSERT(node->avl_child[1] == NULL);
	} else {
		child = node->avl_child[balance2child[b + 1]];
		pfs_avl_node_setparent(child, parent);
		pfs_avl_node_setchild(child, childidx);
	}
	if (parent) {
		parent->avl_child[childidx] = child;
	} else {
		tree->avl_root = child;
	}
}

void *
pfs_avl_first(pfs_avl_tree_t *tree)
{
	return pfs_avl_outermost(tree, PFS_AVL_BEFORE);
}

void *
pfs_avl_last(pfs_avl_tree_t *tree)
{
	return pfs_avl_outermost(tree, PFS_AVL_AFTER);
}

void *
pfs_avl_next(pfs_avl_tree_t *tree, void *data)
{
	return pfs_avl_walk(tree, data, PFS_AVL_AFTER);
}

void *
pfs_avl_prev(pfs_avl_tree_t *tree, void *data)
{
	return pfs_avl_walk(tree, data, PFS_AVL_BEFORE);
}

void *
pfs_avl_find(pfs_avl_tree_t *tree, const void *value, uintptr_t *where)
{
	int direction = 0, diff;
	pfs_avl_node_t *node, *prev = NULL;
	size_t off = tree->avl_offset;

	for (node = tree->avl_root; node; node = node->avl_child[direction]) {
		prev = node;
		diff = tree->avl_compar(value, pfs_avl_node2data(node, off));
		PFS_ASSERT(-1 <= diff && diff <= 1);
		if (diff != 0) {
			direction = balance2child[1 + diff];
			continue;
		}

		return pfs_avl_node2data(node, off);
	}

	if (where)
		*where = pfs_avl_mkindex(prev, direction);
	return NULL;
}

void
pfs_avl_add(pfs_avl_tree_t *tree, void *new_node)
{
	void *data;
	uintptr_t where;

	data = pfs_avl_find(tree, new_node, &where);
	PFS_ASSERT(data == NULL);
	pfs_avl_insert(tree, new_node, where);
}

void
pfs_avl_remove(pfs_avl_tree_t *tree, void *data)
{
	size_t off = tree->avl_offset;
	pfs_avl_node_t *node = pfs_avl_data2node(data, off);
	pfs_avl_node_t *parent = pfs_avl_node_parent(node);
	int childidx = pfs_avl_node_child(node);
	pfs_avl_node_t tmp, *subst;

	PFS_ASSERT(tree->avl_numnodes > 0);
	--tree->avl_numnodes;

	/*
	 * remove any node
	 * Naively, for interior node, we subst its val w/ nearest
	 * non-interior, and rm that non-interior instead.
	 * However, since users manage the memory, we operate on
	 * pfs_avl_node_t field to achieve substitution.
	 */
	if (node->avl_child[0] && node->avl_child[1]) {
		childidx = balance2child[pfs_avl_node_balance(node) + 1];
		subst = pfs_avl_data2node(pfs_avl_walk(tree, data, childidx), off);

		tmp = *subst;
		*subst = *node;
		if (pfs_avl_node_parent(&tmp) == node)
			subst->avl_child[pfs_avl_node_child(&tmp)] = &tmp;

		childidx = pfs_avl_node_child(subst);
		if (parent)
			parent->avl_child[childidx] = subst;
		else
			tree->avl_root = subst;

		pfs_avl_node_setparent(subst->avl_child[0], subst);
		pfs_avl_node_setparent(subst->avl_child[1], subst);

		/*
		 * attach tmp to subst position s.t. we can
		 * use common code removing non-interior
		 */
		parent = pfs_avl_node_parent(&tmp);
		parent->avl_child[pfs_avl_node_child(&tmp)] = &tmp;
		childidx = balance2child[pfs_avl_node_balance(&tmp) + 1];
		if (tmp.avl_child[childidx])
			pfs_avl_node_setparent(tmp.avl_child[childidx], &tmp);
		childidx = pfs_avl_node_child(&tmp);
		node = &tmp;
	}

	pfs_detach_noninterior(tree, node);

	for (node = parent; node; node = parent) {
		int old_balance = pfs_avl_node_balance(node);
		int new_balance = old_balance - child2balance[childidx];
		parent = pfs_avl_node_parent(node);
		childidx = pfs_avl_node_child(node);
		if (old_balance == 0) {
			pfs_avl_node_setbalance(node, new_balance);
			return;
		}
		if (new_balance == 0) {
			pfs_avl_node_setbalance(node, new_balance);
		} else if (pfs_avl_rotation(tree, node, new_balance) == 0) {
			return;
		}
	}
}

void
pfs_avl_create(pfs_avl_tree_t *tree, pfs_avl_compare_fn_t *compar, size_t offset)
{
	PFS_ASSERT(tree);
	PFS_ASSERT(compar);
	PFS_ASSERT((offset & 0x7) == 0);

	tree->avl_compar = compar;
	tree->avl_root = NULL;
	tree->avl_numnodes = 0;
	tree->avl_offset = offset;
}

void
pfs_avl_destroy(pfs_avl_tree_t *tree)
{
	PFS_ASSERT(tree);
	PFS_ASSERT(tree->avl_numnodes == 0);
	PFS_ASSERT(tree->avl_root == NULL);
}
