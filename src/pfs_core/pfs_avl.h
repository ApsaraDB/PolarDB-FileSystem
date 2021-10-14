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

#ifndef	_PFS_AVL_H
#define _PFS_AVL_H

#include <stdint.h>

typedef int pfs_avl_compare_fn_t(const void *, const void *);

typedef struct pfs_avl_node {
	struct pfs_avl_node *avl_child[2]; /* left/right children nodes */
	uintptr_t avl_pcb;		   /* parent, child_index, balance */
} pfs_avl_node_t;

typedef struct pfs_avl_tree {
	pfs_avl_node_t *avl_root;	/* root node in tree */
	pfs_avl_compare_fn_t *avl_compar;
	size_t avl_offset;		/* offsetof(type, avl_link_t field) */
	uint64_t avl_numnodes;		/* number of nodes in the tree */
} pfs_avl_tree_t;

static inline uint64_t
pfs_avl_numnodes(pfs_avl_tree_t *tree)
{
	return tree->avl_numnodes;
}

static inline bool
pfs_avl_is_empty(pfs_avl_tree_t *tree)
{
	return tree->avl_numnodes == 0;
}

void pfs_avl_create(pfs_avl_tree_t *tree, pfs_avl_compare_fn_t *compar, size_t offset);
void pfs_avl_destroy(pfs_avl_tree_t *tree);
void *pfs_avl_find(pfs_avl_tree_t *tree, const void *node, uintptr_t *where);
void pfs_avl_add(pfs_avl_tree_t *tree, void *node);
void pfs_avl_remove(pfs_avl_tree_t *tree, void *node);
void *pfs_avl_first(pfs_avl_tree_t *tree);
void *pfs_avl_last(pfs_avl_tree_t *tree);
void *pfs_avl_next(pfs_avl_tree_t *tree, void *data);
void *pfs_avl_prev(pfs_avl_tree_t *tree, void *data);

#endif /* _PFS_AVL_H */
