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

#include <sys/queue.h>
#include <sys/param.h>
#include <pthread.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "pfs_alloc.h"
#include "pfs_meta.h"

static const char *metanames[] = {
	[MT_NONE]	= "None",
	[MT_BLKTAG]	= "Blktag",
	[MT_DIRENTRY]	= "Direntry",
	[MT_INODE]	= "Inode",
};

#define AN_FREE_BMP_SHIFT (8 * sizeof(uint64_t))

void
pfs_anode_nfree_inc(pfs_anode_t *an, uint64_t val, int delta)
{
	an->an_nfree += delta;
	/*
	 * Only the leafs need to update the bitmap.
	 * And delta can be +1, 0, -1.
	 * When delta is +1/-1, we just flip the bit, or else not.
	 * Pay attention that "delta" is not 64bit integer.
	 */
	if (an->an_children == 0)
		an->an_free_bmp[val / AN_FREE_BMP_SHIFT] ^=
		    ((delta & 1ull) << (val % AN_FREE_BMP_SHIFT));
}

static bool
pfs_anode_isfree_obj(pfs_anode_t *an, uint64_t val)
{
	return (an->an_free_bmp[val / AN_FREE_BMP_SHIFT]
	    & (1ull << (val % AN_FREE_BMP_SHIFT))) != 0;
}

/*
 * Leaf anodes have the actual resources to allocate and free.
 * Internal anodes are just for hierarchy building. When an allocation
 * or free is done, the leaf anodes should update its resources on disks.
 */

int
pfs_anode_alloc(pfs_anode_t *an, uint64_t *pval)
{
	int i;
	int32_t maxfree, maxindx;
	int32_t oldnxt, nxt;
	pfs_anode_t *can;
	bool got;

	/*
	 * Allocate from the leaf node's range [begin, end).
	 * next is to guess a next free object.
	 */
	if (an->an_nchild == 0) {
		got = false;
		oldnxt = nxt = an->an_next;
		PFS_ASSERT(0 <= nxt && nxt < an->an_nall);
		do {
			if (pfs_anode_isfree_obj(an, nxt) &&
			    (*an->an_allocfunc)(an, nxt)) {
				*pval = MONO_MAKE((an->an_id << an->an_shift),
				    nxt);
				pfs_anode_nfree_inc(an, nxt, -1);
				got = true;
			}
			if (++nxt >= an->an_nall)
				nxt = 0;
		} while (!got && nxt != oldnxt);
		if (got) {
			an->an_next = nxt;
			return 0;
		}

		an->an_next = oldnxt;
		pfs_dbgtrace("anode %lu(nfree %d) has no free metaobjs\n",
		    an->an_id, an->an_nfree);
		return -EBUSY;
	}

	/*
	 * Find the child with max free and delegate allocation
	 * to this child. If the child of max free can't allocate,
	 * which may occur when discarding block, we resort to a
	 * first child that can allocate.
	 */
	maxfree = 0;
	maxindx = -1;
	for (i = 0; i < an->an_nchild; i++) {
		can = an->an_children[i];
		if (can->an_nfree > maxfree) {
			maxfree = can->an_nfree;
			maxindx = i;
		}
	}
	if (maxindx < 0)
		ERR_RETVAL(ENOSPC);
	i = maxindx;
	do {
		can = an->an_children[i];
		if (can->an_nfree > 0 && pfs_anode_alloc(can, pval) == 0) {
			*pval = MONO_MAKE((an->an_id << an->an_shift), *pval);
			pfs_anode_nfree_inc(an, i, -1);
			return 0;
		}
		if (++i >= an->an_nchild)
			i = 0;
	} while (i != maxindx);

	/* no available resource for alloc */
	ERR_RETVAL(ENOSPC);
}

void
pfs_anode_free(pfs_anode_t *an, uint64_t val)
{
	int ci;
	pfs_anode_t *can;
	uint64_t mask;

	if (an->an_nchild == 0) {
		(*an->an_freefunc)(an, val);
		pfs_anode_nfree_inc(an, val, 1);
		/*
		 * Always alloc from the last free.
		 * This strategy is especially friendly to snapshot in bsr
		 * when managing blocks, and no-harmful to inode/dentry
		 * managment.
		 */
		an->an_next = MIN(val, (uint64_t)(an->an_next));
		return;
	}

	can = an->an_children[0];
	ci = val >> can->an_shift;
	PFS_ASSERT(0 <= ci && ci < an->an_nchild);
	can = an->an_children[ci];
	mask = (1LLU << can->an_shift) - 1;
	pfs_anode_free(can, val & mask);
	pfs_anode_nfree_inc(an, ci, 1);
}

void
pfs_anode_visit(pfs_anode_t *an, uint64_t val, pfs_anode_visitfn_t *visfn,
    void *data)
{
	int ci;
	pfs_anode_t *can;
	uint64_t mask;

	if (an->an_nchild == 0) {
		(*visfn)(an, val, data);
		return;
	}

	can = an->an_children[0];
	ci = val >> can->an_shift;
	PFS_ASSERT(0 <= ci && ci < an->an_nchild);
	can = an->an_children[ci];
	mask = (1LLU << can->an_shift) - 1;
	pfs_anode_visit(can, val & mask, visfn, data);
	(*visfn)(an, val, data);
}

void *
pfs_anode_get(pfs_anode_t *an, uint64_t val, pfs_txop_t *top)
{
	int ci;
	pfs_anode_t *can;
	uint64_t mask;
	void *obj;

	if (an->an_nchild == 0) {
		obj = (*an->an_getfunc)(an, val, top);
		return obj;
	}

	can = an->an_children[0];
	ci = val >> can->an_shift;
	PFS_ASSERT(0 <= ci && ci < an->an_nchild);
	can = an->an_children[ci];
	mask = (1LLU << can->an_shift) - 1;
	obj = pfs_anode_get(can, val & mask, top);
	return obj;
}

int
pfs_anode_undo(pfs_anode_t *an, uint64_t val, pfs_txop_t *top)
{
	int ci;
	pfs_anode_t *can;
	uint64_t mask;
	int delta;

	if (an->an_nchild == 0) {
		delta = (*an->an_undofunc)(an, val, top);
		pfs_anode_nfree_inc(an, val, delta);
		an->an_next = 0;
		return delta;
	}

	can = an->an_children[0];
	ci = val >> can->an_shift;
	PFS_ASSERT(0 <= ci && ci < an->an_nchild);
	can = an->an_children[ci];
	mask = (1ULL << can->an_shift) - 1;
	delta = pfs_anode_undo(can, val & mask, top);
	pfs_anode_nfree_inc(an, ci, delta);
	return delta;
}

int
pfs_anode_redo(pfs_anode_t *an, uint64_t val, pfs_txop_t *top)
{
	int ci;
	pfs_anode_t *can;
	uint64_t mask;
	int delta;

	if (an->an_nchild == 0) {
		delta = (*an->an_redofunc)(an, val, top);
		pfs_anode_nfree_inc(an, val, delta);
		an->an_next = 0;
		return delta;
	}

	can = an->an_children[0];
	ci = val >> can->an_shift;
	PFS_ASSERT(0 <= ci && ci < an->an_nchild);
	can = an->an_children[ci];
	mask = (1ULL << can->an_shift) - 1;
	delta = pfs_anode_redo(can, val & mask, top);
	pfs_anode_nfree_inc(an, ci, delta);
	return delta;
}

void
pfs_anode_destroy(pfs_anode_t *an)
{
	int i;

	/* Handle the leaf case */
	if (an->an_nchild == 0)
		return;

	/* Handle the internal node case */
	for (i = 0; i < an->an_nchild; i++)
		pfs_anode_destroy(an->an_children[i]);
	if (an->an_children) {
		pfs_mem_free(an->an_children, M_ANODEV);
		an->an_children = NULL;
	}
}

int
pfs_anode_dump(pfs_anode_t *an, int type, int depth, int lvl,
    pfs_printer_t *printer)
{
	int i, rv;
	pfs_anode_t *can;

	if (lvl >= depth)
		return 0;

	if (lvl == 0) {
		PFS_ASSERT(MT_NONE < type && type < MT_NTYPE);
		rv = pfs_printf(printer, "%s Info:\n", metanames[type]);
		if (rv < 0)
			return rv;
	}

	rv = pfs_printf(printer, "%*s(%d)allocnode: id %llu, shift %u, "
	    "nchild=%u, nall %d, nfree %d, next %d\n", lvl, " ", lvl,
	    (unsigned long long)an->an_id, an->an_shift, an->an_nchild,
	    an->an_nall, an->an_nfree, an->an_next);
	if (rv < 0)
		return rv;

	for (i = 0; i < an->an_nchild; i++) {
		can = an->an_children[i];
		rv = pfs_anode_dump(can, type, depth, lvl+1, printer);
		if (rv < 0)
			return rv;
	}
	return 0;
}

#if 0
int
pfs_anode_check(pfs_anode_t *an)
{
	int ci;
	pfs_anode_t *can;
	int nfree = 0;

	if (an->an_nchild == 0) {
		nfree = (*an->an_nfreefunc)(an);
		PFS_ASSERT(nfree == an->an_nfree);
		return nfree;
	}

	for (ci = 0; ci < an->an_nchild; ci++) {
		can = an->an_children[ci];
		nfree += pfs_anode_check(can);
	}
	PFS_ASSERT(nfree == an->an_nfree);
	return nfree;
}
#endif

int
pfs_anode_walk(pfs_anode_t *an, pfs_anode_walkfn_t *walkfn, void *data)
{
	int err, err1;
	int ci;
	pfs_anode_t *can;

	err = 0;
	for (ci = 0; ci < an->an_nchild; ci++) {
		can = an->an_children[ci];
		err1 = pfs_anode_walk(can, walkfn, data);
		ERR_UPDATE(err, err1);
	}
	err1 = (*walkfn)(an, data);
	ERR_UPDATE(err, err1);
	return err;
}
