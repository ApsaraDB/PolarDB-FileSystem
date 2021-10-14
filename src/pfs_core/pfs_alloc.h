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

#ifndef	_PFS_ALLOC_H_
#define	_PFS_ALLOC_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/param.h>

#include "pfs_impl.h"

#define PFS_MAX_ANODE_NCNT \
    (MAX(MAX(PFS_NBT_PERCHUNK, PFS_NIN_PERCHUNK), PFS_NDE_PERCHUNK))

typedef struct	pfs_txop pfs_txop_t;
typedef struct	pfs_anode pfs_anode_t;
typedef bool	pfs_allocfunc_t(pfs_anode_t *, uint64_t);
typedef void	pfs_freefunc_t(pfs_anode_t *, uint64_t);
typedef void *	pfs_getfunc_t(pfs_anode_t *, uint64_t, pfs_txop_t *);
typedef int	pfs_redofunc_t(pfs_anode_t *, uint64_t, pfs_txop_t *);
typedef int	pfs_undofunc_t(pfs_anode_t *, uint64_t, pfs_txop_t *);

typedef int	pfs_anode_walkfn_t(pfs_anode_t *, void *data);
typedef void	pfs_anode_visitfn_t(pfs_anode_t *, uint64_t, void *);

typedef struct pfs_anode {
	/* callback functions and data */
	void		*an_host;
	pfs_allocfunc_t *an_allocfunc;	/* metaset_alloc */
	pfs_freefunc_t	*an_freefunc;	/* metaset_free */
	pfs_getfunc_t	*an_getfunc;	/* metaset_get */
	pfs_undofunc_t	*an_undofunc;	/* metaset_undo */
	pfs_redofunc_t	*an_redofunc;	/* metaset_redo */

	pfs_anode_t	*an_parent;	/* XXX: for debug only */
	pfs_anode_t	**an_children;
	uint64_t	an_id;
	uint32_t	an_shift;	/* shift to get sub object id */
	int32_t		an_nchild;
	int32_t		an_nall;
	int32_t		an_nfree;
	int32_t		an_next;
	uint64_t	an_free_bmp[
			    howmany(PFS_MAX_ANODE_NCNT, sizeof(uint64_t)*8)];
} pfs_anode_t;

int 	pfs_anode_alloc(pfs_anode_t *an, uint64_t *pval);
void 	pfs_anode_free(pfs_anode_t *an, uint64_t val);
void 	pfs_anode_nfree_inc(pfs_anode_t *an, uint64_t val, int delta);
void *	pfs_anode_get(pfs_anode_t *an, uint64_t, pfs_txop_t *);
int	pfs_anode_undo(pfs_anode_t *an, uint64_t val, pfs_txop_t *top);
int	pfs_anode_redo(pfs_anode_t *an, uint64_t val, pfs_txop_t *top);
void  	pfs_anode_destroy(pfs_anode_t *an);
int	pfs_anode_dump(pfs_anode_t *an, int type, int depth, int lvl,
	    pfs_printer_t *printer);
int 	pfs_anode_walk(pfs_anode_t *an, pfs_anode_walkfn_t *walkfn,
	    void *data);
void 	pfs_anode_visit(pfs_anode_t *an, uint64_t val, pfs_anode_visitfn_t *visfn,
    	    void *data);

#endif	/* _PFS_ALLOC_H_ */
