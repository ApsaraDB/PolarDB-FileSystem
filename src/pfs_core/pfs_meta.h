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

#ifndef	_PFS_META_H_
#define	_PFS_META_H_

#include "pfs_impl.h"
#include "pfs_alloc.h"
#include "pfs_version.h"

typedef struct pfs_inode_phy	pfs_inode_phy_t;
typedef struct pfs_direntry_phy pfs_direntry_phy_t;
typedef struct pfs_chunk	pfs_chunk_t;
typedef struct pfs_txop		pfs_txop_t;
typedef struct pfs_tx		pfs_tx_t;

#define	ONO2CKNO(objno)			((objno) >> 40)
#define	ONO2OID(objno)			((objno) & 0xffffffffff)

enum {
	MT_NONE		= 0,
	MT_BLKTAG	= 1,
	MT_DIRENTRY	= 2,
	MT_INODE	= 3,

	MT_NTYPE,
};

enum {
	BDS_NONE 	= 0,
	BDS_READY 	= 1,	/* is ready */
	BDS_INP		= 2,	/* is in progress */

	BDS_NMAX,
};

enum {
	MGF_CHECKVALID		= 0x0001
};

#define	MO2DE(mo)	((pfs_direntry_phy_t *)(mo)->mo_data)
#define	MO2IN(mo)	((pfs_inode_phy_t *)(mo)->mo_data)
#define	MO2BT(mo)	((pfs_blktag_phy_t *)(mo)->mo_data)

#define	GETMO(dp)	((pfs_metaobj_phy_t *) \
			 ((char *)(dp) - offsetof(pfs_metaobj_phy, mo_data)))

#define	MONO_FIRST(phyin) 	(GETMO(phyin)->mo_head)
#define	MONO_NEXT(xmo)		(GETMO(xmo)->mo_next)
#define	MONO_CURR(xmo)		(GETMO(xmo)->mo_number)

#define	MONO_MAKE(sup, sub)	((sup) | (sub))

#define	MONO_VALID(no)		((no) != 0)

#define	INVALID_OID		((uint64_t)-1)

#define	INVALID_BTNO		(0ULL)	// unused
#define	INVALID_DENO		(~0ULL)
#define	INVALID_INO		(~0LL)

typedef struct pfs_metaobj_phy {
	uint64_t	mo_number;
	uint64_t	mo_version;
	uint64_t	mo_next;
	uint64_t	mo_prev;
#define	mo_head		mo_next
#define	mo_tail		mo_prev
	uint8_t		mo_type;	/* MT_NONE means unused*/
	uint8_t		mo_used;
	uint8_t		mo_padding[2];
	uint32_t	mo_checksum;
	uint8_t		mo_data[PFS_OBJDATA_SIZE];
} pfs_metaobj_phy_t;

typedef struct pfs_blktag_phy {
	pfs_ino_t	bt_ino;		/* file ino */
	int64_t		bt_blkid;	/* blkid in a file */
	uint32_t	bt_dstatus;	/* discard status */
	uint32_t	bt_ndiscard;	/* count of doing set INP status,
					   set 0 when being allocated. */
	int32_t		bt_holelen;
	int32_t		bt_holeoff;
} pfs_blktag_phy_t;

typedef struct pfs_metaset_phy {
	uint64_t	ms_sectbda;	/* sector block device address */
	uint32_t	ms_nsect;	/* # of sectors */
	uint32_t	ms_objsize;	/* meta object size */
} pfs_metaset_phy_t;

typedef struct pfs_chunk_phy {
	uint64_t	ck_magic;
	uint64_t	ck_chunksize;
	uint64_t	ck_blksize;
	uint64_t	ck_sectsize;
	uint64_t	ck_number;
	uint32_t	ck_nchunk;
	pfs_metaset_phy_t ck_physet[MT_NTYPE];
	uint32_t	ck_checksum;
} pfs_chunk_phy_t;


typedef struct pfs_metaset {
	pfs_chunk_t	*ms_chunk;
	int		ms_type;
	int		ms_opps;	/* object per page shift value */
	pfs_anode_t	ms_anode;
	uint64_t	ms_sectbda;
	uint32_t	ms_nsect;
	uint32_t	ms_objsize;
	pfs_metaobj_phy_t **ms_objbuf;
} pfs_metaset_t;

typedef struct pfs_chunk {
	uint64_t	ck_number;
	uint64_t	ck_sectsize;
	pfs_chunk_phy_t	*ck_phyck;	/* memory size must be 4KB */
	pfs_metaset_t	ck_metaset[MT_NTYPE];
	pfs_mount_t	*ck_mnt;
} pfs_chunk_t;

typedef struct discard_args {
	tnode_t		*d_bdroot;
	int64_t		d_ckid;
	int64_t		d_nblk;
	bool		d_all;		/* discard all unused blocks, no matter
					   whether it is discarded. */
} discard_args_t;

typedef	void	pfs_meta_visitfn_t(void *, pfs_metaobj_phy_t *);

int 	pfs_meta_load_all_chunks(pfs_mount_t *mnt);
void	pfs_meta_finish_chunk(pfs_chunk_t *ck);
void	pfs_meta_check_chunk(const pfs_chunk_phy_t *phyck);

pfs_metaobj_phy_t *
	pfs_meta_alloc(pfs_mount_t *mnt, int mtype, pfs_txop_t *top);
void	pfs_meta_free(pfs_mount_t *mnt, int mtype, pfs_metaobj_phy_t *mo,
	    pfs_txop_t *top);
pfs_metaobj_phy_t *
	pfs_meta_get(pfs_mount_t *mnt, int mtype, uint64_t objno,
	    pfs_txop_t *top, int flags);
int	pfs_meta_undo(pfs_mount_t *mnt, int mtype, uint64_t objno,
	    pfs_txop_t *top);
int	pfs_meta_redo(pfs_mount_t *mnt, int mtype, uint64_t objno,
	    pfs_txop_t *top);
void	pfs_meta_redo_fini(pfs_tx_t* tx);
void	pfs_meta_visit(pfs_mount_t *mnt, int type, int chunkid, int objid,
	    pfs_meta_visitfn_t *visitfunc, void *visitdata);
int	pfs_meta_info(pfs_mount_t *mnt, int depth, pfs_printer_t *printer);
void	pfs_meta_check_set(const pfs_metaobj_phy_t *objbuf, uint32_t nobj);
void 	pfs_metaobj_dump(const pfs_metaobj_phy_t *mo, int level);

inline pfs_blktag_phy_t *
pfs_meta_alloc_blktag(pfs_mount_t *mnt, pfs_txop_t *top)
{
	pfs_metaobj_phy_t *mo;

	mo = pfs_meta_alloc(mnt, MT_BLKTAG, top);
	return mo ? MO2BT(mo) : NULL;
}

static inline pfs_inode_phy_t *
pfs_meta_alloc_inode(pfs_mount_t *mnt, pfs_txop_t *top)
{
	pfs_metaobj_phy_t *mo;

	mo = pfs_meta_alloc(mnt, MT_INODE, top);
	return mo ? MO2IN(mo) : NULL;
}

static inline pfs_direntry_phy_t *
pfs_meta_alloc_direntry(pfs_mount_t *mnt, pfs_txop_t *top)
{
	pfs_metaobj_phy_t *mo;

	mo = pfs_meta_alloc(mnt, MT_DIRENTRY, top);
	return mo ? MO2DE(mo) : NULL;
}

static inline void
pfs_meta_free_blktag(pfs_mount_t *mnt, pfs_blktag_phy_t *bt,  pfs_txop_t *top)
{
	pfs_meta_free(mnt, MT_BLKTAG, GETMO(bt), top);
}

static inline void
pfs_meta_free_inode(pfs_mount_t *mnt, pfs_inode_phy_t *in, pfs_txop_t *top)
{
	pfs_meta_free(mnt, MT_INODE, GETMO(in), top);
}

static inline void
pfs_meta_free_direntry(pfs_mount_t *mnt, pfs_direntry_phy_t *de, pfs_txop_t *top)
{
	pfs_meta_free(mnt, MT_DIRENTRY, GETMO(de), top);
}

static inline pfs_blktag_phy_t *
pfs_meta_get_blktag_flags(pfs_mount_t *mnt, uint64_t objno, pfs_txop_t *top,
    int flags)
{
	pfs_metaobj_phy_t *mo;
	pfs_blktag_phy_t *bt;

	mo = pfs_meta_get(mnt, MT_BLKTAG, objno, top, flags);
	if (mo == NULL)
		return NULL;

	bt = MO2BT(mo);
	if (bt->bt_holeoff || bt->bt_holelen) {
		PFS_ASSERT(pfs_version_has_features(mnt, PFS_FEATURE_BLKHOLE));
	}
	return bt;
}
#define	pfs_meta_get_blktag(mnt, objno, top)	\
	pfs_meta_get_blktag_flags(mnt, objno, top, MGF_CHECKVALID)

static inline pfs_inode_phy_t *
pfs_meta_get_inode_flags(pfs_mount_t *mnt, uint64_t objno, pfs_txop_t *top,
    int flags)
{
	pfs_metaobj_phy_t *mo;

	mo = pfs_meta_get(mnt, MT_INODE, objno, top, flags);
	return mo ? MO2IN(mo) : NULL;
}
#define	pfs_meta_get_inode(mnt, objno, top)	\
	pfs_meta_get_inode_flags(mnt, objno, top, MGF_CHECKVALID)

static inline pfs_direntry_phy_t *
pfs_meta_get_direntry_flags(pfs_mount_t *mnt, uint64_t objno, pfs_txop_t *top,
    int flags)
{
	pfs_metaobj_phy_t *mo;

	mo = pfs_meta_get(mnt, MT_DIRENTRY, objno, top, flags);
	return mo ? MO2DE(mo) : NULL;
}
#define	pfs_meta_get_direntry(mnt, objno, top)	\
	pfs_meta_get_direntry_flags(mnt, objno, top, MGF_CHECKVALID)

static inline int
pfs_meta_used_blktag(pfs_mount_t *mnt, uint64_t objno)
{
	pfs_metaobj_phy_t *mo;
	mo = pfs_meta_get(mnt, MT_BLKTAG, objno, NULL, 0);
	if (mo == NULL)
		return -1;
	return mo->mo_used;
}

int 	pfs_meta_list_insert(pfs_mount_t *mnt, pfs_metaobj_phy_t *headmo,
    	    pfs_metaobj_phy_t *mo);
int 	pfs_meta_list_delete(pfs_mount_t *mnt, pfs_metaobj_phy_t *headmo,
    	    pfs_metaobj_phy_t *mo);

bool 	pfs_meta_bd_mark_inp(pfs_mount_t *mnt, int64_t btno);
bool 	pfs_meta_bd_mark_done(pfs_mount_t *mnt, int64_t btno);
void	pfs_meta_bd_build_index(pfs_mount_t *mnt);
void	pfs_meta_bd_select(pfs_mount_t *mnt, int64_t ckid, void *data);

void 	pfs_metaobj_check_crc(pfs_metaobj_phy_t *mo);
void 	pfs_metaobj_check_crc_buf(pfs_metaobj_phy_t *mobuf, int nmo);
void	pfs_meta_lock(pfs_mount_t *mnt);
void	pfs_meta_unlock(pfs_mount_t *mnt);
bool	pfs_meta_islocked(pfs_mount_t *mnt);
void 	pfs_meta_used_oid(pfs_mount_t *mnt, int type, int ckid, oidvect_t *ov);

void	pfs_metaobj_cp(const pfs_metaobj_phy_t *src, pfs_metaobj_phy_t *dest);

inline bool
chunk_magic_valid(uint64_t ckid, uint64_t magic)
{
	if (magic == PFS_CHUNK_MAGIC)
		return true;
	return (ckid == 0 &&
	    (int64_t)(magic - PFS_CHUNK_MAGIC) >= 0 &&
	    (int64_t)(magic - PFS_CHUNK_MAGIC) < PFS_MAX_VERSION);
}

inline uint64_t
chunk_magic_make(uint64_t ckid)
{
	if (ckid != 0)
		return PFS_CHUNK_MAGIC;
	return PFS_CHUNK_MAGIC + pfs_version_get();
}

inline uint64_t
chunk_magic_version(uint64_t magic)
{
	return magic - PFS_CHUNK_MAGIC;
}

#endif	/* _PFS_META_H_ */
