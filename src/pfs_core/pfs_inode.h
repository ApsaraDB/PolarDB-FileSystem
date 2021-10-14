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

#ifndef	_PFS_INODE_H_
#define	_PFS_INODE_H_

#include <sys/queue.h>

#include <time.h>
#include <pthread.h>
#include <limits.h>

#include "pfs_avl.h"
#include "pfs_impl.h"
#include "pfs_meta.h"

/* time update mode */
#define	IN_ATIME	0x01
#define	IN_MTIME	0x02
#define	IN_CTIME	0x04

typedef struct 	pfs_tx	pfs_tx_t;

enum {
	PFS_INODET_NONE	= 0,
	PFS_INODET_FILE	= 1,
	PFS_INODET_DIR	= 2,
};

/*
 * FIXME: Need a btter name.
 * In this design, there is no block indexing info stored
 * on inode. It has no indexing meaning now.
 */
typedef struct pfs_inode_phy {
	uint8_t		in_type;
	uint8_t		in_flags;		/* flags depending on type */
	uint16_t	in_padding;
	uint32_t	in_pvtid;		/* XXX setxattr("pvtid", uint32_t) */
	uint64_t	in_deno;		/* head direntry number */

	uint64_t	in_nlink;
	uint64_t	in_nblock;
	uint64_t	in_size;
	uint64_t	in_atime;
	uint64_t	in_ctime;		/* do we needs these ts ? */
	uint64_t	in_mtime;
	uint64_t	in_btime;		/* us accuracy */
} pfs_inode_phy_t;

typedef struct pfs_dblk {
	int64_t		db_blkno;
	int32_t		db_holeoff;
	int32_t		db_holelen;
} pfs_dblk_t;

typedef struct pfs_writemodify {
	pfs_dblk_t	*wm_dblkv;	/* modified dblk vector */
	int		wm_dblki;
	int		wm_dblkn;
	int64_t		wm_sizeinc;	/* size increment */
	pthread_t	wm_thread;	/* modifying thread */
} pfs_writemodify_t;

enum {
	DXOP_ADD	= 1,
	DXOP_DEL,
};

struct dxredo_rec {
	int		rr_op;
	uint32_t	rr_nmhash;
	pfs_ino_t	rr_ino;
	bool		rr_isdir;
};

#define DXR_MAX_NREC	4		/* rename() needs 3 at most */

typedef struct pfs_dxredo {
	pthread_t	r_thread;	/* modifying thread */
	struct dxredo_rec r_rec[DXR_MAX_NREC];
	int		r_cnt;
} pfs_dxredo_t;

typedef struct pfs_inode_blk_table pfs_inode_blk_table_t;

/*
 * I: inode lock in_mtx
 */
typedef struct pfs_inode {
	pfs_ino_t	in_ino;		/* cache of meta inode */
	uint8_t		in_type;
	int64_t		in_size;
	int64_t		in_size2;
	uint64_t	in_ctime;
	uint64_t	in_btime;

	pthread_mutex_t in_mtx;
	pthread_mutex_t in_mtx_rpl;
	pthread_cond_t 	in_cond;
	pfs_avl_node_t	in_node;
	TAILQ_ENTRY(pfs_inode) in_next;
	pfs_mount_t 	*in_mnt;

	pfs_inode_phy_t	*in_phyin;

//	bool		in_doom;	/* unlink barrier, whether is being unlinked */
//					/* protected by mount inode list lock */
	int32_t		in_refcnt;	/* XXX: opened file count */
					/* protected by mount inode list lock */
	bool		in_stale;
	bool		in_cbdone;
	int64_t		in_nblk_ip;	/* (I) number of block in progress */
	int64_t		in_nblk_modify;	/* (I) # blocks being modified */
	pfs_writemodify_t in_write_modify;

	pfs_avl_tree_t	in_dx_root;	/* (I) index of subfiles */
	pfs_dxredo_t	in_dx_redo;	/* (I) record all subfile change, like wm */

	int64_t		in_sync_ver;	/* record the rpl version when sync*/
	int64_t		in_rpl_ver;	/* rpl_ver > sync_ver means the replay
 					* thread has updated the inode */

	volatile pthread_t	in_rpl_lock_thd; /* record rpl lock owner */

	pfs_inode_blk_table_t	*in_blk_tables;
	int64_t		in_blk_table_nsoft;
	int64_t		in_blk_table_nhard;
} pfs_inode_t;

#define	IN_FIELD(in, field)	(in)->in_phyin->field

#define	IN_UPDATE_TIME(in, mode)		\
	INPHY_UPDATE_TIME((in)->in_phyin, mode)

#define INPHY_UPDATE_TIME(phyin, mode) do {	\
	time_t curtime; 			\
	time(&curtime); 			\
	if ((mode) & IN_ATIME) 			\
		phyin->in_atime = curtime; 	\
	if ((mode) & IN_MTIME) 			\
		phyin->in_mtime = curtime; 	\
	if ((mode) & IN_CTIME) 			\
		phyin->in_ctime = curtime; 	\
} while(0)

#define	PHYIN_ISORPHAN(phyin)			\
	((phyin)->in_type != PFS_INODET_NONE && GETMO(phyin)->mo_used && \
	(phyin)->in_deno == INVALID_DENO)

void	pfs_inodephy_init(pfs_inode_phy_t *phyin, uint64_t deno, bool isdir);
void	pfs_inodephy_fini(pfs_inode_phy_t *phyin);
uint64_t
	pfs_inodephy_diskusage(pfs_mount_t *mnt, pfs_inode_phy_t *phyin);
uint64_t
	pfs_inodephy_get_btime(pfs_mount_t *mnt, pfs_ino_t ino);
int	pfs_inodephy_release(pfs_mount_t *mnt, pfs_ino_t ino, uint64_t btime);
int	pfs_inode_release(pfs_mount_t *mnt, pfs_ino_t ino, uint64_t btime,
    pfs_inode_t* in);
int	pfs_inodephy_stat(pfs_mount_t *mnt, pfs_ino_t ino, pfs_inode_t *in, struct stat *st);
int	pfs_inodephy_setxattr(pfs_mount_t *mnt, pfs_ino_t ino, const char *name,
	    const void *value, size_t size);
ssize_t	pfs_inodephy_size(pfs_mount_t *mnt, pfs_ino_t ino);

int	pfs_inode_compare(const void *keya, const void *keyb);
int	pfs_inode_add(pfs_inode_t *in, pfs_blkid_t blkid);
void 	pfs_inode_map(pfs_inode_t *in, pfs_blkid_t blkid, pfs_blkno_t *dblkno,
	    off_t *dbhoff);
int	pfs_inode_del_from(pfs_inode_t *in, pfs_blkid_t blkid);
pfs_inode_t *
	pfs_inode_get(pfs_mount_t *mnt, pfs_ino_t ino);
void	pfs_inode_put(pfs_inode_t *in);
int 	pfs_inode_change(pfs_inode_t *in, ssize_t newsize, bool force);
int	pfs_inode_stat(pfs_inode_t *in, struct stat *st);
void	pfs_inode_invalidate(pfs_ino_t ino, pfs_mount_t *mnt);
int 	pfs_inode_sync(pfs_inode_t *in, int type, uint64_t btime,
	    bool force_unlck_meta);
int 	pfs_inode_sync_first(pfs_inode_t *in, int type, uint64_t btime,
	    bool force_unlck_meta);
void 	pfs_inode_destroy(pfs_inode_t *in);
void 	pfs_inode_destroy_self(pfs_inode_t *in);
void	pfs_inode_lock(pfs_inode_t *in);
void	pfs_inode_unlock(pfs_inode_t *in);
void 	pfs_inode_expand_dblk_hole(pfs_inode_t *in, pfs_blkid_t blkid,
	    off_t newbhoff, int32_t newbhlen);
void 	pfs_inode_shrink_dblk_hole(pfs_inode_t *in, pfs_blkid_t blkid,
	    off_t newbhoff, int32_t newbhlen);
void 	pfs_inode_writemodify_shrink_dblk_hole(pfs_inode_t *in,
	    pfs_blkid_t blkid, off_t newbhoff, int32_t newbhlen);
void 	pfs_inode_writemodify_increment_size(pfs_inode_t *in, int64_t szdelta);
int 	pfs_inode_writemodify_commit(pfs_inode_t *in);
bool	pfs_inode_skip_sync(pfs_inode_t *in);
int	pfs_inode_phy_check(pfs_inode_t *in);

void	pfs_inode_rpl_lock(pfs_inode_t *in);
bool	pfs_inode_rpl_unlock(pfs_inode_t *in);
pfs_inode_t *pfs_get_inode_tx(pfs_tx_t* tx, pfs_ino_t ino);
void	pfs_put_inode_tx_all(pfs_tx_t* tx);

int	pfs_inode_dir_add(pfs_inode_t *dirin, const char *name, bool isdir,
	    pfs_ino_t *inop, uint64_t *btimep);
int	pfs_inode_dir_find(pfs_inode_t *dirin, const char *name,
	    pfs_ino_t *tgtino, int *typep, uint64_t *btimep);
int	pfs_inode_dir_del(pfs_inode_t *dirin, pfs_ino_t ino, const char *name,
	    bool isdir);
int	pfs_inode_dir_rename(pfs_mount_t *mnt, bool isdir,
	    pfs_inode_t *odirin, pfs_ino_t oino, const char *oldname,
	    pfs_inode_t *ndirin, pfs_ino_t nino, const char *newname);

void	pfs_inode_sync_blk_meta(pfs_inode_t *in, const pfs_blktag_phy_t *blktag);
void	pfs_inode_sync_meta(pfs_inode_t *in, const pfs_inode_phy_t *phyin);

void	pfs_inode_mark_stale(pfs_inode_t *in);

static inline ssize_t
pfs_inode_size(pfs_inode_t *in)
{
	ssize_t size;

	PFS_ASSERT(in->in_type == PFS_INODET_FILE);
	PFS_ASSERT(in->in_size == in->in_size2);
	size = (ssize_t)in->in_size;
	return size;
}

static inline uint64_t
pfs_inodephy_nblock(pfs_inode_phy_t *phyin)
{
	PFS_ASSERT(phyin->in_type == PFS_INODET_FILE);
	return phyin->in_nblock;
}

static inline void
pfs_inodephy_set_pvtid(pfs_mount_t *mnt, pfs_inode_phy_t *phyin, uint32_t val)
{
	PFS_ASSERT(pfs_version_has_features(mnt, PFS_FEATURE_PVTID));
	phyin->in_pvtid = val + 1;
}

static inline uint32_t
pfs_inodephy_get_pvtid(pfs_mount_t *mnt, pfs_inode_phy_t *phyin)
{
	if (phyin->in_pvtid == 0)
		return UINT_MAX;
	PFS_ASSERT(pfs_version_has_features(mnt, PFS_FEATURE_PVTID));
	return phyin->in_pvtid - 1;
}

#endif	/* _PFS_INODE_H_ */
