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

#ifndef	_PFS_MOUNT_H_
#define	_PFS_MOUNT_H_

#include <sys/queue.h>
#include <pthread.h>

#include "pfs_meta.h"
#include "pfs_alloc.h"
#include "pfs_log.h"
#include "pfs_stat.h"
#include "pfs_avl.h"

/*
 * mount flag: 32bit = 8sets(4bit/set)
 *
 * | (6~7)unused set | (5)special flag set | (4)trace set | (3)pfstool set | (1~2)workthread set | (0)RDWR set |
 */

#define	MNTFLG_RD		0x0001
#define	MNTFLG_WR		0x0002
#define	MNTFLG_RDWR		MNTFLG_RD|MNTFLG_WR
#define	MNTFLG_LOG		0x0010
#define	MNTFLG_TOOL		0x1000	/* Only pfstool will set this flag,
				   	   to get max hostid to instead itself */
#define	MNTFLG_PFSD		0x0100
#define MNTFLG_DISCARD_BYFORCE	0x100000	/* discard by force */
#define MNTFLG_PAXOS_BYFORCE	0x200000	/* paxos acquired by force */

#define	PFS_RD			(MNTFLG_RD|MNTFLG_LOG)
#define	PFS_RDWR		(MNTFLG_RD|MNTFLG_WR|MNTFLG_LOG)
#define	PFS_TOOL		MNTFLG_TOOL
#define	PFS_FLUSH		MNTFLG_FLUSH
#define PFS_TRACE       0x10000   /* Add Trace flag*/

/* mount status */
#define	MNTST_INITED		0x0001
/* add new mount state to fix thread exit failure */
#define MNTST_FAILED        0x0002

typedef struct pfs_inode 	pfs_inode_t;
typedef	struct pfs_file 	pfs_file_t;
typedef struct pfs_txop 	pfs_txop_t;
typedef struct nameinfo 	nameinfo_t;
typedef struct admin_info	admin_info_t;

/*
 * (I) 	inode mutex lock
 * (M)	meta data rw lock
 */
typedef struct pfs_mount {
	int		mnt_id;
	int64_t		mnt_epoch;

	pthread_mutex_t	mnt_inodetree_mtx;
	TAILQ_HEAD(, pfs_inode) mnt_inodelist;	/* destack helper for swap out*/
	pfs_avl_tree_t	mnt_inodetree;		/* (I) */

	int		mnt_flags;		/* flags set by user, whether
						   enable modules. */
	uint64_t	mnt_disk_version;	/* version on disk */
	uint64_t	mnt_run_version;	/* running pfs version */

	pthread_mutex_t	mnt_inited_mtx;
	pthread_cond_t	mnt_inited_cond;
	int		mnt_status;		/* mount status */

	pthread_rwlock_t mnt_meta_rwlock;	/* (M) */
	pfs_anode_t	mnt_anode[MT_NTYPE];	/* (M) */

	bool		mnt_discard_force;	/* discard forcedly */
	tnode_t		*mnt_bdroot[BDS_NMAX];	/* (M) discard tree array */
	tnode_t		*mnt_changed_bdroot;	/* private to bd thread */

	int		mnt_ioch_desc;
	int		mnt_nchunk;
	pfs_chunk_t	**mnt_chunkv;
	char		mnt_pbdname[PFS_MAX_PBDLEN];
	uint32_t	mnt_blksize;
	uint32_t	mnt_sectsize;
	uint32_t	mnt_fragsize;
	uint64_t	mnt_disksize;

	pfs_log_t	mnt_log;

	/* fields for disk paxos impl */
	//pfs_paxos_t	mnt_paxos;
	int		mnt_hostid_fd;	/* mount local file region lock fd */
	pfs_file_t	*mnt_paxos_file;
	const char	*mnt_lockspace_name;
	const char	*mnt_lock_name;
	uint32_t	mnt_num_hosts;		/* host info */
	uint32_t	mnt_host_id;
	uint64_t	mnt_host_generation;

	/* admin thread info */
	admin_info_t    *mnt_admin;

	pthread_mutex_t	mnt_poll_mtx;
	pthread_cond_t	mnt_poll_cond;
	pthread_t	mnt_poll_tid;
	int		mnt_poll_stop;
	int		mnt_poll_sync;

	pthread_mutex_t	mnt_discard_mtx;
	pthread_cond_t	mnt_discard_cond;
	pthread_t	mnt_discard_tid;
	int		mnt_discard_stop;

	pthread_mutex_t	mnt_stat_mtx;
	pthread_cond_t	mnt_stat_cond;
	pthread_t	mnt_stat_tid;
	int		mnt_stat_stop;
} pfs_mount_t;

#define	MOUNT_META_RDLOCK(mnt)	do { \
	MNT_STAT_BEGIN(); \
	rwlock_rdlock(&(mnt)->mnt_meta_rwlock); \
	MNT_STAT_END(MNT_STAT_META_RDLOCK); \
} while(0)

#define	MOUNT_META_WRLOCK(mnt)	do { \
	MNT_STAT_BEGIN(); \
	rwlock_wrlock(&(mnt)->mnt_meta_rwlock); \
	MNT_STAT_END(MNT_STAT_META_WRLOCK); \
} while(0)

#define	MOUNT_META_TRYRDLOCK(mnt)	\
	(rwlock_tryrdlock(&(mnt)->mnt_meta_rwlock) == 0)

#define	MOUNT_META_UNLOCK(mnt)	rwlock_unlock(&(mnt)->mnt_meta_rwlock)

extern "C" {
int		pfs_mount(const char *cluster, const char *pbdname, int host_id, int flags);
int		pfs_remount(const char *cluster, const char *pbdname, int host_id, int flags);
int		pfs_umount(const char *pbdname);
int		pfs_mount_growfs(const char *pbdname);
}

int		pfs_mount_acquire(const char *cluster, const char *pbdname, int host_id, int flags);
int		pfs_mount_release(const char *pbdname, int host_id);



pfs_mount_t *	pfs_get_mount(const char *pbdname);
pfs_mount_t *	pfs_get_mount_byid(int mntid);
void		pfs_put_mount(pfs_mount_t *mnt);
pfs_bda_t 	pfs_mount_align_io(pfs_mount_t *mnt, pfs_bda_t data_bda, size_t data_len,
	    	   size_t *io_len, size_t *op_len);
pfs_inode_t *	pfs_get_inode(pfs_mount_t *mnt, pfs_ino_t ino);
void 		pfs_put_inode(pfs_mount_t *mnt, pfs_inode_t *in);
pfs_inode_t *	pfs_add_inode(pfs_mount_t *mnt, pfs_inode_t *in);
int		pfs_mount_block_isused(pfs_mount_t *mnt, uint64_t btno);
bool		pfs_mount_needsync(pfs_mount_t *mnt);
int 		pfs_mount_sync(pfs_mount_t *mnt);
void		pfs_mount_signal_sync(pfs_mount_t *mnt);
int 		pfs_mount_flush(pfs_mount_t *mnt);

int		pfs_bd_compare(const void *keya, const void *keyb);
void 		pfs_bd_add(pfs_mount_t *mnt, int bts, int64_t btno);
int64_t		pfs_bd_get(pfs_mount_t *mnt, int bts);
void 		pfs_bd_del(pfs_mount_t *mnt, int bts, int64_t btno);
int64_t		pfs_bd_find(pfs_mount_t *mnt, int bts, int64_t btno);
uint64_t	blkno2btno(pfs_mount_t *mnt, pfs_blkno_t blkno);
pfs_blkno_t	btno2blkno(pfs_mount_t *mnt, uint64_t btno);
int		pfs_mount_fstrim(pfs_mount_t *mnt, int64_t beginid,
		    int64_t endid, bool all);
void 		pfs_dump_used(pfs_mount_t *mnt, int type, int ckid[2]);
int		pfs_list_used(pfs_mount_t *mnt, int type, int ckid, oidvect_t *ov);
void		pfs_dump_meta(pfs_mount_t *mnt, int type, int chunkid, int objid);
/*
 * mount_XXXable() means whether XXX module is enabled.
 * mount_XXXed() means whether specified mount status is true.
 */
static inline bool
pfs_loggable(pfs_mount_t *mnt)
{
	return (mnt->mnt_flags & MNTFLG_LOG) != 0;
}

static inline bool
pfs_writable(pfs_mount_t *mnt)
{
	return (mnt->mnt_flags & MNTFLG_WR) != 0;
}

static inline bool
pfs_inited(pfs_mount_t *mnt)
{
	return (mnt->mnt_status & MNTST_INITED) != 0;
}

static inline bool
pfs_paxos_forced(pfs_mount_t *mnt)
{
	return (mnt->mnt_flags & MNTFLG_WR) != 0 &&
	    (mnt->mnt_flags & MNTFLG_PAXOS_BYFORCE) != 0;
}

static inline bool
pfs_istool(pfs_mount_t *mnt)
{
	return (mnt->mnt_flags & MNTFLG_TOOL) == MNTFLG_TOOL;
}

static inline bool
pfs_ispfsd(pfs_mount_t *mnt)
{
	return (mnt->mnt_flags & MNTFLG_PFSD) == MNTFLG_PFSD;
}

#endif	/* _PFS_MOUNT_H_ */
