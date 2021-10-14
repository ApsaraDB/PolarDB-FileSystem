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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <unistd.h>

#include "pfs_admin.h"
#include "pfs_alloc.h"
#include "pfs_devio.h"
#include "pfs_dir.h"
#include "pfs_file.h"
#include "pfs_inode.h"
#include "pfs_log.h"
#include "pfs_meta.h"
#include "pfs_mount.h"
#include "pfs_option.h"
#include "pfs_paxos.h"
#include "pfs_trace.h"
#include "pfs_tls.h"
#include "pfs_tx.h"
#include "pfs_stat.h"
#include "pfs_namecache.h"
#include "pfs_config.h"

extern "C" {
    unsigned int __attribute__((weak)) server_id = 1984;
}

enum rwlock_action {
	RW_NOLOCK,
	RW_RDLOCK,
	RW_WRLOCK,
};

#define	MAX_NLARGEORPHAN 128
typedef struct orphan_largefile_arg {
	pfs_mount_t	*or_mnt;
	uint64_t	or_large_orphan_fcount;
	struct {
		pfs_ino_t	or_large_orphan_fino;
		uint64_t	or_large_orphan_fbtime;
	}or_array[MAX_NLARGEORPHAN];
} orphan_largefile_arg_t;

typedef struct mountentry {
	int			me_id;
	int64_t			me_epoch;
	pthread_rwlock_t	me_rwlock;
	pfs_mount_t		*me_mount;
} mountentry_t;

static mountentry_t		mount_entry[PFS_MAX_NMOUNT];

static void __attribute__((constructor))
init_pfs_mountentry()
{
	int i;
	mountentry_t *me;

	for (i = 0; i < PFS_MAX_NMOUNT; i++) {
		me = &mount_entry[i];
		me->me_epoch = 1;
		me->me_id = i;
		rwlock_init(&me->me_rwlock, NULL);
	}
}

static inline bool
pfs_init_failed(pfs_mount_t *mnt)
{
	return (mnt->mnt_status & MNTST_FAILED) != 0;
}

inline void
mountentry_rdlock(mountentry_t *me)
{
	rwlock_rdlock(&me->me_rwlock);
}

inline void
mountentry_wrlock(mountentry_t *me)
{
	rwlock_wrlock(&me->me_rwlock);
}

inline void
mountentry_unlock(mountentry_t *me)
{
	rwlock_unlock(&me->me_rwlock);
}

inline void
mountentry_init(mountentry_t *me, pfs_mount_t *mnt)
{
	me->me_mount = mnt;
	me->me_epoch++;

	mnt->mnt_id = me->me_id;
	mnt->mnt_epoch = me->me_epoch;
}

inline void
mountentry_fini(mountentry_t *me)
{
	PFS_ASSERT(me->me_mount != NULL);

	me->me_mount = NULL;
	me->me_epoch++;
}

mountentry_t *
mountentry_find_iter(bool (*condfunc)(const mountentry_t *, const void *),
    const void *conddata, enum rwlock_action lock)
{
	bool found;
	mountentry_t *me;
	int i;

again:
	found = false;
	for (i = 0; i < PFS_MAX_NMOUNT; i++) {
		me = &mount_entry[i];
		mountentry_rdlock(me);
		if (condfunc(me, conddata)) {
			found = true;
			break;
		}
		mountentry_unlock(me);
	}
	if (!found)
		return NULL;

	if (lock == RW_RDLOCK)
		return me;
	if (lock == RW_NOLOCK) {
		mountentry_unlock(me);
		return me;
	}
	mountentry_unlock(me);
	mountentry_wrlock(me);
	if (condfunc(me, conddata))
		return me;
	mountentry_unlock(me);

	goto again;
}

static bool
mountentry_isfree(const mountentry_t *me, const void *data)
{
	return me->me_mount == NULL;
}

static inline bool pfs_mount_hasname(pfs_mount_t *, const char *);
static bool
mountentry_hasname(const mountentry_t *me, const void *data)
{
	pfs_mount_t *mnt = me->me_mount;

	PFS_ASSERT(mnt == NULL || mnt->mnt_epoch == me->me_epoch);
	return mnt && pfs_mount_hasname(mnt, (const char *)data);
}

#define	INODE_LIST_LOCK(mnt)	mutex_lock(&(mnt)->mnt_inodetree_mtx)
#define	INODE_LIST_UNLOCK(mnt)	mutex_unlock(&(mnt)->mnt_inodetree_mtx)

static void 	pfs_wait_inited(pfs_mount_t *mnt);
static void 	pfs_notify_inited(pfs_mount_t *mnt);
static void 	pfs_notify_init_failed(pfs_mount_t *mnt);
static int	pfs_bd_start(pfs_mount_t *mnt);
static void	pfs_bd_stop(pfs_mount_t *mnt);

static void	pfs_bd_free(tnode_t *node);
static void	pfs_bd_reset(tnode_t **bdrootp);

static int	pfs_orphans_reclaim(pfs_mount_t *mnt);

static int	pfs_mntstat_start(pfs_mount_t *mnt);
static void	pfs_mntstat_stop(pfs_mount_t *mnt);

static int64_t discard_interval = 5;
PFS_OPTION_REG(discard_interval, pfs_check_ival_normal);

static int64_t discard_period = 100;
PFS_OPTION_REG(discard_period, pfs_check_ival_normal);

static int64_t discard_ninp = 500;
PFS_OPTION_REG(discard_ninp, pfs_check_ival_normal);

static int64_t poll_interval = 1;
PFS_OPTION_REG(poll_interval, pfs_check_ival_normal);

static int64_t orphan_interval = 1;
PFS_OPTION_REG(orphan_interval, pfs_check_ival_normal);

bool
pfs_check_ival_orphan_select(void *data)
{
	int64_t integer_val = *(int64_t*)data;
	if (integer_val <= 0 || integer_val > MAX_NORPHAN)
		return false;
	return true;
}

static int64_t orphan_select_max_num = 100;
PFS_OPTION_REG(orphan_select_max_num, pfs_check_ival_orphan_select);

static int64_t readtx_skip_sync = PFS_OPT_ENABLE;
PFS_OPTION_REG(readtx_skip_sync, pfs_check_ival_switch);

static int64_t inodetree_lru_size = 65536;
PFS_OPTION_REG(inodetree_lru_size, pfs_check_ival_normal);

static int
pfs_load_log(pfs_mount_t *mnt)
{
	int rv;
	struct tx_qhead rplhead;

	TAILQ_INIT(&rplhead);
	rv = pfs_log_request(&mnt->mnt_log, LOG_LOAD, NULL, &rplhead);
	if (rv < 0) {
		pfs_etrace("load log failed, rv=%d\n", rv);
		return rv;
	}
	if (rv > 0) {
		PFS_ASSERT(TAILQ_EMPTY(&rplhead) == false);
		pfs_txlist_replay(mnt, &rplhead);
	}
	PFS_ASSERT(TAILQ_EMPTY(&rplhead) == true);
	return 0;
}

bool
pfs_mount_needsync(pfs_mount_t *mnt)
{
	bool skip = (readtx_skip_sync == PFS_OPT_ENABLE);

	/*
	 * Issuing a poll request when read tx begins in two cases:
	 * 1. on RO.
	 * 2. on RW but configured not to skip.
	 */
	return !pfs_writable(mnt) || !skip;
}

int
pfs_mount_sync(pfs_mount_t *mnt)
{
	int rv;
	struct tx_qhead rplhead;
	MNT_STAT_BEGIN();
	TAILQ_INIT(&rplhead);
	rv = pfs_log_request(&mnt->mnt_log, LOG_POLL, NULL, &rplhead);
	if (rv > 0) {
		rv = 0;
		if (!TAILQ_EMPTY(&rplhead)) {
			if (pfs_writable(mnt) && pfs_loggable(mnt))
				pfs_etrace("new log entries found, another writer exists!\n");
			pfs_txlist_replay(mnt, &rplhead);
		}
	}
	PFS_ASSERT(TAILQ_EMPTY(&rplhead) == true);
	MNT_STAT_END(MNT_STAT_SYNC_MOUNT);
	return rv;
}

void
pfs_mount_signal_sync(pfs_mount_t *mnt)
{
	mutex_lock(&mnt->mnt_poll_mtx);
	mnt->mnt_poll_sync = true;
	cond_signal(&mnt->mnt_poll_cond);
	mutex_unlock(&mnt->mnt_poll_mtx);
}

static void *
pfs_poll_thread_entry(void *arg)
{
	pfs_mount_t *mnt = (pfs_mount_t *)arg;
	struct timespec ts;
	int err;

	pfs_itrace("poll thread starts, period = %ds\n", poll_interval);

	pfs_wait_inited(mnt);
	if (pfs_init_failed(mnt))
		return NULL;
        for (;;) {
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += poll_interval;
                err = 0;
                mutex_lock(&mnt->mnt_poll_mtx);
                mnt->mnt_poll_sync = false;
                while (err == 0 && !mnt->mnt_poll_stop && !mnt->mnt_poll_sync)
                        err = pthread_cond_timedwait(&mnt->mnt_poll_cond,
                            &mnt->mnt_poll_mtx, &ts);
                mutex_unlock(&mnt->mnt_poll_mtx);

                if (mnt->mnt_poll_stop)
                        break;

                if (err && err != ETIMEDOUT) {
                        pfs_etrace("poll thread wait error %d, %s\n", err,
			    strerror(err));
                        continue;
                }

		err = pfs_mount_sync(mnt);
		if (err != 0)
			pfs_etrace("poll thread poll error %d\n", err);
        }
	pfs_itrace("poll thread stops\n");

	return NULL;
}

static int
pfs_poll_start(pfs_mount_t *mnt)
{
	int err;

	err = pthread_create(&mnt->mnt_poll_tid, NULL, pfs_poll_thread_entry, mnt);
	if (err) {
		mnt->mnt_poll_tid = 0;
		pfs_etrace("cant create poll log thread: %d, %s\n", err,
		    strerror(err));
		return -err;
	}
	return 0;
}

static void
pfs_poll_stop(pfs_mount_t *mnt)
{
	int rv;

	if (mnt->mnt_poll_tid) {
		mutex_lock(&mnt->mnt_poll_mtx);
		mnt->mnt_poll_stop = true;
		cond_signal(&mnt->mnt_poll_cond);
		mutex_unlock(&mnt->mnt_poll_mtx);

		rv = pthread_join(mnt->mnt_poll_tid, NULL);
		PFS_VERIFY(rv == 0);
		mnt->mnt_poll_tid = 0;
	}
}

static inline bool
pfs_mount_hasname(pfs_mount_t *mnt, const char *name)
{
	return strncmp(mnt->mnt_pbdname, name, sizeof(mnt->mnt_pbdname)) == 0;
}

static int
pfs_init_anode(pfs_mount_t *mnt, int mtype)
{
	int i;
	pfs_anode_t *an, *can;
	pfs_anode_t **tmp;

	an = &mnt->mnt_anode[mtype];
	memset(an, 0, sizeof(*an));
	if (mtype == MT_NTYPE)
		return 0;

	an->an_id = 0;
	an->an_shift = 0; /* root will not shift */
	tmp = (pfs_anode_t **)pfs_mem_realloc(an->an_children,
	    mnt->mnt_nchunk * sizeof(*tmp), M_ANODEV);
	if (tmp == NULL)
		ERR_RETVAL(ENOMEM);
	an->an_children = tmp;

	an->an_nchild = mnt->mnt_nchunk;
	for (i = 0; i < mnt->mnt_nchunk; i++) {
		can = &mnt->mnt_chunkv[i]->ck_metaset[mtype].ms_anode;
		can->an_parent = an;
		an->an_children[i] = can;
		pfs_anode_nfree_inc(an, i, can->an_nfree);
		an->an_nall += can->an_nall;
	}
	return 0;
}

/*
 * pfs_mnt2dev_flags:
 *
 * Convert rw permission in mntflags (MNTFLG_*) into devflags (DEVFLG_*)
 */
static int
pfs_mnt2dev_flags(int mntflags, bool require_safe)
{
	int devflags = 0;
	if (mntflags & MNTFLG_RD)
		devflags |= DEVFLG_RD;
	/* by default, writable dev is also readable */
	if (mntflags & MNTFLG_WR)
		devflags |= DEVFLG_RD|DEVFLG_WR;
	if (require_safe)
		devflags |= DEVFLG_REQ_SAFE;
	return devflags;
}

static int
pfs_create_mount(const char *cluster, const char *pbdname, int host_id,
    int flags, pfs_mount_t **mntp)
{
	int iodesc = -1;
	pfs_mount_t *mnt = NULL;
	int i, err = 0;
	struct pbdinfo pi;
	bool require_safe;
	int devflags;

	mnt = (pfs_mount_t *)pfs_mem_malloc(sizeof(*mnt), M_MOUNT);
	if (mnt == NULL)
		ERR_GOTO(ENOMEM, out);
	memset(mnt, 0, sizeof(*mnt));
	mnt->mnt_id = -1;
	mnt->mnt_epoch = -1;
	mnt->mnt_status = 0;
	mnt->mnt_hostid_fd = -1;
	mnt->mnt_nchunk = 0;
	mnt->mnt_chunkv = NULL;
	mnt->mnt_admin = NULL;
	pfs_avl_create(&mnt->mnt_inodetree, pfs_inode_compare,
	    offsetof(pfs_inode_t, in_node));
	TAILQ_INIT(&mnt->mnt_inodelist);
	mnt->mnt_host_id = host_id;
	mnt->mnt_host_generation = 0;
	mnt->mnt_num_hosts = 0;
	mnt->mnt_paxos_file = NULL;
	mnt->mnt_log.log_mount = mnt;
	mnt->mnt_poll_stop = false;
	mnt->mnt_poll_sync = false;
	mnt->mnt_poll_tid = 0;
	mnt->mnt_run_version = (uint64_t)-1;
	mnt->mnt_disk_version = 0;

	mnt->mnt_blksize = mnt->mnt_sectsize = mnt->mnt_fragsize = 0;
	mnt->mnt_disksize = 0;

	for (i = 0; i < BDS_NMAX; i++)
		mnt->mnt_bdroot[i] = NULL;
	mnt->mnt_changed_bdroot = NULL;
	mnt->mnt_discard_stop = false;
	mnt->mnt_discard_force = ((flags & MNTFLG_DISCARD_BYFORCE) != 0);
	mnt->mnt_stat_tid = 0;
	mnt->mnt_stat_stop = false;
	rwlock_init(&mnt->mnt_meta_rwlock, NULL);
	mutex_init(&mnt->mnt_inodetree_mtx);
	mutex_init(&mnt->mnt_inited_mtx);
	cond_init(&mnt->mnt_inited_cond, NULL);
	mutex_init(&mnt->mnt_poll_mtx);
	cond_init(&mnt->mnt_poll_cond, NULL);
	mutex_init(&mnt->mnt_discard_mtx);
	cond_init(&mnt->mnt_discard_cond, NULL);
	mutex_init(&mnt->mnt_stat_mtx);
	cond_init(&mnt->mnt_stat_cond, NULL);

	/**
	 * MySQL is bounded to a fixed io channel. Otherwise vestigial
	 * IOs from a crashed MySQL may overwrite ones from a new running
	 * MySQL that uses another IO channel.
	 */
	require_safe = flags & PFS_TOOL ? false : true;
	devflags = pfs_mnt2dev_flags(flags, require_safe);
	iodesc = pfsdev_open(cluster, pbdname, devflags);
	if (iodesc < 0) {
		pfs_etrace("cant open pbd %s\n", pbdname);
		ERR_GOTO(EIO, out);
	}

	/*
	 * Check the mount rw option against the capability of PBD.
	 * Bail out if they mismatch.
	 *
	 * We may get invalid rw type from an old version polarswitch
	 * that doesn't provide rw type. In that case, we go on even
	 * if rw type is unknown. If any write is tried on a ro PBD,
	 * it must crash at that time.
	 */
	if (pfsdev_info(iodesc, &pi) < 0) {
		pfs_etrace("cant get pbd info %s\n", pbdname);
		ERR_GOTO(EIO, out);
	}
	if ((flags & MNTFLG_WR) != 0 && pi.pi_rwtype == 0) {
		pfs_etrace("mount with write but pbd is readonly: "
			   "%#x vs %d\n", flags, pi.pi_rwtype);
		ERR_GOTO(EPERM, out);
	}

	if (strncpy_safe(mnt->mnt_pbdname, pbdname, sizeof(mnt->mnt_pbdname))
	    < 0) {
		pfs_etrace("too long pbd name %s\n", pbdname);
		ERR_GOTO(ENAMETOOLONG, out);
	}
	mnt->mnt_lockspace_name = mnt->mnt_pbdname;
	mnt->mnt_lock_name = "disk_paxos";
	mnt->mnt_flags = flags;
	mnt->mnt_ioch_desc = iodesc;

	*mntp = mnt;
	return 0;

out:
	if (mnt) {
		pfs_mem_free(mnt, M_MOUNT);
		mnt = NULL;
	}
	if (iodesc >= 0) {
		pfsdev_close(iodesc);
		iodesc = -1;
	}
	return err;
}

/*
 * pfs_destroy_mount:
 *
 *	Start destroying all refered objects and finally destroy the mount
 *	itself. The implementation should be safe even if some refered objects
 *	have not been initialized.
 */
static void
pfs_destroy_mount(pfs_mount_t *mnt)
{
	int i;

	/*
	 * All opened files must be closed.
	 * Otherwisw, we shall destroy all nodes by pfs_avl_destroy_nodes()
	 */
	//PFS_ASSERT(pfs_avl_is_empty(&mnt->mnt_inodetree));

	pfs_inode_t *in = (pfs_inode_t *)pfs_avl_first(&mnt->mnt_inodetree);
	while (in != NULL) {
		pfs_inode_t *tmp = in;
		in = (pfs_inode_t *)pfs_avl_next(&mnt->mnt_inodetree, in);
		pfs_avl_remove(&mnt->mnt_inodetree, tmp);
		// FIXME
		// Dir-index maintain the reference across inodes in the form
		// of pfs_dxent_t->e_in (see 77ddaef8 for details).
		// In PFSD, however, destroy-mount should clean up all inodes
		// left in inodelist LRU set. Throughout this process, we may
		// destroy child inode before its parent due to the random
		// order of avl traversal, leaving reference ('e_in') of parent
		// inode a dangling pointer and crash.
		// We hotfix this by calling a simlilar inode-destroy function.
		// The only difference is that it won't follow the reference
		// of inode.
		pfs_inode_destroy_self(tmp);
	}
	pfs_avl_destroy(&mnt->mnt_inodetree);

	/* destroy the anode */
	pfs_anode_destroy(&mnt->mnt_anode[MT_BLKTAG]);
	pfs_anode_destroy(&mnt->mnt_anode[MT_DIRENTRY]);
	pfs_anode_destroy(&mnt->mnt_anode[MT_INODE]);

	for (i = 0; i < mnt->mnt_nchunk; i++) {
		if (mnt->mnt_chunkv[i]) {
			pfs_meta_finish_chunk(mnt->mnt_chunkv[i]);
			mnt->mnt_chunkv[i] = NULL;
		}
	}
	pfs_mem_free(mnt->mnt_chunkv, M_CHUNKV);
	mnt->mnt_chunkv = NULL;

	if (mnt->mnt_ioch_desc >= 0) {
		pfsdev_close(mnt->mnt_ioch_desc);
		mnt->mnt_ioch_desc = -1;
	}

	// destory pfs read/write lock
	rwlock_destroy(&mnt->mnt_meta_rwlock);
	mutex_destroy(&mnt->mnt_inodetree_mtx);
	mutex_destroy(&mnt->mnt_inited_mtx);
	cond_destroy(&mnt->mnt_inited_cond);
	mutex_destroy(&mnt->mnt_poll_mtx);
	cond_destroy(&mnt->mnt_poll_cond);
	mutex_destroy(&mnt->mnt_discard_mtx);
	cond_destroy(&mnt->mnt_discard_cond);
	mutex_destroy(&mnt->mnt_stat_mtx);
	cond_destroy(&mnt->mnt_stat_cond);

	for (i = 0; i < BDS_NMAX; i++) {
		if (mnt->mnt_bdroot[i])
			pfs_bd_reset(&mnt->mnt_bdroot[i]);
	}
	if (mnt->mnt_changed_bdroot) {
		pfs_bd_reset(&mnt->mnt_changed_bdroot);
	}

	mnt->mnt_status = 0;
	mnt->mnt_admin = NULL;
	mnt->mnt_discard_force = false;

	pfs_mem_free(mnt, M_MOUNT);
}

int
pfs_mount(const char *cluster, const char *pbdname, int host_id, int flags)
{
	mountentry_t *me;
	int err = 0;
	int fd = -1;
	pfs_mount_t *mnt = NULL;

	// when connecting polarstore, DB will pass NULL as "cluster"
	if (cluster == NULL)
		cluster = CL_DEFAULT;

	if (pbdname == NULL) {
		pfs_etrace("invalid cluster(%s) or pbdname(%s)\n",
		    cluster ? cluster : "NULL", pbdname ? pbdname : "NULL");
		errno = EINVAL;
		return -1;
	}

	if (flags & MNTFLG_TOOL)
		pfs_trace_redirect(pbdname, 0);

	pfs_itrace("before mount, PBD(%s), hostid(%d), flags(0x%x)\n",
	    pbdname, host_id, flags);

	/* init pfs config from default path */
	if (pfs_option_init(NULL) != CONFIG_OK)
		pfs_etrace("pfs init option config failed, use default value PBD(%s), hostid(%d), flags(0x%x)\n",
		    pbdname, host_id, flags);
remount:
	/* ensure the pbd is nonexistent */
	me = mountentry_find_iter(mountentry_hasname, pbdname, RW_NOLOCK);
	if (me) {
		pfs_etrace("PBD %s has already been mounted\n", pbdname);
		errno = EEXIST;
		return -1;
	}
	/*
	 * XXX:
	 * there is race condition here since the same pbdname may have
	 * been mounted.
	 */

	/* find a free entry and wrlock it */
	me = mountentry_find_iter(mountentry_isfree, NULL, RW_WRLOCK);
	if (me == NULL) {
		pfs_etrace("no free mount entry\n");
		errno = EUSERS;
		return -1;
	}

	err = pfs_create_mount(cluster, pbdname, host_id, flags, &mnt);
	if (err < 0)
		goto finish_mount;

	pfs_trace_ctx_init(server_id, pfsdev_trace_pbdname(cluster, pbdname));
	if ((flags & MNTFLG_TOOL) == 0)
		pfs_mntstat_start(mnt);

	/* load leader record by direct devio I/O */
	if (flags & MNTFLG_LOG) {
		err = pfs_log_preload(&mnt->mnt_log);
		if (err < 0)
			goto finish_mount;
	}

	/* For pfsd, paxos_hostid_local_lock is moved up to SDK side */
	if (!pfs_ispfsd(mnt) && !pfs_istool(mnt) && pfs_writable(mnt)) {
		fd = paxos_hostid_local_lock(pbdname, DEFAULT_MAX_HOSTS + 1,
		    __func__);
		if (fd < 0) {
			err = fd;
			goto finish_mount;
		}
	}
	err = pfs_meta_load_all_chunks(mnt);
	if (err)
		goto finish_mount;
	err = pfs_version_select(mnt);
	if (err < 0)
		goto finish_mount;
	if (!pfs_istool(mnt) && pfs_writable(mnt)) {
		err = pfs_version_upgrade(mnt);
		/* For pfsd, paxos_hostid_local_unlock is moved up to SDK side*/
		paxos_hostid_local_unlock(fd);
		fd = -1;
		if (err < 0)
			goto finish_mount;
	}

	/* init allocation node */
	if (pfs_init_anode(mnt, MT_BLKTAG) < 0 ||
	    pfs_init_anode(mnt, MT_DIRENTRY) < 0 ||
	    pfs_init_anode(mnt, MT_INODE) < 0)
		ERR_GOTO(EIO, finish_mount);

	if ((flags & (PFS_TOOL|MNTFLG_PFSD)) == 0 && host_id == 0)
		ERR_GOTO(EINVAL, finish_mount);

	/* open log if required; paxos is the prerequisite for logging. */
	if (flags & MNTFLG_LOG) {
		err = pfs_leader_load(mnt);
		if (err < 0)
			goto finish_mount;

		err = pfs_log_start(&mnt->mnt_log);
		if (err < 0)
			goto finish_mount;

		err = pfs_load_log(mnt);
		if (err < 0)
			goto finish_mount;

		pfs_memdir_load(mnt);

		err = pfs_poll_start(mnt);
		if (err < 0)
			goto finish_mount;
	}

	/*
	 * build block-discard ready tree and inprocess tree.
	 */
	pfs_meta_bd_build_index(mnt);

	if ((flags & (MNTFLG_WR | MNTFLG_LOG | MNTFLG_TOOL)) ==
	    (MNTFLG_WR | MNTFLG_LOG) &&
	    (flags & MNTFLG_DISCARD_BYFORCE) == 0) {
		err = pfs_bd_start(mnt);
		if (err) {
			pfs_etrace("cant start discard thread\n");
			goto finish_mount;
		}
	}

	pfs_notify_inited(mnt);

	pfs_itrace("after mount, PBD(%s), hostid(%d), flags(0x%x)\n",
	    mnt->mnt_pbdname, mnt->mnt_host_id, mnt->mnt_flags);

	mountentry_init(me, mnt);
	mountentry_unlock(me);

	/*
	 * Only create adm thread for RDWR mount, but exclude PFSTOOL.
	 */
	if ((flags & (MNTFLG_LOG | MNTFLG_TOOL)) != MNTFLG_LOG)
		return 0;

	/*
	 * XXX
	 * It is not thread safe. There is race condition here when multi
	 * threads init admin during mounting the same pbd.
	 */
	mnt = pfs_get_mount(pbdname);
	if (mnt == NULL) {
		pfs_etrace("cant get mount %s\n", pbdname);
		errno = ENODEV;
		return -1;
	}
	if (flags & MNTFLG_WR) {
		err = pfs_orphans_reclaim(mnt);
		if (err < 0) {
			errno = EIO;
			pfs_etrace("cant reclaim orphans: err %d\n", err);
		}
	}
	if (err >= 0) {
		mnt->mnt_admin = pfs_admin_init(pbdname);
		if (mnt->mnt_admin == NULL) {
			pfs_etrace("cant init admin info: %d, %s\n", errno,
				   strerror(errno));
			errno = EINVAL;
			err = -1;
		} else
			err = 0;
	}
	pfs_put_mount(mnt);

	if (err)
		pfs_umount(pbdname);
	return err;

finish_mount:
	mountentry_unlock(me);
	if (fd >= 0) {
		/* For pfsd, paxos_hostid_local_unlock is moved up to SDK side*/
		PFS_ASSERT(!pfs_ispfsd(mnt));

		paxos_hostid_local_unlock(fd);
		fd = -1;
	}
	if (err && mnt) {
		/* confirm pfs mount is not succ */
		if (!pfs_inited(mnt)){
			pfs_notify_init_failed(mnt);
		}

		pfs_bd_stop(mnt);
		pfs_poll_stop(mnt);
		pfs_memdir_unload(mnt);
		pfs_admin_fini(mnt->mnt_admin, pbdname);
		if (mnt->mnt_log.log_file)
			pfs_log_stop(&mnt->mnt_log);

		pfs_leader_unload(mnt);
		pfs_mntstat_stop(mnt);
		pfs_trace_ctx_stop();
		pfs_destroy_mount(mnt);
		mnt = NULL;
	}
	if (err == -EAGAIN) {
		pfs_etrace("try to remount\n");
		goto remount;
	}
	errno = -err;
	return -1;
}

int
pfs_umount(const char *pbdname)
{
	pfs_mount_t *mnt = NULL;
	mountentry_t *me;

	if (!pbdname || strlen(pbdname) >= PFS_MAX_PBDLEN) {
		pfs_etrace("invalid pbdname %s\n", pbdname ? pbdname : "NULL");
		errno = EINVAL;
		return -1;
	}

	/*
	 * Stop admin thread if any. admin thread acts like an app
	 * thread in that it call pfs APIs. It may blocks on the mount
	 * entry lock while umount hold the lock and is waiting for
	 * its exit.
	 *
	 * XXX
	 * It is not thread safe. There is race condition here when multi
	 * threads fini admin during umounting the same pbd.
	 */
	mnt = pfs_get_mount(pbdname);
	if (mnt == NULL) {
		pfs_etrace("cannot find PBD %s\n", pbdname);
		errno = EINVAL;
		return -1;
	}
	pfs_admin_fini(mnt->mnt_admin, pbdname);
	mnt->mnt_admin = NULL;
	pfs_put_mount(mnt);

	me = mountentry_find_iter(mountentry_hasname, pbdname, RW_WRLOCK);
	if (me == NULL) {
		pfs_etrace("cannot find PBD %s\n", pbdname);
		errno = ENODEV;
		return -1;
	}
	mnt = me->me_mount;
	PFS_ASSERT(mnt != NULL);

	pfs_bd_stop(mnt);
	pfs_poll_stop(mnt);

	pfs_memdir_unload(mnt);
	if (mnt->mnt_log.log_file)
		pfs_log_stop(&mnt->mnt_log);

	pfs_namecache_clear_mount(mnt);
	pfs_leader_unload(mnt);
	pfs_mntstat_stop(mnt);
	mnt->mnt_status = 0;
	pfs_trace_ctx_stop();
	pfs_destroy_mount(mnt);

	mountentry_fini(me);
	mountentry_unlock(me);
	return 0;
}

pfs_mount_t *
pfs_get_mount(const char *pbdname)
{
	mountentry_t *me;

	if (!pbdname || strlen(pbdname) >= PFS_MAX_PBDLEN)
		return NULL;
	me = mountentry_find_iter(mountentry_hasname, pbdname, RW_RDLOCK);
	if (me == NULL)
		return NULL;
	return me->me_mount;
}

pfs_mount_t *
pfs_get_mount_byid(int mntid)
{
	mountentry_t *me = &mount_entry[mntid];

	if (mntid < 0 || mntid >= PFS_MAX_NMOUNT)
		return NULL;

	mountentry_rdlock(me);
	if (!me->me_mount) {
		mountentry_unlock(me);
		return NULL;
	}

	PFS_ASSERT(me->me_mount->mnt_epoch == me->me_epoch);
	return me->me_mount;
}

void
pfs_put_mount(pfs_mount_t *mnt)
{
	mountentry_t *me = &mount_entry[mnt->mnt_id];

	PFS_ASSERT(mnt->mnt_id >= 0 && mnt->mnt_id < PFS_MAX_NMOUNT);
	PFS_ASSERT(me->me_mount == mnt);

	mountentry_unlock(me);
}

pfs_inode_t *
pfs_get_inode(pfs_mount_t *mnt, pfs_ino_t ino)
{
	pfs_inode_t fin, *in;
	MNT_STAT_BEGIN();
	fin.in_ino = ino;
	INODE_LIST_LOCK(mnt);
	in = (pfs_inode_t *)pfs_avl_find(&mnt->mnt_inodetree, &fin, NULL);
	if (in != NULL) {
		++in->in_refcnt;
		if (in->in_refcnt == 1) {
			//Move "in" to tail so that do not disturb "head" swap
			//out.
			TAILQ_REMOVE(&mnt->mnt_inodelist, in, in_next);
			TAILQ_INSERT_TAIL(&mnt->mnt_inodelist, in, in_next);
		}
	}

	INODE_LIST_UNLOCK(mnt);
	MNT_STAT_END(MNT_STAT_CONTAINER_INODE_GET);
	return in;
}

void
pfs_put_inode(pfs_mount_t *mnt, pfs_inode_t *in)
{
	bool need_free = false;
	PFS_ASSERT(in != NULL);
	MNT_STAT_BEGIN();
	INODE_LIST_LOCK(mnt);
	--in->in_refcnt;
	if ((int)pfs_avl_numnodes(&mnt->mnt_inodetree) <=
	    inodetree_lru_size) {
		if (in->in_refcnt == 0) {
			//make in easier to be swap out.
			TAILQ_REMOVE(&mnt->mnt_inodelist, in, in_next);
			TAILQ_INSERT_HEAD(&mnt->mnt_inodelist, in, in_next);
		}
	} else {
		if (in->in_refcnt != 0) {
			//choose a candidate to be swap out.
			in = TAILQ_FIRST(&mnt->mnt_inodelist);
			if (in->in_refcnt != 0)
				in = NULL;
		}

		if (in != NULL) {
			pfs_avl_remove(&mnt->mnt_inodetree, in);
			TAILQ_REMOVE(&mnt->mnt_inodelist, in, in_next);
			need_free = true;
		}
	}
	INODE_LIST_UNLOCK(mnt);
	if (need_free)
		pfs_inode_destroy(in);
	MNT_STAT_END(MNT_STAT_CONTAINER_INODE_PUT);
}

pfs_inode_t *
pfs_add_inode(pfs_mount_t *mnt, pfs_inode_t *in)
{
	pfs_inode_t *in2;

	INODE_LIST_LOCK(mnt);
	in2 = (pfs_inode_t *)pfs_avl_find(&mnt->mnt_inodetree, in, NULL);
	if (in2 == NULL) {
		pfs_avl_add(&mnt->mnt_inodetree, in);
		//make in hard to be swap out.
		TAILQ_INSERT_TAIL(&mnt->mnt_inodelist, in, in_next);
		in2 = in;
	}
	INODE_LIST_UNLOCK(mnt);

	return in2;
}

int
pfs_mount_block_isused(pfs_mount_t *mnt, uint64_t btno)
{
	int used;

	pfs_meta_lock(mnt);
	used = pfs_meta_used_blktag(mnt, btno);
	pfs_meta_unlock(mnt);
	return used;
}

int
pfs_mount_flush(pfs_mount_t *mnt)
{
	int rv;
	struct tx_qhead rplhead;

	TAILQ_INIT(&rplhead);
	do {
		rv = pfs_log_request(&mnt->mnt_log, LOG_FLUSH, NULL, &rplhead);
		PFS_ASSERT(TAILQ_EMPTY(&rplhead));
		if (rv < 0 && rv != -ENODATA && rv != -EAGAIN) {
			pfs_itrace("LOG_FLUSH failed, rv=%d\n", rv);
			break;
		}
		/*
		 * Maybe new log entries are found, wait poll thread sending
		 * a LOG_POLL to poll those entries.
		 */
		if (rv == -EAGAIN)
			usleep(100);
	} while (rv != -ENODATA);

	if (rv == -ENODATA)
		return 0;
	else
		return rv;
}

int
pfs_mount_growfs(const char *pbdname)
{
	int err;
	int oldnchunk;
	pfs_mount_t *mnt;

	if (!pbdname || strlen(pbdname) >= PFS_MAX_PBDLEN) {
		pfs_etrace("invalid pbdname %s\n", pbdname ? pbdname : "NULL");
		errno = EINVAL;
		return -1;
	}
	mnt = pfs_get_mount(pbdname);
	if (!mnt) {
		pfs_etrace("cannot find PBD %s\n", pbdname);
		errno = EINVAL;
		return -1;
	}

	pfs_itrace("PBD %s old disk size is %llu, nchunk is %d\n",
	    mnt->mnt_pbdname, (unsigned long long)mnt->mnt_disksize,
	    mnt->mnt_nchunk);

	MOUNT_META_WRLOCK(mnt);
	if (!pfs_inited(mnt)) {
		pfs_etrace("%s mount isn't inited\n", mnt->mnt_pbdname);
		ERR_GOTO(EINVAL, out);
	}

	/* sync block device state */
	err = pfsdev_reload(mnt->mnt_ioch_desc);
	if (err < 0) {
		pfs_etrace("%s reload failed\n", mnt->mnt_pbdname);
		goto out;
	}

	/* load extra chunks */
	oldnchunk = mnt->mnt_nchunk;
	err = pfs_meta_load_all_chunks(mnt);
	if (err < 0) {
		pfs_etrace("%s growfs failed\n", mnt->mnt_pbdname);
		if (oldnchunk != mnt->mnt_nchunk) {
			PFS_ASSERT("mnt_chunkv realloced to new size" == NULL);
			exit(EINVAL);
		} else
			goto out;
	}

	/* reload all anodes */
	if (mnt->mnt_nchunk != oldnchunk) {
		if (pfs_init_anode(mnt, MT_BLKTAG) < 0 ||
		    pfs_init_anode(mnt, MT_DIRENTRY) < 0 ||
		    pfs_init_anode(mnt, MT_INODE) < 0) {
			PFS_ASSERT("anode grows failed" == NULL);
			exit(EINVAL);
		}
	}

	pfs_itrace("PBD %s new disk size is %llu, nchunk is %d\n",
	    mnt->mnt_pbdname, (unsigned long long)mnt->mnt_disksize,
	    mnt->mnt_nchunk);

	MOUNT_META_UNLOCK(mnt);
	pfs_put_mount(mnt);
	return 0;

out:
	MOUNT_META_UNLOCK(mnt);
	pfs_put_mount(mnt);
	errno = -err;
	return -1;
}

static void
pfs_wait_inited(pfs_mount_t *mnt)
{
	mutex_lock(&mnt->mnt_inited_mtx);
	while (!pfs_inited(mnt) && !pfs_init_failed(mnt))
		cond_wait(&mnt->mnt_inited_cond, &mnt->mnt_inited_mtx);
	mutex_unlock(&mnt->mnt_inited_mtx);
}

static void
pfs_notify_inited(pfs_mount_t *mnt)
{
	mutex_lock(&mnt->mnt_inited_mtx);
	mnt->mnt_status = MNTST_INITED;
	cond_broadcast(&mnt->mnt_inited_cond);
	mutex_unlock(&mnt->mnt_inited_mtx);
}

/*
* \brief: notify blocking thread to handle pfs_mount's failure
*/
static void
pfs_notify_init_failed(pfs_mount_t *mnt)
{
	mutex_lock(&mnt->mnt_inited_mtx);
	mnt->mnt_status = MNTST_FAILED;
	cond_broadcast(&mnt->mnt_inited_cond);
	mutex_unlock(&mnt->mnt_inited_mtx);
}

#define	PHYIN_IS_LARGE_FILE(phyin)		\
	((phyin)->in_type == PFS_INODET_FILE && \
	    ((int64_t)(phyin)->in_size) > file_shrink_size)

static void
pfs_orphans_inode_reclaim(void *data, pfs_metaobj_phy_t *mo)
{
	orphan_largefile_arg_t *args = (orphan_largefile_arg_t*)data;
	pfs_mount_t *mnt = args->or_mnt;
	pfs_inode_phy_t *phyin = MO2IN(mo);
	int err = 0;
	if (PHYIN_ISORPHAN(phyin)) {
		if (PHYIN_IS_LARGE_FILE(phyin)) {
			if (args->or_large_orphan_fcount < MAX_NLARGEORPHAN) {
				args->or_array[args->or_large_orphan_fcount].
				    or_large_orphan_fino = mo->mo_number;
				args->or_array[args->or_large_orphan_fcount].
				    or_large_orphan_fbtime = phyin->in_btime;
			}
			++args->or_large_orphan_fcount;
			return;
		}
		err = pfs_inodephy_release(mnt, mo->mo_number, phyin->in_btime);
		//We can not return error.
		PFS_VERIFY(err >= 0);
	}
}

static int
pfs_orphans_reclaim(pfs_mount_t *mnt)
{
	int err = -EAGAIN, err1;
	int i = 0;
	orphan_largefile_arg_t args;

	while (err == -EAGAIN) {
		err = 0;
		memset(&args, 0, sizeof(args));
		args.or_mnt = mnt;
		tls_write_begin(mnt);
		//Manually lock because we iterate meta before we change it.
		pfs_meta_lock(mnt);
		for (i = 0; i < mnt->mnt_nchunk; ++i)
			pfs_meta_visit(mnt, MT_INODE, i, -1,
			    pfs_orphans_inode_reclaim, &args);
		tls_write_end(err);
		if (err < 0 && err != -EAGAIN)
			goto out;
		i = 0;
		pfs_itrace("Release %lu large orphans!\n",
		    args.or_large_orphan_fcount);
		for (i = 0; args.or_large_orphan_fcount != 0 &&
		    i < MAX_NLARGEORPHAN; ++i, --args.or_large_orphan_fcount) {
			do {
				err1 = pfs_file_release(mnt,
				    args.or_array[i].or_large_orphan_fino,
				    args.or_array[i].or_large_orphan_fbtime);
			} while (err1 == -EAGAIN);
			if (err1 < 0) {
				err = err1;
				goto out;
			}
		}
		if (args.or_large_orphan_fcount != 0)
			err = -EAGAIN;
	}
out:
	return err;
}

static void
pfs_bd_free(tnode_t *node)
{
	/* the key is a meta object number, nothing to free */
}

int
pfs_bd_compare(const void *keya, const void *keyb)
{
	int64_t btno1 = (int64_t)keya;
	int64_t btno2 = (int64_t)keyb;

	if (btno1 > btno2)
		return 1;
	if (btno1 < btno2)
		return -1;
	return 0;
}

/*
 * Select blocks to discard. Prefer to blocks already in discarding.
 * Otherwise, discard new free blocks.
 */
static void
pfs_bd_select(pfs_mount_t *mnt, tnode_t **bdrootp, bool *backoff)
{
	tnode_t *node;
	int64_t btno;
	int n;

	MOUNT_META_WRLOCK(mnt);
	if (mnt->mnt_bdroot[BDS_INP]) {
		/*
		 * There are inprogress block discards, either because
		 * other nodes are discarding blocks or we got commit
		 * conflicts with others. We prefer to these blocks to
		 * avoid throwing out new ones.
		 *
		 * Also we try to backoff in this case, either to make
		 * sure others can finish their block discarding or avoid
		 * more conflicts.
		 */
		*bdrootp = mnt->mnt_bdroot[BDS_INP];
		mnt->mnt_bdroot[BDS_INP] = NULL;
		MOUNT_META_UNLOCK(mnt);
		*backoff = true;
		return;
	}

	n = 0;
	while ((btno = pfs_bd_get(mnt, BDS_READY)) >= 0 &&
	    n < discard_ninp) {
		pfs_bd_del(mnt, BDS_READY, btno);
		node = (tnode_t *)tsearch((tkey_t *)btno, bdrootp, pfs_bd_compare);
		PFS_ASSERT(node != NULL);
		n++;
	}
	if (n > 0)
		pfs_itrace("find %d blocks to discard\n", n);
	MOUNT_META_UNLOCK(mnt);
	*backoff = false;
}

/*
 * Mark the block tags in the current bd tree as discarding.
 *
 * If there are new discarding block tags in inp_bdroot,
 * ohter nodes must have committed changes to these block
 * tags. We bail out to retry marking.
 *
 * We try to mark all block tags in bd tree as discarding.
 * However, there may be block tag changes by other threads
 * between the time window of pfs_bd_select and pfs_bd_mark_discarding.
 * We record the changed block tags into changed bd tree.
 * These changed block tags are removed from current bd tree.
 */
static void
pfs_bd_mark_inp_walkfn(const tnode_t *node, VISIT vis, int level)
{
	int64_t btno = (int64_t)TNODE_KEY(node);
	pfs_mount_t *mnt;
	pfs_tx_t *tx;
	tnode_t *ptr;
	bool ok;

	if (vis != postorder && vis != leaf)
		return;

	tx = pfs_tls_get_tx();
	PFS_ASSERT(tx != NULL);
	mnt = tx->t_mnt;
	PFS_ASSERT(mnt != NULL);

	ok = pfs_meta_bd_mark_inp(mnt, btno);
	/*
	 * When discard forcedly flag is set, then unused blk which
	 * dstatus is NONE will be discarded forcedly. Meanwhile,
	 * status of such kind of blk doesn't change.
	 */
	if (!ok && !mnt->mnt_discard_force) {
		// inseart into work bd tree
		ptr = (tnode_t *)tsearch((tkey_t *)btno,
		    &mnt->mnt_changed_bdroot, pfs_bd_compare);
		PFS_ASSERT(ptr != NULL);
	}
}

static int
pfs_bd_mark_inp(pfs_mount_t *mnt, tnode_t **bdrootp)
{
	tkey_t *key;
	tnode_t *node;

	pfs_meta_lock(mnt);

	PFS_ASSERT(mnt->mnt_changed_bdroot == NULL);
	twalk(*bdrootp, pfs_bd_mark_inp_walkfn);
	while ((node = mnt->mnt_changed_bdroot) != NULL) {
		key = TNODE_KEY(node);
		(void)tdelete(key, &mnt->mnt_changed_bdroot, pfs_bd_compare);
		(void)tdelete(key, bdrootp, pfs_bd_compare);
	}

	/*
	 * Status of all selected blocks have changed, bdroot becomes
	 * empty, then skip subsequent steps.
	 */
	if (*bdrootp == NULL)
		return -ENODATA;
	return 0;
}

static void
pfs_bd_mark_done_walkfn(const tnode_t *node, VISIT vis, int level)
{
	int64_t btno = (int64_t)TNODE_KEY(node);
	pfs_tx_t *tx;
	pfs_mount_t *mnt;
	tnode_t *ptr;
	bool ok;

	if (vis != postorder && vis != leaf)
		return;

	tx = pfs_tls_get_tx();
	PFS_ASSERT(tx != NULL);
	mnt = tx->t_mnt;
	PFS_ASSERT(mnt != NULL);

	ok = pfs_meta_bd_mark_done(mnt, btno);
	if (!ok && !mnt->mnt_discard_force) {
		/* inseart into done block discard tree */
		ptr = (tnode_t *)tsearch((tkey_t *)btno,
		    &mnt->mnt_changed_bdroot, pfs_bd_compare);
		PFS_ASSERT(ptr != NULL);
	}
}

static int
pfs_bd_mark_done(pfs_mount_t *mnt, tnode_t **bdrootp)
{
	tkey_t *key;
	tnode_t *node;

	pfs_meta_lock(mnt);

	PFS_ASSERT(mnt->mnt_changed_bdroot == NULL);
	twalk(*bdrootp, pfs_bd_mark_done_walkfn);
	while ((node = mnt->mnt_changed_bdroot) != NULL) {
		key = TNODE_KEY(node);
		(void)tdelete(key, &mnt->mnt_changed_bdroot, pfs_bd_compare);
		(void)tdelete(key, bdrootp, pfs_bd_compare);
	}

	/*
	 * Status of all selected blocks have changed, bdroot becomes
	 * empty, then skip subsequent steps.
	 */
	if (*bdrootp == NULL)
		return -ENODATA;
	return 0;
}

static void
pfs_bd_execute_walkfn(const tnode_t *node, VISIT vis, int level)
{
	int err;
	uint64_t btno;
	pfs_blkno_t blkno;
	pfs_bd_info_t *bdi;
	pfs_mount_t *mnt;

	if (vis != postorder && vis != leaf)
		return;

	bdi = pfs_tls_get_bdinfo();
	bdi->i_ntotal++;
	if (bdi->i_err)
		return;

	mnt = bdi->i_mnt;
	btno = (int64_t)TNODE_KEY(node);
	blkno = btno2blkno(mnt, btno);

	PFS_ASSERT(blkno % PFS_NBT_PERCHUNK != 0);
	err = pfsdev_trim(mnt->mnt_ioch_desc, blkno * PFS_BLOCK_SIZE);
	if (err < 0) {
		pfs_etrace("exec discard block(btno:%lu, blkno:%ld) failed,"
		    " err=%d\n", btno, blkno, err);
		bdi->i_err = err;
		return;
	}
	pfs_dbgtrace("discard blk(btno:%lu, blkno:%ld)\n", btno, blkno);
	bdi->i_ndone++;
}

static int
pfs_bd_execute(pfs_mount_t *mnt, tnode_t **bdrootp)
{
	pfs_bd_info_t bdi;

	memset(&bdi, 0, sizeof(bdi));
	bdi.i_mnt = mnt;
	bdi.i_err = 0;
	bdi.i_ndone = 0;
	bdi.i_ntotal = 0;

	pfs_tls_set_ttl(discard_period);
	pfs_tls_set_bdinfo(&bdi);
	twalk(*bdrootp, pfs_bd_execute_walkfn);
	pfs_tls_set_bdinfo(NULL);
	pfs_tls_set_ttl(0);

	pfs_itrace("discard %d of %d blocks successfully, error: %d\n",
	    bdi.i_ndone, bdi.i_ntotal, bdi.i_err);
	return bdi.i_err;
}

static void
pfs_bd_reset(tnode_t **bdrootp)
{
	if (*bdrootp) {
		tdestroy(*bdrootp, pfs_bd_free);
		*bdrootp = NULL;
	}
}

void
pfs_bd_add(pfs_mount_t *mnt, int bds, int64_t btno)
{
	tkey_t *key = (tkey_t *)btno;
	tnode_t *node;

	PFS_ASSERT(bds >= BDS_NONE && bds < BDS_NMAX);
	node = (tnode_t *)tsearch(key, &mnt->mnt_bdroot[bds], pfs_bd_compare);
	PFS_ASSERT(node != NULL);
	PFS_ASSERT((int64_t)(TNODE_KEY(node)) == btno);
}

void
pfs_bd_del(pfs_mount_t *mnt, int bds, int64_t btno)
{
	tkey_t *key = (tkey_t *)btno;

	PFS_ASSERT(bds >= BDS_NONE && bds < BDS_NMAX);
	(void)tdelete(key, &mnt->mnt_bdroot[bds], pfs_bd_compare);
}

int64_t
pfs_bd_find(pfs_mount_t *mnt, int bds, int64_t btno)
{
	tkey_t *key = (tkey_t *)btno;
	tnode_t *node;

	PFS_ASSERT(bds >= BDS_NONE && bds < BDS_NMAX);
	node = (tnode_t *)tfind(key, &mnt->mnt_bdroot[bds], pfs_bd_compare);
	if (node == NULL)
		return -1;
	PFS_ASSERT((int64_t)(TNODE_KEY(node)) == btno);
	return btno;
}

int64_t
pfs_bd_get(pfs_mount_t *mnt, int bds)
{
	PFS_ASSERT(bds >= BDS_NONE && bds < BDS_NMAX);
	if (mnt->mnt_bdroot[bds] == NULL)
		return -1;
	return (int64_t)TNODE_KEY(mnt->mnt_bdroot[bds]);
}

int
pfs_bd_discard(pfs_mount_t *mnt, tnode_t **bdroot)
{
	int err;

	err = 0;
	tls_write_begin(mnt);
	err = pfs_bd_mark_inp(mnt, bdroot);
	tls_write_end(err);
	if (err) {
		/*
		 * We may conflict with other nodes. In that case,
		 * it is not real error, but interesting to see.
		 *
		 * Note that in the txop_undo, the block tags are
		 * first rolled back and put into either ready_bdroot
		 * or inp_bdroot.
		 */
		if (err != -ENODATA) {
			pfs_etrace("failed to commit discarding: error %d (%s)\n",
			    err, strerror(-err));
		}
		return err;
	}

	err = pfs_bd_execute(mnt, bdroot);
	if (err < 0)
		return err;

	tls_write_begin(mnt);
	err = pfs_bd_mark_done(mnt, bdroot);
	tls_write_end(err);
	if (err) {
		if (err != -ENODATA) {
			pfs_etrace("failed to commit discarded: error %d (%s)\n",
			    err, strerror(-err));
		}
		return err;
	}

	return 0;
}

void *
pfs_bd_thread_entry(void *arg)
{
	int err;
	pfs_mount_t *mnt = (pfs_mount_t *)arg;
	struct timespec ts;
	tnode_t *bdroot = NULL;
	bool quiescent;

	pfs_wait_inited(mnt);
	if (pfs_init_failed(mnt))
		return NULL;
	bdroot = NULL;

	pfs_itrace("block discard thread starts, interval = %d, period = %d"
	    ", ninp = %d\n", discard_interval, discard_period, discard_ninp);
	err = 0;
	for (;;) {
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += discard_interval;
                err = 0;
                mutex_lock(&mnt->mnt_discard_mtx);
                while (err == 0 && !mnt->mnt_discard_stop)
                        err = pthread_cond_timedwait(&mnt->mnt_discard_cond,
                            &mnt->mnt_discard_mtx, &ts);
                mutex_unlock(&mnt->mnt_discard_mtx);

                if (mnt->mnt_discard_stop)
                        break;

                if (err && err != ETIMEDOUT) {
                        pfs_etrace("discard thread wait error %d, %s\n", err,
			    strerror(err));
                        continue;
                }

		PFS_ASSERT(bdroot == NULL && mnt->mnt_discard_force == false);
		quiescent = false;
		pfs_bd_select(mnt, &bdroot, &quiescent);
		if (bdroot == NULL)
			continue;
		if (quiescent) {
			pfs_itrace("detect discard conflict, sleep %ds\n",
			    discard_period);
			sleep(discard_period);
		}

		(void)pfs_bd_discard(mnt, &bdroot);
		pfs_bd_reset(&bdroot);
	}
	pfs_itrace("block discard thread stops\n");

	return NULL;
}

/*
 * Change blktag's mo_number to a continuous blkno which starts from 0 and end with
 * chunk count * PFS_NBT_PERCHUNK.
 */
pfs_blkno_t
btno2blkno(pfs_mount_t *mnt, uint64_t btno)
{
	uint64_t ckno, btid;	/* chunk number and blktag id */
	uint32_t shift;

	shift = ffs(roundup_power2(PFS_NBT_PERCHUNK)) - 1;
	ckno = btno >> shift;
	btid = btno - (ckno << shift);
	return (ckno * PFS_NBT_PERCHUNK + btid);
}

uint64_t
blkno2btno(pfs_mount_t *mnt, pfs_blkno_t blkno)
{
	uint64_t ckno, btid;	/* chunk number and blktag id */
	uint32_t shift;

	shift = ffs(roundup_power2(PFS_NBT_PERCHUNK)) - 1;
	ckno = blkno / PFS_NBT_PERCHUNK;
	btid = blkno % PFS_NBT_PERCHUNK;
	return ((ckno << shift) + btid);
}

static int
pfs_bd_start(pfs_mount_t *mnt)
{
	int err;

	err = pthread_create(&mnt->mnt_discard_tid, NULL,
	    pfs_bd_thread_entry, mnt);
	if (err) {
		mnt->mnt_discard_tid = 0;
		pfs_etrace("cant create discard thread: %d, %s\n",
		    err, strerror(err));
		return -err;
	}
	return 0;
}

static void
pfs_bd_stop(pfs_mount_t *mnt)
{
	int rv;

	if (mnt->mnt_discard_tid) {
		mutex_lock(&mnt->mnt_discard_mtx);
		mnt->mnt_discard_stop = true;
		cond_signal(&mnt->mnt_discard_cond);
		mutex_unlock(&mnt->mnt_discard_mtx);

		rv = pthread_join(mnt->mnt_discard_tid, NULL);
		PFS_VERIFY(rv == 0);
		mnt->mnt_discard_tid = 0;
	}
}

int
pfs_mount_fstrim(pfs_mount_t *mnt, int64_t beginid, int64_t endid, bool all)
{
	int err;
	int64_t ckid;
	discard_args_t data;

	if (beginid < 0)
		beginid = 0;
	if (endid < 0)
		endid = mnt->mnt_nchunk;

	if (endid > mnt->mnt_nchunk || beginid >= endid) {
		pfs_etrace("invalid chunk range [%ld, %ld), PBD %s has %d valid"
		     " chunks\n", beginid, endid, mnt->mnt_pbdname, mnt->mnt_nchunk);
		errno = EINVAL;
		return -1;
	}
	pfs_itrace("try to discard blks in chunk range [%ld, %ld)\n",
	    beginid, endid);

	err = 0;
	data.d_all = all;
	data.d_bdroot = NULL;
	for (ckid = beginid; ckid < endid; ckid++) {
		data.d_ckid = ckid;
		data.d_nblk = 0;
		pfs_meta_bd_select(mnt, ckid, &data);
		if (data.d_bdroot == NULL)
			continue;

		pfs_itrace("try to discard %ld blks in chunk %ld\n", data.d_nblk, ckid);
		err = pfs_bd_discard(mnt, &data.d_bdroot);
		pfs_bd_reset(&data.d_bdroot);
		data.d_bdroot = NULL;

		if (err < 0) {
			pfs_etrace("discard blks failed, err=%d\n", err);
			break;
		}
	}
	return err;
}

void
pfs_dump_used(pfs_mount_t *mnt, int type, int ckid[2])
{
	int i, j, n;
	oidvect_t ov;
	uint64_t oid;

	if (ckid[0] < 0)
		ckid[0] = 0;
	if (ckid[1] < 0 || ckid[1] > mnt->mnt_nchunk)
		ckid[1] = mnt->mnt_nchunk;
	for (i = ckid[0]; i < ckid[1]; i++) {
		n = 0;
		oidvect_init(&ov);
		pfs_meta_used_oid(mnt, type, i, &ov);
		printf("chunk %d has used %d objects:\n", i,
		       oidvect_end(&ov) - oidvect_begin(&ov));
		for (j = oidvect_begin(&ov); j < oidvect_end(&ov); j++) {
			oid = oidvect_get(&ov, j);
			printf("%6lu ", oid);
			if ((++n % 10) == 0)
				printf("\n");
		}
		if ((n % 10) != 0)
			printf("\n");
		oidvect_fini(&ov);
	}
}

int
pfs_list_used(pfs_mount_t *mnt, int type, int ckid, oidvect_t *ov)
{
	if (type <= MT_NONE || type >= MT_NTYPE)
		ERR_RETVAL(EINVAL);

	if (ckid < 0 || ckid >= mnt->mnt_nchunk)
		ERR_RETVAL(EINVAL);

	pfs_meta_used_oid(mnt, type, ckid, ov);
	return 0;
}

static void
pfs_dump_metaobj(void *data, pfs_metaobj_phy_t *mo)
{
	pfs_metaobj_dump(mo, 0);
}

/*
 * pfs_dump_meta:
 *
 *	dump metadata as specified by parameters
 *	@type	< 0 means all metatypes;
 *		> 0 means one type.
 *	@ckid	< 0 means all chunks;
 *		>= 0 means one chunk.
 *	@objid  < 0 means all objects;
 *		>= means one object.
 *
 *	FIXME:
 *	currently, there is no way to check the validity of
 *	@objid when it is nonnegtive.
 */
void
pfs_dump_meta(pfs_mount_t *mnt, int type, int ckid, int objid)
{
	int i;

	if (type < 0) {
		pfs_dump_meta(mnt, MT_BLKTAG, ckid, objid);
		pfs_dump_meta(mnt, MT_DIRENTRY, ckid, objid);
		pfs_dump_meta(mnt, MT_INODE, ckid, objid);
		return;
	}
	if (ckid < 0) {
		for (i = 0; i < mnt->mnt_nchunk; i++) {
			pfs_dump_meta(mnt, type, i, objid);
		}
		return;
	}

	if (type <= MT_NONE || type >= MT_NTYPE) {
		pfs_etrace("unknown type %d\n", type);
		return;
	}
	if (ckid >= mnt->mnt_nchunk) {
		pfs_etrace("too large chunkid %d\n", ckid);
		return;
	}
	pfs_meta_visit(mnt, type, ckid, objid, pfs_dump_metaobj, NULL);
}

/*
 * pfs_mount has recorded file system's attributes, metadata cache and
 * opened device, etc. It is built by mount() with a costly operation of
 * loading metadata.
 *
 * If we only want to modify mounted file system's attributes, called
 * remount(), what we should do is updating necessary information in
 * pfs_mount excluding the metadata cache.
 *
 * To make modification of pfs_mount safe, we should protect pfs_mount
 * from other threads which can be divided into two categories:
 * 1. user threads: They only call API and acquire RDLOCK of mountentry
 * before accessing pfs_mount.
 * 2. built-in threads: They are created by libpfs and usually access
 * raw pfs_mount pointer directly, such as poll/block-discard/log/admin
 * threads([1]).
 *
 * The remount thread will acquire WRLOCK of mountentry and stop/suspend
 * all built-in threads([2]). The implementation is as follows:
 *              /- stop built-in threads expect log thread
 * 1. prepare--|-  suspend log thread
 *              \- unload paxos
 * 2. do_remount-- reopen device
 *              /- load paxos
 * 3. done-----|-  resume log thread
 *              \- start built-in threads
 *
 * ------
 * [1] Admin thread and its command threads access libpfs through API while
 * 'lsof' command accesses multiple pfs_mount objects directly.
 * [2] Log thread is only suspended because trimgroups shouldn't be freed.
 */

int
pfs_remount_rw(const char *pbdname, int host_id, int flags)
{
	int err, devflags;
	struct pbdinfo pi;
	mountentry_t *me;

	pfs_mount_t *mnt = pfs_get_mount(pbdname);
	if (mnt == NULL) {
		pfs_etrace("cant find pbd %s\n", pbdname);
		ERR_RETVAL(ENODEV);
	}
	pfs_itrace("before remount, PBD(%s), hostid(%d), mnt_flags(0x%x)\n",
	    mnt->mnt_pbdname, mnt->mnt_host_id, mnt->mnt_flags);

	PFS_ASSERT(mnt->mnt_discard_force == false &&
	    (flags & MNTFLG_WR) == MNTFLG_WR);
	if (pfsdev_info(mnt->mnt_ioch_desc, &pi) < 0) {
		pfs_etrace("cant get pbd info %s\n", mnt->mnt_pbdname);
		pfs_put_mount(mnt);
		ERR_RETVAL(EIO);
	}
	if (pi.pi_rwtype != 1) {
		pfs_etrace("remount with write but pbd is readonly: %#x vs %d\n"
		    , flags, pi.pi_rwtype);
		pfs_put_mount(mnt);
		ERR_RETVAL(EPERM);
	}
	pfs_admin_fini(mnt->mnt_admin, pbdname);
	mnt->mnt_admin = NULL;
	pfs_put_mount(mnt);

	me = mountentry_find_iter(mountentry_hasname, pbdname, RW_WRLOCK);
	if (me == NULL) {
		pfs_etrace("cannot find PBD %s\n", pbdname);
		ERR_RETVAL(ENODEV);
	}
	mnt = me->me_mount;
	pfs_bd_stop(mnt);
	pfs_poll_stop(mnt);
	pfs_log_suspend(&mnt->mnt_log);
	pfs_leader_unload(mnt);
	mnt->mnt_discard_stop = false;
	mnt->mnt_poll_stop = false;
	mnt->mnt_status = 0;
	mnt->mnt_flags = 0;

	/*
	 * do remount:
	 * - reopen device.
	 */
	devflags = pfs_mnt2dev_flags(flags, true);
	err = pfsdev_reopen(mnt->mnt_ioch_desc, NULL, mnt->mnt_pbdname,
	    devflags);
	if (err < 0) {
		pfs_etrace("reopen failed, err=%d, it is unrecoverable\n");
		exit(EIO);
	}
	if (pfsdev_info(mnt->mnt_ioch_desc, &pi) < 0) {
		pfs_etrace("cant get pbd info %s\n", mnt->mnt_pbdname);
		exit(EIO);
	}
	if ((flags & MNTFLG_WR) != 0 && pi.pi_rwtype != 1) {
		pfs_etrace("remount with write but pbd is readonly: %#x vs %d\n"
		    , flags, pi.pi_rwtype);
		exit(EPERM);
	}
	mnt->mnt_host_id = host_id;
	mnt->mnt_flags = flags;

	/*
	 * done remount:
	 * - load paxos.
	 * - resume log thread.
	 * - start built-in threads.
	 */
	err = pfs_leader_load(mnt);
	if (err < 0) {
		pfs_etrace("load paxos file failed, err=%d\n", err);
		exit(EIO);
	}

	pfs_log_resume(&mnt->mnt_log);
	err = pfs_poll_start(mnt);
	if (err < 0) {
		pfs_etrace("can't start poll thread, err=%d\n", err);
		exit(EIO);
	}

	PFS_ASSERT(mnt->mnt_changed_bdroot == NULL);
	if ((flags & (MNTFLG_WR | MNTFLG_LOG)) == (MNTFLG_WR | MNTFLG_LOG)) {
		err = pfs_bd_start(mnt);
		if (err) {
			pfs_etrace("cant start discard thread, err=%d\n", err);
			exit(EIO);
		}
	}
	do {
		err = pfs_mount_sync(mnt);
		if (err != 0)
			pfs_etrace("mount_sync error %d\n", err);
		if (err != 0 && err != -EAGAIN)
			exit(EIO);
	} while (err == -EAGAIN);
	pfs_notify_inited(mnt);
	pfs_itrace("after remount, PBD(%s), hostid(%d), mnt_flags(0x%x)\n",
	    mnt->mnt_pbdname, mnt->mnt_host_id, mnt->mnt_flags);
	mountentry_unlock(me);

	mnt = pfs_get_mount(pbdname);
	if (mnt == NULL) {
		//between mountentry_unlock and pfs_get_mount, it is unmounted.
		pfs_etrace("cant get mount %s\n", pbdname);
		errno = ENODEV;
		return -1;
	}

	err = pfs_orphans_reclaim(mnt);
	if (err < 0) {
		errno = EIO;
		pfs_etrace("remount cant reclaim orphans: err %d\n", err);
		return err;
	}

	mnt->mnt_admin = pfs_admin_init(pbdname);
	if (mnt->mnt_admin == NULL) {
		pfs_etrace("cant init admin info: %d, %s\n", errno,
		    strerror(errno));
		exit(EINVAL);
	}
	pfs_put_mount(mnt);
	return 0;
}

int
pfs_remount_ro(pfs_mount_t *mnt, int host_id)
{
	int err = 0;
	if (pfs_writable(mnt)) {
		pfs_bd_stop(mnt);
		pfs_log_suspend(&mnt->mnt_log);
		pfs_leader_unload(mnt);
		mnt->mnt_discard_stop = false;
		mnt->mnt_host_id = host_id;
		mnt->mnt_status = 0;
		mnt->mnt_flags &= (~MNTFLG_WR);
		err = pfs_leader_load(mnt);
		if (err < 0) {
			pfs_etrace("load paxos file failed, err=%d\n", err);
			exit(EIO);
		}
		pfs_log_resume(&mnt->mnt_log);
		pfs_notify_inited(mnt);
	} else {
		mnt->mnt_host_id = host_id;
	}

	return err;
}

static int  pfsd_mnt_wrref_count = 0;
static int  pfsd_mnt_ref_count = 0;

static pthread_mutex_t pfsd_mnt_shared_info_lock = PTHREAD_MUTEX_INITIALIZER;
typedef struct pfsd_mount_shared_info {
	int ms_ref_count;
	bool ms_is_rwmnt;
}pfsd_mount_shared_info_t;

static pfsd_mount_shared_info_t pfsd_mount_shared_infos[DEFAULT_MAX_HOSTS + 1];

static void __attribute__((constructor))
init_pfsd_mount_shared_infos()
{
	int i;
	pfsd_mount_shared_info_t *info;

	for (i = 0; i < DEFAULT_MAX_HOSTS + 1; i++) {
		info = &pfsd_mount_shared_infos[i];
		info->ms_ref_count = 0;
		info->ms_is_rwmnt = false;
	}

}

static inline bool
pfs_need_demote_paxos(pfs_mount_t *mnt, int umount_host_id)
{
	return false;
}

static inline bool
pfs_need_promote_rw(pfs_mount_t *mnt, int new_flags)
{
	return ((new_flags & MNTFLG_WR) != 0 &&
	    (mnt->mnt_flags & MNTFLG_WR) == 0);
}

static int
pfs_host_incref(int host_id, int flags)
{
	int *hostid_ref_count = &pfsd_mount_shared_infos[host_id].ms_ref_count;
	if ((flags & MNTFLG_WR) != 0) {
		if(*hostid_ref_count != 0) {
			pfs_etrace("Repeat rw mount with same hostid: "
	                    "host_id:%d, flags:%d, refcnt: %d\n", host_id,
	                    flags, *hostid_ref_count);
			return -1;
		}
		++pfsd_mnt_wrref_count;
		pfsd_mount_shared_infos[host_id].ms_is_rwmnt = true;
	} else if (*hostid_ref_count != 0) {
        if (pfsd_mount_shared_infos[host_id].ms_is_rwmnt) {
			pfs_etrace("Repeat ro mount on rw mount with same hostid: "
	                    "host_id:%d, flags:%d, refcnt: %d\n", host_id,
	                    flags, *hostid_ref_count);
			errno = EACCES;
            return -1;
		}
	}
	++*hostid_ref_count;
	++pfsd_mnt_ref_count;
	return 0;
}

static int
pfs_host_decref(int host_id)
{
	int *hostid_ref_count = &pfsd_mount_shared_infos[host_id].ms_ref_count;
	if (*hostid_ref_count <= 0) {
		pfs_etrace("cannot find host_id %d\n", host_id);
		return -1;
	}
	--*hostid_ref_count;
	if (pfsd_mount_shared_infos[host_id].ms_is_rwmnt) {
		PFS_ASSERT(*hostid_ref_count == 0);
		--pfsd_mnt_wrref_count;
		pfsd_mount_shared_infos[host_id].ms_is_rwmnt = false;
	}
	--pfsd_mnt_ref_count;
	return 0;
}

static int
pfs_host_promot_ref(int host_id)
{
	int *hostid_ref_count = &pfsd_mount_shared_infos[host_id].ms_ref_count;
	if (*hostid_ref_count <= 0) {
		pfs_etrace("cannot find host_id %d\n", host_id);
		return -1;
	}

	if (pfsd_mount_shared_infos[host_id].ms_is_rwmnt || *hostid_ref_count
	    != 1) {
		pfs_etrace("we can not reset the hostid ref: hostid[%d], "
		     "refcount[%d]\n", host_id, *hostid_ref_count);
		return -1;
	}
	pfsd_mount_shared_infos[host_id].ms_is_rwmnt = true;
	++pfsd_mnt_wrref_count;
	return 0;
}

static int
pfs_host_depromot_ref(int host_id)
{
	int *hostid_ref_count = &pfsd_mount_shared_infos[host_id].ms_ref_count;
	if (*hostid_ref_count <= 0) {
		pfs_etrace("cannot find host_id %d\n", host_id);
		return -1;
	}

	if ((!pfsd_mount_shared_infos[host_id].ms_is_rwmnt) ||
	    *hostid_ref_count != 1) {
		pfs_etrace("we can not reset the hostid ref: hostid[%d], "
			   "refcount[%d]\n", host_id, *hostid_ref_count);
		return -1;
	}
	pfsd_mount_shared_infos[host_id].ms_is_rwmnt = false;
	--pfsd_mnt_wrref_count;
	return 0;
}

static int
pfs_host_get_another_id()
{
	for (int i = 1; i < DEFAULT_MAX_HOSTS + 1; ++i) {
		if (pfsd_mount_shared_infos[i].ms_ref_count > 0) {
			return i;
		}
	}
	return  -1;
}

static int
pfs_host_get_another_wrid()
{
	for (int i = 1; i < DEFAULT_MAX_HOSTS + 1; ++i) {
		if(pfsd_mount_shared_infos[i].ms_is_rwmnt) {
			PFS_ASSERT(pfsd_mount_shared_infos[i].ms_ref_count == 1);
			return i;
		}
	}
	return -1;
}

int
pfs_mount_acquire(const char *cluster, const char *pbdname, int host_id,
    int flags)
{
	int ret = 0;
	pfs_mount_t *mnt = NULL;

	pfs_itrace("before mount_acquire, PBD(%s), hostid(%d), flags(0x%x)\n",
	    pbdname, host_id, flags);
	if (host_id > DEFAULT_MAX_HOSTS) {
		errno = EINVAL;
		return -1;
	}
	//We do not support pfs tool flag. All the IO will be sent to
	// slot 0.
	flags &= (~MNTFLG_TOOL);
	flags |= MNTFLG_PFSD;

	mutex_lock(&pfsd_mnt_shared_info_lock);
	mnt = pfs_get_mount(pbdname);
	while (mnt == NULL) {

		ret = pfs_mount(cluster, pbdname, host_id, flags);
		if(ret != 0 && errno != EEXIST) {
			mutex_unlock(&pfsd_mnt_shared_info_lock);
			pfs_etrace("pfs_mount failed (%s) %d\n", pbdname, errno);
			return ret;
		}
		mnt = pfs_get_mount(pbdname);
	}
	if (host_id == 0) {
		host_id = mnt->mnt_num_hosts;
		pfs_itrace("real mount_acquire, PBD(%s), hostid(%d)\n",
		    pbdname, host_id);
	}
	if (pfs_host_incref(host_id, flags) != 0) {
		pfs_etrace("pfs_mount host_incref failed for %d\n", host_id);
		mutex_unlock(&pfsd_mnt_shared_info_lock);
		pfs_put_mount(mnt);
		errno = EINVAL;
		return -1;
	}

	if (pfs_need_promote_rw(mnt, flags)) {
		//Now we get mount, but the flag is not matched
		pfs_put_mount(mnt);

		ret = pfs_remount_rw(pbdname, host_id, flags);
		if (ret != 0) {
			pfs_etrace("pfs_remount_rw failed %s for host %d, %s\n", pbdname, host_id, strerror(errno));
			pfs_host_decref(host_id);
			//This must not be the first mount. So we do not need
			//umount.
		}
	}
	else {
		pfs_put_mount(mnt);
	}
	//PAXOS_BYFORCE promote is not needed. In fact it is illegal operation.
	//else if(pfs_need_promote_paxos(mnt, flags)) {
	mutex_unlock(&pfsd_mnt_shared_info_lock);
	pfs_itrace("after pfs_mount_acquire %d, errno %d\n", ret, errno);
	return ret;
}

int
pfs_mount_release(const char *pbdname, int host_id)
{
	pfs_mount_t *mnt = NULL;
	mountentry_t *me = NULL;
	int next_host_id = -1;
	bool umount_needed = false;
	int rv = 0;

	pfs_itrace("before mount_release, PBD(%s), hostid(%d)\n",
	    pbdname, host_id);
	if (host_id > DEFAULT_MAX_HOSTS) {
		errno = EINVAL;
		return -1;
	}
	mutex_lock(&pfsd_mnt_shared_info_lock);
	me = mountentry_find_iter(mountentry_hasname, pbdname, RW_WRLOCK);
	if (me == NULL) {
		pfs_etrace("cannot find PBD %s\n", pbdname);
		mutex_unlock(&pfsd_mnt_shared_info_lock);
		errno = EINVAL;
		return -1;
	}

	mnt = me->me_mount;
	PFS_ASSERT(mnt != NULL);
	if (host_id == 0) {
		host_id = mnt->mnt_num_hosts;
		pfs_itrace("real mount_release, PBD(%s), hostid(%d)\n",
		    pbdname, host_id);
	}
	if (pfs_host_decref(host_id) != 0) {
		mountentry_unlock(me);
		mutex_unlock(&pfsd_mnt_shared_info_lock);
		pfs_etrace("mount_release failed, PBD(%s), hostid(%d)\n",
		    pbdname, host_id);
		errno = EINVAL;
		return -1;
	}

	if (pfsd_mnt_wrref_count != 0) {
		if (mnt->mnt_host_id == (uint32_t)host_id) {
			next_host_id = pfs_host_get_another_wrid();
			PFS_ASSERT(next_host_id > 0);
			pfs_itrace("Now we change to hostid:%d \n",
			    next_host_id);
			do {
				rv = pfs_log_request_impl(&mnt->mnt_log,
				    LOG_TRY_RESET_LOCK, NULL, NULL, host_id,
				    next_host_id);
			} while (rv == ETIMEDOUT || rv == EAGAIN);
		}
	} else if (pfsd_mnt_ref_count != 0) {
		if (mnt->mnt_host_id == (uint32_t)host_id) {
			next_host_id = pfs_host_get_another_id();
			PFS_ASSERT(next_host_id > 0);
			pfs_itrace("Now we change to hostid:%d for ro mount \n",
			    next_host_id);
			//It is safe until rw operation is not enabled in pfsadm.
			pfs_remount_ro(mnt, next_host_id);
		}
	}
	else {
		pfs_itrace("Now no available hostid left, we are going to "
		    "umount \n");
		umount_needed = true;

	}
	mountentry_unlock(me);
	//Maybe it does not need umount now... so thread safe depends on
	//mnt_shared_info_lock.
	if (umount_needed) {
		rv = pfs_umount(pbdname);
		if(rv < 0) {
			pfs_etrace("Umount failed, we can restart safely! \n");
			exit(EIO);
		}
	}
	mutex_unlock(&pfsd_mnt_shared_info_lock);
	return 0;
}

int
pfs_remount(const char *cluster, const char *pbdname, int host_id, int flags)
{
	int ret = 0;
	pfs_mount_t *mnt;
	mountentry_t *me;

	if (cluster == NULL)
		cluster = CL_DEFAULT;
	if (pbdname == NULL) {
		pfs_etrace("invalid cluster(%s) or pbdname(%s)\n",
		    cluster ? cluster : "NULL", pbdname ? pbdname : "NULL");
		errno = EINVAL;
		return -1;
	}
	pfs_itrace("remount cluster(%s), PBD(%s), hostid(%d),flags(0x%x)\n",
	    cluster, pbdname, host_id, flags);
	if ((flags & MNTFLG_TOOL) != 0 || (flags & MNTFLG_LOG) == 0 ||
	   (flags & MNTFLG_WR) == 0) {
		pfs_etrace("invalid or unsupported flags(0x%x)\n", flags);
		errno = EINVAL;
		return -1;
	}
	if (host_id <= 0) {
		pfs_etrace("invalid host_id(%d)\n", host_id);
		errno = EINVAL;
		return -1;
	}

	flags |= MNTFLG_PFSD;

	mutex_lock(&pfsd_mnt_shared_info_lock);
	me = mountentry_find_iter(mountentry_hasname, pbdname, RW_WRLOCK);
	if (me == NULL) {
		pfs_etrace("cannot find PBD %s\n", pbdname);
		mutex_unlock(&pfsd_mnt_shared_info_lock);
		errno = EINVAL;
		return -1;
	}
	mnt = me->me_mount;
	if (pfs_host_promot_ref(host_id) != 0) {
		pfs_etrace("It can not remount to rw, host_id(%d)\n ",
		    host_id);
		mountentry_unlock(me);
		mutex_unlock(&pfsd_mnt_shared_info_lock);
		errno = EINVAL;
		return  -1;
	}

	if (!pfs_need_promote_rw(mnt, flags)) {
		pfs_etrace("It does not need remount to rw, flags(0x%x), but"
		    " this is not an error \n ", mnt->mnt_flags);
		mountentry_unlock(me);
		mutex_unlock(&pfsd_mnt_shared_info_lock);
		return 0;
	}
	mountentry_unlock(me);

	ret = pfs_remount_rw(pbdname, host_id, flags);
	if (ret < 0) {
		pfs_host_depromot_ref(host_id);
		errno = -ret;
	}
	mutex_unlock(&pfsd_mnt_shared_info_lock);

	return ret;
}

static void*
pfs_mntstat_thread_entry(void *arg)
{
	int err;
	pfs_mount_t *mnt = (pfs_mount_t *)arg;
	struct timespec ts;
	struct timeval now;

	pfs_wait_inited(mnt);
	if (pfs_init_failed(mnt))
		return NULL;
	pfs_itrace("Stat cleanup thread starts, interval = 1\n");
	err = 0;
	for (;;) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;
		err = 0;
		mutex_lock(&mnt->mnt_stat_mtx);
		while (err == 0 && !mnt->mnt_stat_stop)
			err = pthread_cond_timedwait(&mnt->mnt_stat_cond,
			    &mnt->mnt_stat_mtx, &ts);
		mutex_unlock(&mnt->mnt_stat_mtx);

		if (mnt->mnt_stat_stop)
			break;

		if (err && err != ETIMEDOUT) {
			pfs_etrace("Stat cleanup thread wait error %d, %s\n",
			    err, strerror(err));
			continue;
		}
		//No matter whether pfs_mntstat_enable is true or false we need
		//clean to avoid see old data.
		gettimeofday(&now, NULL);
		pfs_mntstat_sync(&now);
		pfs_mntstat_reinit(&now);
	}
	pfs_itrace("stat cleanup thread stops\n");
	return NULL;
}


static int
pfs_mntstat_start(pfs_mount_t *mnt)
{
	int err;
	pfs_mntstat_init();
	err = pthread_create(&mnt->mnt_stat_tid, NULL, pfs_mntstat_thread_entry,
	    mnt);
	if (err) {
		mnt->mnt_stat_tid = 0;
		pfs_etrace("cant create stat thread: %d, %s\n",
		    err, strerror(err));
		return -err;
	}
	return 0;
}

static void
pfs_mntstat_stop(pfs_mount_t *mnt)
{
	int rv;
	if (mnt->mnt_stat_tid) {
		mutex_lock(&mnt->mnt_stat_mtx);
		mnt->mnt_stat_stop = true;
		cond_signal(&mnt->mnt_stat_cond);
		mutex_unlock(&mnt->mnt_stat_mtx);

		rv = pthread_join(mnt->mnt_stat_tid, NULL);
		PFS_VERIFY(rv == 0);
		mnt->mnt_stat_tid = 0;
	}
}
