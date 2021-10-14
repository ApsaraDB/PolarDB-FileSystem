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

#include <assert.h>
#include <errno.h>
#include <search.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "pfs_devio.h"
#include "pfs_dir.h"
#include "pfs_file.h"
#include "pfs_impl.h"
#include "pfs_log.h"
#include "pfs_mount.h"
#include "pfs_option.h"
#include "pfs_tls.h"
#include "pfs_trace.h"
#include "pfs_tx.h"
#include "pfs_stat.h"
/*
 * PFS log is for two purposes. First, it is to ensure the atomicity
 * of changing meta data of one PFS instance; Second, it is the way to
 * sync the meta data among different PFS instances. For simplicity of
 * serializing log IO by multiple file IO threads, especially when
 * replaying new log entries, a seperate log thread is created to
 * serve log IO, rather than file IO threads contending a log mutex
 * and doing IO directly by themselves.
 *
 * Atomical meta data change is achieved in the following way: when
 * writing PFS log, log data is appended first, and then the log
 * header is written. Writing a log header is an atomic 4K size IO,
 * which is guaranteed by BSR.
 *
 * Each PFS instance records its change of meta data in log. When it
 * is to write log, a PFS instance should check the log header whether
 * other instances have already written new log entries. If so, its
 * logging of meta data change is canceled: all its changes to meta
 * data are rolled back, new log entries are replayed onto meta data
 * for syncing and the modification operation is tried again.
 *
 * For each read operation, a PFS instance polls and replays new log
 * entries first, to ensure that meta data is synced among PFS
 * instances. After that, actual file IO is carried out.
 *
 * It is a little complicate when replaying new log entries, since
 * there are multiple file IO threads each requesting a tx for log IO.
 * To coordinate these file IO threads, the log thread will create a
 * replay tx and put it at the head of work queue. The replay tx is to
 * hold new log entries found by the log thread. Meanwhile, the replay
 * tx is embedded into the first tx request from file IO threads with
 * other tx requests linked onto the first one as wait peers. The
 * first tx is signaled and its thread continues running. The thread
 * checks if its tx contains a replay tx. If so, it runs the replay
 * tx, singals wait peer tx and at last notifies the log thread. The
 * log thread polls the replay tx until it is done. Only then will the
 * log thread continues its handling of pending tx requests.
 */

/*
 * The offset should be in the range [0, modulus)
 */
#define	OFF_MODULAR_ADD(offset, len, modulus) do {	\
	offset += len;					\
	if (offset >= modulus)				\
		offset -= modulus;			\
} while(0)

/*
 * The length should be in the range (0, modulus]
 */
#define	LEN_MODULAR_CUT(len, offset, modulus) do {	\
	if (len + offset > modulus)			\
		len = modulus - offset;			\
} while(0)

/* log flags */
enum {
	LOGF_REPLAY_WAIT	= 0x0001,
	LOGF_SPACE_NEEDED	= 0x0002,
	LOGF_TRIM_FORCED	= 0x0004,
};

/* log states */
enum {
	LOGST_NOTLOADED	= 0,
	LOGST_SERVING,
	LOGST_SUSPENDED,
	LOGST_STOP,
};

/* handle request command */
enum {
	LOG_IO_STOP 	= 0,
	LOG_IO_CONT,
	LOG_IO_BACK,
};

void	pfs_log_replaytx_put(pfs_log_t *log, struct tx_qhead *otxq, bool trim);
void 	pfs_log_reply_queue(pfs_log_t *log, struct req_qhead *reqhead, int rv);
void 	pfs_log_reply(pfs_log_t *log, log_req_t *req, int rv);

static int pfs_log_handle_load(pfs_log_t *log, struct req_qhead *work_req);
static int pfs_log_handle_poll(pfs_log_t *log, struct req_qhead *work_req);
static int pfs_log_handle_try_reset_lock(pfs_log_t *log,
    struct req_qhead *work_req);
static int pfs_log_handle_write(pfs_log_t *log, struct req_qhead *work_req);
static int pfs_log_handle_trim(pfs_log_t *log, struct req_qhead *work_req);
static int pfs_log_handle_flush(pfs_log_t *log, struct req_qhead *work_req);
static int pfs_log_handle_replaydone(pfs_log_t *log, struct req_qhead *work_req);
static int pfs_log_handle_stop(pfs_log_t *log, struct req_qhead *work_req);
static int pfs_log_handle_suspend(pfs_log_t *log, struct req_qhead *work_req);
static int pfs_log_handle_resume(pfs_log_t *log, struct req_qhead *work_req);

typedef struct log_req_handler {
	const char	*hdl_name;
	bool		hdl_needpaxos;
	int		(*hdl_func)(pfs_log_t *, struct req_qhead *);
} log_req_handler_t;

/*
 * (1)LOAD is 1:
 * LOAD is the first request after log thread starts.
 * (2)REPLAYDONE is 2:
 * If log state is LOG_REPLAY_WAIT, other kind requests cant be handled.
 * (3)TRIM < WRITE:
 * If there are no space for write tx, WRITE sends a TRIM and
 * step back to TRIM index.
 * (4)TRIM < FLUSH:
 * FLUSH means trim forcedly, it sends a TRIM and step back to TRIM index.
 * (5)POLL < WRITE:
 * If new entries exist, WRITE needs a paxos lock,
 * so let POLL handled before WRITE.
 */
static log_req_handler_t log_req_handlers[] = {
	{ "MERGED", 	false,	NULL },
	{ "LOAD", 	false,	pfs_log_handle_load },
	{ "REPLAYDONE",	false,	pfs_log_handle_replaydone },
	{ "TRIM", 	true, 	pfs_log_handle_trim },
	{ "POLL", 	false,	pfs_log_handle_poll },
	{ "TRY_RESET_LOCK", false, pfs_log_handle_try_reset_lock },
	{ "WRITE", 	true, 	pfs_log_handle_write },
	{ "FLUSH", 	true, 	pfs_log_handle_flush },
	{ "SUSPEND", 	false,	pfs_log_handle_suspend },
	{ "RESUME", 	false,	pfs_log_handle_resume },
	{ "STOP", 	false,	pfs_log_handle_stop },
	{ "INVALID", 	false,	NULL },
};

#define	LOG_BIT_LOAD	(1 << LOG_LOAD)
#define	LOG_BIT_POLL	(1 << LOG_POLL)
#define LOG_BIT_TRY_RESET_LOCK (1 << LOG_TRY_RESET_LOCK)
#define	LOG_BIT_WRITE	(1 << LOG_WRITE)
#define	LOG_BIT_TRIM	(1 << LOG_TRIM)
#define	LOG_BIT_SUSPEND	(1 << LOG_SUSPEND)
#define	LOG_BIT_RESUME	(1 << LOG_RESUME)
#define	LOG_BIT_STOP	(1 << LOG_STOP)
#define	LOG_BIT_FLUSH	(1 << LOG_FLUSH)
#define	LOG_BIT_REPLAYDONE (1 << LOG_REPLAYDONE)

/*
 * trimgroup_nsect_threshold: the memory threshold of workgrp.
 * Note: memory of trimgrp isn't in statistics, the max
 * whole memory maybe double.
 *
 * trimgroup_ntx_threshold: the tx threshold of workgrp.
 * Note: Its value can't be too small, because RO needs a
 * log buffer to catch up with RW.
 */
/* memory threshold, 128MB */
static int64_t trimgroup_nsect_threshold = 32768;
PFS_OPTION_REG(trimgroup_nsect_threshold, pfs_check_ival_normal);

/* ntx threshold */
static int64_t trimgroup_ntx_threshold = 20000;
PFS_OPTION_REG(trimgroup_ntx_threshold, pfs_check_ival_normal);

/* ntx threshold (hard), upper bound of trimgroups */
static int64_t trimgroup_ntx_threshold_hard = 40000 - 1;
PFS_OPTION_REG(trimgroup_ntx_threshold_hard, pfs_check_ival_normal);

/* trim interval(unit:second) */
static int64_t log_trim_interval = 10;
PFS_OPTION_REG(log_trim_interval, pfs_check_ival_normal);

/* log thread swap in pages max one time.
 * 2562 is the max dirty pages count for truncate 10GB tx.
 */
static int64_t trimgroup_nsects_swapinmax = 2562;
PFS_OPTION_REG(trimgroup_nsects_swapinmax, pfs_check_ival_normal);

/*
 * At least, the log thread should wake up every second to
 * update its paxos lease.
 */
static int64_t log_paxos_lease = 1;
PFS_OPTION_REG(log_paxos_lease, pfs_check_ival_normal);

/* look one logentry ahead of journal's head as skip-poll flag */
static int64_t log_skip_journal_probe = 1;
PFS_OPTION_REG(log_skip_journal_probe, pfs_check_ival_normal);

static int
node_cmp(const void *fst, const void *snd)
{
	const pfs_sectbuf_t *sb1 = (const pfs_sectbuf_t *)fst;
	const pfs_sectbuf_t *sb2 = (const pfs_sectbuf_t *)snd;

	if (sb1->s_bda < sb2->s_bda)
		return -1;
	if (sb1->s_bda > sb2->s_bda)
		return 1;
	return 0;
}

static void
node_free(void *nodep)
{
	/*
	 * sectbuf's resources are managed by g_sects.
	 * g_rootp is only an index for searching.
	 */
}

static void
pfs_trimgroup_init(pfs_trimgroup_t *grp)
{
	memset(grp, 0, sizeof(*grp));
	grp->g_ltxid = grp->g_rtxid = 0;
	grp->g_roffset = 0;
	grp->g_nsects = 0;
	grp->g_nsects_empty = 0;
	grp->g_sect_empty_first = NULL;
	TAILQ_INIT(&grp->g_sects);
	grp->g_rootp = NULL;
}

static void
pfs_trimgroup_fini(pfs_trimgroup_t *grp)
{
	pfs_sectbuf_t *sb;

	while ((sb = TAILQ_FIRST(&grp->g_sects)) != NULL) {
		TAILQ_REMOVE(&grp->g_sects, sb, s_next);
		pfs_sectbuf_put(sb);
	}
	grp->g_ltxid = grp->g_rtxid = 0;
	grp->g_roffset = 0;
	grp->g_nsects = 0;
	grp->g_nsects_empty = 0;
	grp->g_sect_empty_first = NULL;
	tdestroy(grp->g_rootp, node_free);
	grp->g_rootp = NULL;
}

static inline int
pfs_trimgroup_nsectors(pfs_trimgroup_t *grp)
{
	return grp->g_nsects;
}

static int
pfs_trimgroup_ntx(pfs_trimgroup_t *grp)
{
	return grp->g_rtxid - grp->g_ltxid;
}

static void
pfs_trimgroup_dump(pfs_trimgroup_t *grp)
{
	pfs_itrace("txgroup %p (%ld, %ld], nsects=%ld, roffset=%lu\n", grp,
	    grp->g_ltxid, grp->g_rtxid, grp->g_nsects, grp->g_roffset);
}

static int
pfs_trimgroup_insert(pfs_trimgroup_t *grp, pfs_txid_t txid, uint64_t logused,
    struct txop_qhead *opsq, uint64_t logsize)
{
	pfs_sectbuf_t **nodep;
	pfs_txop_t *top;
	pfs_sectbuf_t *sb = NULL;
	PFS_ASSERT(txid == grp->g_rtxid + 1);
	TAILQ_FOREACH(top, opsq, top_next) {
		if (sb == NULL)
			sb = pfs_sectbuf_get();
		PFS_ASSERT(sb);
		pfs_sectbuf_bind(sb, top);
		nodep = (pfs_sectbuf_t **)tsearch(sb, &grp->g_rootp, node_cmp);
		if (nodep == NULL) {
			pfs_etrace("tsearch tx %ld sectbuf bda %lu failed\n",
			    txid, sb->s_bda);
			PFS_ASSERT("tsearch internal error" == NULL);
		}

		if (*nodep != sb) {
			pfs_sectbuf_t *sb2 = *nodep;
			PFS_ASSERT(sb2->s_txid <= sb->s_txid);
			sb2->s_txid = txid;
			pfs_sectbuf_sync(sb2, top);
			PFS_ASSERT(grp->g_sect_empty_first != NULL ||
			    sb2->s_buf);
			/**
			 * Here we set g_sect_empty_first at next sect_buf.
			 */
			if (grp->g_sect_empty_first == sb2 &&
			    TAILQ_NEXT(sb2, s_next) != NULL)
				grp->g_sect_empty_first
				    = TAILQ_NEXT(sb2, s_next);
			/*
			 * Move existed sectbuf to tail, keep g_sects in
			 * non-descending order according to txid.
			 */
			TAILQ_REMOVE(&grp->g_sects, sb2, s_next);
			TAILQ_INSERT_TAIL(&grp->g_sects, sb2, s_next);
		} else {
			grp->g_nsects++;
			TAILQ_INSERT_TAIL(&grp->g_sects, sb, s_next);
			if (grp->g_nsects_empty == 0) {
				PFS_ASSERT(!grp->g_sect_empty_first);
				grp->g_sect_empty_first = sb;
			}
			sb = NULL;
			++grp->g_nsects_empty;
		}
	}
	if(sb)
		pfs_sectbuf_put(sb);
	grp->g_rtxid = txid;
	OFF_MODULAR_ADD(grp->g_roffset, logused, logsize);
	return 0;
}

static void
pfs_trimgroup_delete(pfs_trimgroup_t *grp, pfs_txid_t to_txid)
{
	pfs_sectbuf_t *sb;

	/*
	 * If to_txid is less than grp->g_ltxid, we should return.
	 * Otherwise grp->g_ltxid would be updated to to_txid
	 * and that is wrong.
	 */
	if (to_txid <= grp->g_ltxid)
		return;

	while ((sb = TAILQ_FIRST(&grp->g_sects)) != NULL &&
	       sb->s_txid <= to_txid) {
		/*
		 * sectbufs in a trimgroup is in non-descending order
		 * according to txid.
		 */
		TAILQ_REMOVE(&grp->g_sects, sb, s_next);
		tdelete(sb, &grp->g_rootp, node_cmp);
		if (!sb->s_buf)
			--grp->g_nsects_empty;
		if (sb == grp->g_sect_empty_first)
			grp->g_sect_empty_first = TAILQ_FIRST(&grp->g_sects);
		pfs_sectbuf_put(sb);
		grp->g_nsects--;
	}
	grp->g_ltxid = MIN(to_txid, grp->g_rtxid);
}

static int
pfs_trimgroup_flush(pfs_trimgroup_t *grp, int iodesc, pfs_txid_t *tail_txid,
    size_t *tail_offset)
{
	pfs_sectbuf_t *sb;
	int rv, n;

	n = 0;
	TAILQ_FOREACH(sb, &grp->g_sects, s_next) {
		PFS_ASSERT(sb->s_txid > grp->g_ltxid && sb->s_txid <= grp->g_rtxid);
		rv = pfsdev_pwrite(iodesc, sb->s_buf, PBD_SECTOR_SIZE, sb->s_bda);
		if (rv < 0) {
			pfs_etrace("trim log failed bda @%lld rv=%d\n",
			    sb->s_bda, rv);
			return rv;
		}
		n++;
	}
	if (n > 0) {
		*tail_txid = grp->g_rtxid;
		*tail_offset = grp->g_roffset;
	}
	return n;
}

static int64_t
pfs_log_tryswap_trimgroup(pfs_log_t *log, bool force, int handle_type)
{
	pfs_trimgroup_t *orig_workgrp = log->log_workgrp;
	pfs_sectbuf_t *sb = orig_workgrp->g_sect_empty_first;
	int64_t nswapin = orig_workgrp->g_nsects_empty;
	int64_t ntx_threshold = trimgroup_ntx_threshold;
	bool over_threshold = pfs_trimgroup_ntx(orig_workgrp) >= ntx_threshold
	    || pfs_trimgroup_nsectors(orig_workgrp) >= trimgroup_nsect_threshold;

	//RO does not generate dirty pages.
	if (!pfs_writable(log->log_mount))
		return -nswapin;

	//All the dirty pages have been generated.
	if (nswapin == 0)
		goto direct_swap;

	//Try to avoid tx_write/tx_replay lead to swap.
	if (!force &&
	    (handle_type == LOG_WRITE || handle_type == LOG_REPLAYDONE) &&
	    !over_threshold)
		return -nswapin;

	PFS_ASSERT(sb);

	//We do not need to lock during LOG_WRITE handling.
	if (handle_type != LOG_WRITE && !MOUNT_META_TRYRDLOCK(log->log_mount)) {
		if (over_threshold)
			pfs_dbgtrace("%ld sects left for swapping but meta lock"
			    " failed!\n", nswapin);
		return -nswapin;
	}

	if (!force && !over_threshold)
		nswapin = trimgroup_nsects_swapinmax;
	else if (nswapin > trimgroup_nsects_swapinmax)
		pfs_itrace("%ld sects will be swapped one time!\n", nswapin);

	while (sb) {
		if (sb->s_buf == NULL) {
			sb->s_buf = (char *)pfs_mem_malloc(PBD_SECTOR_SIZE,
			    M_SECTBUF);
			PFS_ASSERT(sb->s_buf != NULL);
			memcpy(sb->s_buf, sb->s_metabuf, PBD_SECTOR_SIZE);
			--nswapin;
			--orig_workgrp->g_nsects_empty;
			if (orig_workgrp->g_nsects_empty == 0)
				break;
			if (nswapin == 0) {
				sb = TAILQ_NEXT(sb, s_next);
				break;
			}
		}
		sb = TAILQ_NEXT(sb, s_next);
	}

	if (handle_type != LOG_WRITE)
		MOUNT_META_UNLOCK(log->log_mount);
	if (orig_workgrp->g_nsects_empty != 0) {
		PFS_ASSERT(sb);
		orig_workgrp->g_sect_empty_first = sb;
		pfs_dbgtrace("%ld sects left for swapping\n",
		    orig_workgrp->g_nsects_empty);
		return orig_workgrp->g_nsects_empty;
	}
	orig_workgrp->g_sect_empty_first = NULL;

direct_swap:
	if (pfs_trimgroup_ntx(log->log_waitgrp) > 0)
		return 0;
	if (!force &&
	    pfs_trimgroup_nsectors(orig_workgrp) < trimgroup_nsect_threshold &&
	    pfs_trimgroup_ntx(orig_workgrp) < trimgroup_ntx_threshold)
		return 0;

	pfs_trimgroup_dump(log->log_workgrp);
	pfs_trimgroup_dump(log->log_waitgrp);
	log->log_workgrp = log->log_waitgrp;
	log->log_waitgrp = orig_workgrp;

	/* waitgrp and workgrp must be continuous. */
	log->log_workgrp->g_ltxid = orig_workgrp->g_rtxid;
	log->log_workgrp->g_rtxid = orig_workgrp->g_rtxid;
	log->log_workgrp->g_roffset = orig_workgrp->g_roffset;
	return 0;
}

static int
pfs_log_add_trimentry(pfs_log_t *log, pfs_txid_t txid, uint32_t txspace,
    struct txop_qhead *opsq)
{
	int err;

	/* new tx is always inserted into the tail of workgrp */
	err = pfs_trimgroup_insert(log->log_workgrp, txid, txspace, opsq,
	    log->log_leader.log_size);
	PFS_ASSERT(err == 0);

	return 0;
}

static void
pfs_log_del_trimentry(pfs_log_t *log, pfs_txid_t to_txid)
{
	pfs_trimgroup_delete(log->log_waitgrp, to_txid);
	pfs_trimgroup_delete(log->log_workgrp, to_txid);
}

static bool
pfs_log_paxos_expired(const pfs_log_t *log)
{
	struct timespec now;

	PFS_ASSERT(log->log_paxos_got == true);
	clock_gettime(CLOCK_REALTIME, &now);
	/* XXX: tv_nsec should be considered. */
	return now.tv_sec - log->log_paxos_ts.tv_sec >= log_paxos_lease;
}

static int
pfs_log_paxos_try_acquire(pfs_log_t *log, pfs_leader_record_t **latestp)
{
	int rv = 0;

	log->log_leader_latest = log->log_leader;
	*latestp = &log->log_leader_latest;
	return rv;
}

static int
pfs_log_paxos_try_release(pfs_log_t *log)
{
	return 0;
}

static int64_t
pfs_log_usedspace(uint64_t log_size, int64_t tail_offset, int64_t head_offset)
{
	int64_t used;

	used = head_offset - tail_offset;
	if (used < 0)
		used += log_size;
	PFS_ASSERT(used % sizeof(pfs_logentry_phy_t) == 0);
	return used;
}

/*
 * pfs_log_space:
 *
 * 	Calculate the space free for more logging.
 */
static size_t
pfs_log_space(pfs_log_t *log)
{
	pfs_leader_record_t *lr = &log->log_leader;
	int64_t used;

	used = pfs_log_usedspace(lr->log_size, lr->tail_offset, lr->head_offset);
	return lr->log_size - used;
}

static int
pfs_log_paxos_forward_leader(pfs_log_t *log, const char *caller)
{
	int rv;
	pfs_leader_record_t *lr = &log->log_leader;
	pfs_leader_record_t *lr_latest = &log->log_leader_latest;
	pfs_leader_record_t latest_bak = *lr_latest;

	/*
	 * log_leader's log anchor should move forwarder than
	 * cached leader.
	 */
	PFS_ASSERT(lr->tail_txid >= lr_latest->tail_txid);
	PFS_ASSERT(lr->head_txid >= lr_latest->head_txid &&
	    lr->head_lsn >= lr_latest->head_lsn);
	PFS_ASSERT(lr->tail_txid > lr_latest->tail_txid ||
	    (lr->head_txid > lr_latest->head_txid &&
	     lr->head_lsn > lr_latest->head_lsn));
	/*
	 * update log anchor of cached pfs_leader_record from log_leader
	 * while their paxos parts are same.
	 */
	lr_latest->tail_txid = lr->tail_txid;
	lr_latest->head_txid = lr->head_txid;
	lr_latest->tail_offset = lr->tail_offset;
	lr_latest->head_offset = lr->head_offset;
	lr_latest->log_size = lr->log_size;
	lr_latest->head_lsn = lr->head_lsn;
	PFS_ASSERT(memcmp(lr_latest, lr, sizeof(pfs_leader_record_t)) == 0);

	pfs_dbgtrace("%s write leader record: txid (%llu, %llu], "
	    "offset (%llu, %llu] lsn %llu\n", caller,
	    (unsigned long long)lr_latest->tail_txid,
	    (unsigned long long)lr_latest->head_txid,
	    (unsigned long long)lr_latest->tail_offset,
	    (unsigned long long)lr_latest->head_offset,
	    (unsigned long long)lr_latest->head_lsn);
	rv = pfs_leader_write(log->log_mount, lr_latest);
	if (rv < 0) {
		if (rv == PFS_AIO_TIMEOUT)
			rv = -ETIMEDOUT;
		/* recovery cached pfs_leader_record */
		*lr_latest = latest_bak;
	} else {
		PFS_ASSERT(rv == PFS_OK);
		rv = 0;	/* PFS_OK is positive */
	}

	return rv;
}

static inline bool
pfs_log_check_one(const pfs_logentry_phy_t *le)
{
	if (le->le_checksum != crc32c_compute(le, sizeof(*le),
	    offsetof(struct pfs_logentry_phy, le_checksum)))
		return false;
	return true;
}

static void
pfs_log_check(const pfs_logentry_phy_t *lebuf, uint32_t nle)
{
	const pfs_logentry_phy_t *le;

	for (le = lebuf; le - lebuf < nle; le++) {
		/* Skip old version log entry whose checksum is zero */
		if (le->le_checksum == 0)
			continue;

		if (!pfs_log_check_one(le)) {
			pfs_etrace("logentry %lld (txid %lld) checksum %u is invalid\n",
			    (long long)le->le_lsn, (long long)le->le_txid,
			    le->le_checksum);
			PFS_ASSERT("logentry crc error" == NULL);
			exit(EIO);
		}
	}
}

void
pfs_log_dump(pfs_logentry_phy_t *lebuf, uint32_t nle, int level)
{
	const pfs_logentry_phy_t *le;

	for (le = lebuf; le - lebuf < nle; le++) {
		DUMP_FIELD("%ld",	level, le, le_txid);
		DUMP_FIELD("%ld",	level, le, le_lsn);
		DUMP_FIELD("%lu",	level, le, le_sector_bda);
		DUMP_FIELD("%u",	level, le, le_obj_idx);
		DUMP_FIELD("%u",	level, le, le_checksum);
		if (pfs_log_check_one(le) == false)
			DUMP_VALUE("%s", level, (le_checksum_isvalid), "false");
		DUMP_FIELD("%d",	level, le, le_more);
		pfs_metaobj_dump(&le->le_obj_val, level+1);
	}
}

/*
 * pfs_log_read:
 *
 * 	Read log data in a circular way. There is no loop in read,
 * 	that is different from write, because in write we have to
 * 	write as much data as asked by caller, whereas in read, we
 * 	can read log data as much as possible, by our best effort.
 */
static ssize_t
pfs_log_read(pfs_log_t *log, char *buf, int len, size_t offset)
{
	pfs_file_t *logf = log->log_file;
	pfs_leader_record_t *lr = &log->log_leader;
	ssize_t readlen;
	int rv;

	OFF_MODULAR_ADD(offset, 0, lr->log_size);
	PFS_ASSERT(offset < lr->log_size);

	readlen = PFS_FRAG_SIZE - (offset & (PFS_FRAG_SIZE - 1));
	LEN_MODULAR_CUT(readlen, offset, lr->log_size);
	if (readlen > len)
		readlen = len;
	PFS_ASSERT((size_t)readlen >= sizeof(pfs_logentry_phy_t));

	rv = pfs_file_pread(logf, buf, readlen, offset);
	if (rv > 0) {
		PFS_ASSERT(rv % sizeof(pfs_logentry_phy_t) == 0);
		pfs_log_check((pfs_logentry_phy_t *)buf,
		    rv / sizeof(pfs_logentry_phy_t));
	}
	return rv;
}

/*
 * pfs_log_scan:
 *
 * 	Scan from the start txid upto stop txid, (start, stop].
 * 	Save the meta data change in @tx. @tx will either be
 * 	replayed into memory or committed onto PBD. After scan,
 * 	offset and txid will be updated by the caller, if necessary.
 *
 * 	return value is the length of scaned log entries.
 */
static int
pfs_log_scan(pfs_log_t *log, char *buf, ssize_t buflen, off_t start_offset,
    pfs_txid_t start_txid, pfs_txid_t stop_txid, log_req_t *req)
{
	pfs_leader_record_t *lr = &log->log_leader;
	struct tx_qhead *txhead = req->r_otxq;
	pfs_tx_t *tx;
	uint64_t offset;
	pfs_lsn_t last_lsn;
	pfs_txid_t last_txid;
	pfs_logentry_phy_t *le;
	pfs_txop_t *top;
	int nentry;
	int err;
	ssize_t readlen;

	pfs_dbgtrace("log scan tx range (%llu %llu] @ %llu\n",
	    (unsigned long long)start_txid,
	    (unsigned long long)stop_txid,
	    (unsigned long long)start_offset);

	offset = start_offset;
	PFS_ASSERT(offset < lr->log_size);

	/*
	 * If there is no tx missed, just return.
	 */
	if (start_txid == stop_txid)
		return 0;

	nentry = 0;
	tx = NULL;
	last_lsn = -1;
	last_txid = start_txid;
	le = (pfs_logentry_phy_t *)buf;
	readlen = 0;
	for (;;) {
		if ((char *)le - buf >= readlen) {
			PFS_ASSERT(offset < lr->log_size);
			OFF_MODULAR_ADD(offset, readlen, lr->log_size);
			readlen = pfs_log_read(log, buf, buflen, offset);
			if (readlen > 0) {
				le = (pfs_logentry_phy_t *)buf;
			} else {
				PFS_ASSERT("log scan internal error" == NULL);
				return -EIO;
			}
		}

		/*
		 * lsn of current le should be incremented by one.
		 * TODO: last_lsn should be provided as an argment.
		 *
		 * txid of current le should be nondecreasing and in the
		 * range of (start_txid, stop_txid]
		 */
		PFS_ASSERT(last_lsn < 0 || le->le_lsn - last_lsn == 1);
		PFS_ASSERT((int64_t)(le->le_txid - last_txid) == 0 ||
			   (int64_t)(le->le_txid - last_txid) == 1);
		PFS_ASSERT((int64_t)(le->le_txid - start_txid) > 0 &&
			   (int64_t)(le->le_txid - stop_txid) <= 0);

		/*
		 * Recreate txop for the entries in the range
		 * (start_txid, stop_txid]. If reach the latest txid
		 * and there is no more log entries, scan is terminated.
		 */
		if (tx == NULL || tx->t_id != le->le_txid) {
			pfs_tx_t *tmp = pfs_tx_get(log->log_mount, TXT_REPLAY, false);
			if (tmp == NULL) {
				req->r_error = -ENOSPC;
				return -1;
			}
			tmp->t_id = le->le_txid;
			tx = tmp;
			TAILQ_INSERT_TAIL(txhead, tx, t_next);
		}
		pfs_dbgtrace("log scan le %llu\n", le->le_lsn);
		top = NULL;
		err = pfs_tx_recreate_op(tx, le, top);
		if (err < 0)
			return err;
		nentry++;

		if ((pfs_txid_t)le->le_txid == stop_txid && !le->le_more) {
			pfs_dbgtrace("recreate txop upto tid %llu, lsn %llu "
			    "nle %llu\n",
			    (unsigned long long)le->le_txid,
			    (unsigned long long)le->le_lsn,
			    (unsigned long long)nentry);
			break;
		}

		last_lsn = le->le_lsn;
		last_txid = le->le_txid;
		/*
		 * Advance to next log entry. If the buf is exhausted,
		 * read new log entries into the buffer.
		 */
		le++;
	}

	return nentry * sizeof(pfs_logentry_phy_t);
}

static bool
pfs_log_need_trim(pfs_log_t *log)
{
	if (log->log_leader.tail_txid == log->log_leader.head_txid) {
		PFS_ASSERT(log->log_workgrp->g_ltxid == log->log_workgrp->g_rtxid);
		PFS_ASSERT(log->log_waitgrp->g_ltxid == log->log_waitgrp->g_rtxid);
		return false;
	}

	/*
	 * When workgrp is full and trimgrp isn't empty, then trimgrp
	 * can be flushed to superblocks.
	 */
	if ((pfs_trimgroup_nsectors(log->log_workgrp) >= trimgroup_nsect_threshold ||
	    pfs_trimgroup_ntx(log->log_workgrp) >= trimgroup_ntx_threshold) &&
	    log->log_waitgrp->g_ltxid < log->log_waitgrp->g_rtxid)
		return true;
	return false;
}

static bool
pfs_log_need_trim_hard(pfs_log_t *log)
{
	int64_t local_ntx_threshold_hard = trimgroup_ntx_threshold_hard;
	int64_t local_ntx_threshold = trimgroup_ntx_threshold;
	if (pfs_trimgroup_ntx(log->log_workgrp) >= local_ntx_threshold_hard) {
		pfs_itrace("Force trim needed! trimgroup_ntx:"
		    "%d >= trimgroup_ntx_threshold_hard:%ld.\n",
		    pfs_trimgroup_ntx(log->log_workgrp),
		    local_ntx_threshold_hard);
		PFS_ASSERT(local_ntx_threshold_hard > local_ntx_threshold);
		return true;
	}
	return false;
}

/*
 * pfs_log_trim
 *
 * 	Trim the log from the tail txid upto @trimto_txid.
 */
static int
pfs_log_trim(pfs_log_t *log)
{
	pfs_leader_record_t *lr = &log->log_leader;
	pfs_leader_record_t oldlr;
	size_t logspace = pfs_log_space(log);
	pfs_trimgroup_t *grp = log->log_waitgrp;
	int rv, nsects;
	pfs_txid_t tail_txid;
	uint64_t tail_offset;

	if (grp->g_ltxid == grp->g_rtxid)
		return 0;

	PFS_ASSERT((pfs_txid_t)lr->tail_txid == grp->g_ltxid &&
		   grp->g_rtxid == log->log_workgrp->g_ltxid);
	MNT_STAT_BEGIN();
	pfs_itrace("trim tx in (%llu, %llu] %zd/%zd\n",
	    (unsigned long long)grp->g_ltxid,
	    (unsigned long long)grp->g_rtxid,
	    logspace, lr->log_size);

	/* Flush sectors in trimgroup to superblocks. */
	tail_txid = -1;
	tail_offset = 0;
	nsects = pfs_trimgroup_flush(grp, log->log_mount->mnt_ioch_desc,
	    &tail_txid, &tail_offset);
	if (nsects <= 0)
		return nsects;

	oldlr = *lr;
	lr->tail_txid = tail_txid;
	lr->tail_offset = tail_offset;
	rv = pfs_log_paxos_forward_leader(log, "log_trim");
	if (rv < 0) {
		pfs_etrace("write paxos leader failed after trimming log: rv=%d\n", rv);
		*lr = oldlr;
		return rv;
	}

	/*
	 * ONLY after leader has been written, relevant sectbufs could be
	 * removed. Otherwise sectbufs in waitgrp are lost.
	 */
	pfs_log_del_trimentry(log, tail_txid);
	PFS_ASSERT(grp->g_ltxid == grp->g_rtxid);

	pfs_itrace("trimmed (%ld, %lu], offset %lu->%lu, nsects=%d\n",
	    oldlr.tail_txid, tail_txid, oldlr.tail_offset, tail_offset, nsects);
	MNT_STAT_END(MNT_STAT_JOURNAL_TRIM);
	return 0;
}

/*
 * pfs_log_write:
 *
 * 	Write meta data change to log file. If the log file has no enough
 * 	space for the data, trim the log.
 */
int
pfs_log_write(pfs_log_t *log, char *buf, size_t buflen, uint64_t offset)
{
	pfs_file_t *logf = log->log_file;
	pfs_leader_record_t *lr = &log->log_leader;
	int wlen;
	size_t left;

	PFS_ASSERT(buflen < pfs_log_space(log));

	/*
	 * The loop below is to handle circular write.
	 * If a new write exceeds log file size, the head offseet
	 * should be wrapped around
	 */
	OFF_MODULAR_ADD(offset, 0, lr->log_size);
	for (wlen = 0, left = buflen; left > 0; left -= wlen, buf += wlen) {
		wlen = left;
		LEN_MODULAR_CUT(wlen, offset, lr->log_size);

		wlen = pfs_file_pwrite(logf, buf, wlen, offset);
		if (wlen < 0)
		       return wlen;
		OFF_MODULAR_ADD(offset, wlen, lr->log_size);
	}

	return buflen;
}

static int
pfs_log_load(pfs_log_t *log, pfs_leader_record_t *latest, log_req_t *req)
{
	pfs_leader_record_t *lr = &log->log_leader;
	pfs_leader_record_t leader;
	int rv;

	if (latest == NULL) {
		latest = &leader;
		memset(latest, 0, sizeof(*latest));
		rv = pfs_leader_read(log->log_mount, latest);
		if (rv < 0) {
			pfs_etrace("Read paxos leader failed in TXT_LOG_LOAD, err=%d\n", rv);
			return rv;
		}
	}

	PFS_ASSERT(lr->tail_txid <= latest->tail_txid);
	PFS_ASSERT(lr->head_txid <= latest->head_txid);
	if (lr->tail_txid < latest->tail_txid)
		pfs_itrace("Journal tail moves from %llu to %llu, journal is"
		    " trimmed during mount\n",
		    (unsigned long long)lr->tail_txid,
		    (unsigned long long)latest->tail_txid);

	/*
	 * FIXME:
	 * Only when lr and latest have intersection of tx, journal load is allowed.
	 * Maybe we could do better.
	 */
	if (lr->head_txid < latest->tail_txid) {
		pfs_etrace("When loading journal, lr (%llu %llu] and latest (%llu %llu]"
		    " don't have any intersection\n",
		    (unsigned long long)lr->tail_txid,
		    (unsigned long long)lr->head_txid,
		    (unsigned long long)latest->tail_txid,
		    (unsigned long long)latest->head_txid);
		return -EAGAIN;
	}

	rv = pfs_log_scan(log, log->log_workbuf, log->log_workbufsz,
	    lr->tail_offset, lr->tail_txid, latest->head_txid, req);
	if (rv < 0)
		return rv;

	pfs_itrace("Leader before mount: (%llu %llu], latest: (%llu %llu], nle=%d\n",
	    (unsigned long long)lr->tail_txid,
	    (unsigned long long)lr->head_txid,
	    (unsigned long long)latest->tail_txid,
	    (unsigned long long)latest->head_txid,
	    rv / sizeof(pfs_logentry_phy_t));

	lr->tail_txid = latest->tail_txid;
	lr->tail_offset = latest->tail_offset;
	lr->head_txid = latest->head_txid;
	lr->head_offset = latest->head_offset;
	lr->head_lsn = latest->head_lsn;
	return rv;
}

/*
 * pfs_log_poll:
 *
 * 	Read leader record. If there is change of log in leader record,
 * 	read the log entries and apply them into local pfs.
 *
 * 	return value is the number of new log entries polled.
 */
static int
pfs_log_poll(pfs_log_t *log, const pfs_leader_record_t *latest, log_req_t *req)
{
	pfs_mount_t *mnt = log->log_mount;
	pfs_leader_record_t *lr = &log->log_leader;
	pfs_leader_record_t cur_lr;
	pfs_logentry_phy_t *le;
	ssize_t rv, rlen;

	if (latest == NULL) {
		if (log_skip_journal_probe != 1) {

		rlen = PBD_SECTOR_SIZE - (lr->head_offset & (PBD_SECTOR_SIZE-1));
		rv = rlen = pfs_log_read(log, log->log_workbuf, rlen, lr->head_offset);
		if (rv < 0)
			return rv;
		le = (pfs_logentry_phy_t *)log->log_workbuf;
		if ((int64_t)(le->le_txid - lr->head_txid) <= 0)
			return 0;	/* no new log entries appended */

		}

		memset(&cur_lr, 0, sizeof(cur_lr));
		rv = pfs_leader_read(mnt, &cur_lr);
		if (rv < 0)
			return rv;
		latest = &cur_lr;

		/*
		 * Discard previous read, which may be stale now, because when
		 * we are reading leader record, the read data may be changed
		 * again. After leader record is committed, the read data is
		 * stable.
		 */
		rlen = 0;
	} else
		rlen = 0;

	if ((int64_t)(lr->head_txid - latest->tail_txid) < 0) {
		/*
		 * This follower has missed some log entries. There
		 * is no way to know which updates are done. Have to
		 * reload all the meta data from the PBD.
		 *
		 * TODO:
		 * implement the reloading
		 */
		pfs_etrace("meta data need reloading, not implemented yet,"
		    "lr->head %llu, latest->tail_txid %llu\n",
		    (unsigned long long)lr->head_txid,
		    (unsigned long long)latest->tail_txid);
		PFS_ASSERT("meta data need reloading, not implemented yet" == NULL);
		exit(0xdd);
	}

	/*
	 * Note:
	 * If journal is trimmed, LOG_POLL CANNOT send a LOG_TRIM to free
	 * sectors in memory like what LOG_WRITE does. Because LOG_TRIM
	 * needs the paxos lock.
	 */
	if (lr->tail_txid < latest->tail_txid) {
		pfs_itrace("LOG_POLL: others have trimmed tx, local lr"
		    " (%llu, %llu], global lr (%llu, %llu]\n",
		    (unsigned long long)lr->tail_txid,
		    (unsigned long long)lr->head_txid,
		    (unsigned long long)latest->tail_txid,
		    (unsigned long long)latest->head_txid);
		pfs_log_del_trimentry(log, latest->tail_txid);
		lr->tail_txid = latest->tail_txid;
		lr->tail_offset = latest->tail_offset;
	}

	rlen = pfs_log_scan(log, log->log_workbuf, log->log_workbufsz,
	    lr->head_offset, lr->head_txid, latest->head_txid, req);
	if (rlen < 0)
		return rlen;

	pfs_dbgtrace("polled from (%llu %llu]'s head to (%llu %llu]'s head,"
	    " nle=%d\n",
	    (unsigned long long)lr->tail_txid,
	    (unsigned long long)lr->head_txid,
	    (unsigned long long)latest->tail_txid,
	    (unsigned long long)latest->head_txid,
	    rlen / sizeof(pfs_logentry_phy_t));

	lr->head_txid = latest->head_txid;
	lr->head_offset = latest->head_offset;
	lr->head_lsn = latest->head_lsn;
	return rlen;
}

static int
pfs_log_commit(pfs_log_t *log, pfs_tx_t *tx, pfs_leader_record_t *latest)
{
	pfs_leader_record_t lrbak = log->log_leader;
	pfs_leader_record_t *lr = &log->log_leader;
	int rv;

	if ((int64_t)(lr->head_txid - latest->head_txid) < 0) {
		/*
		 * TODO: more accurate comparison.
		 *
		 * Leader record is stale.
		 * Ask user to retry.
		 */
		return -EAGAIN;
	}

	/*
	 * First write the log data. After that, write the log anchor,
	 * that is leader record, which is an atomic IO.
	 */
	rv = pfs_tx_log(tx, lr->head_txid, lr->head_lsn, lr->head_offset,
	    log->log_workbuf, log->log_workbufsz);
	if (rv < 0) {
		pfs_etrace("tx log failed %d\n", rv);
		goto out;
	}
	lr->head_txid += 1;
	lr->head_lsn += rv / sizeof(pfs_logentry_phy_t);
	OFF_MODULAR_ADD(lr->head_offset, rv, lr->log_size);

	rv = pfs_log_paxos_forward_leader(log, "log_commit");
	if (rv < 0) {
		pfs_etrace("write paxos leader failed after log commit, rv=%d\n", rv);
		goto out;
	}

out:
	if (rv < 0) {
		/* recovery all changes of log->log_leader */
		*lr = lrbak;
	}
	return rv;
}

static int
pfs_log_handle_load(pfs_log_t *log, struct req_qhead *work_req)
{
        int rv;
	log_req_t *req;

	PFS_ASSERT(log->log_state == LOGST_NOTLOADED);
	PFS_ASSERT((log->log_flags & LOGF_REPLAY_WAIT) == 0);

	/* Only ONE LOG_LOAD could be received, remove it firstly. */
	req = TAILQ_FIRST(&work_req[LOG_LOAD]);
	TAILQ_REMOVE(&work_req[LOG_LOAD], req, r_next);
	PFS_ASSERT(TAILQ_EMPTY(&work_req[LOG_LOAD]) == true);

	rv = pfs_log_load(log, NULL, req);
	if (rv < 0) {
		pfs_etrace("LOG_LOAD failed, rv=%d\n", rv);
		pfs_log_reply(log, req, rv);
		return LOG_IO_STOP;
	}

	if (rv == 0) {
		/*
		 * No entries need to be loaded, log thread can serves
		 * immediately. This happens at only two cases:
		 * 1. startup after mkfs.
		 * 2. all journal entries are trimmed.
		 */
		PFS_ASSERT(log->log_leader.tail_txid == log->log_leader.head_txid);
		log->log_state = LOGST_SERVING;
		pfs_log_reply(log, req, 0);
		return LOG_IO_CONT;
	}

	log->log_flags |= LOGF_REPLAY_WAIT;
	pfs_log_reply(log, req, rv);
	return LOG_IO_CONT;
}

static int
pfs_log_handle_poll(pfs_log_t *log, struct req_qhead *work_req)
{
	pfs_leader_record_t *latest = NULL;
	int rv;
	log_req_t *req;

	PFS_ASSERT(log->log_state == LOGST_SERVING);
	/*
	 * We are waiting for replay to end.
	 * These LOG_POLL requests come after LOGF_REPLAY_WAIT state,
	 * they CANT be moved to work_req[LOG_REPLAY_WAIT].
	 * Leave them in work_req[LOG_POLL] and handle them
	 * until replay is done.
	 */
	if (log->log_flags & LOGF_REPLAY_WAIT)
		return LOG_IO_CONT;
	MNT_STAT_BEGIN();
	/*
	 * If log thread has got paxos lock, use cached log_leader
	 * directly to avoid unnecessary I/O.
	 */
	if (log->log_paxos_got && !pfs_log_paxos_expired(log)) {
		latest = &log->log_leader_latest;
	} else {
		latest = NULL;
	}

	req = TAILQ_FIRST(&work_req[LOG_POLL]);
	rv = pfs_log_poll(log, latest, req);
	MNT_STAT_END(MNT_STAT_JOURNAL_POLL);
	if (rv < 0) {
		/*
		 * Error occurs while polling. Notify all tx the unfortunate
		 * event.
		 */
		pfs_etrace("LOG_POLL failed, rv=%d\n", rv);
		pfs_log_reply_queue(log, &work_req[LOG_POLL], rv);
		return LOG_IO_STOP;
	}

	if (rv == 0) {
		/*
		 * No new log entries are polled, notify all the polling
		 * tx and fall through to continue.
		 */
		PFS_ASSERT(TAILQ_EMPTY(req->r_otxq) == true);
		pfs_log_reply_queue(log, &work_req[LOG_POLL], 0);
		return LOG_IO_CONT;
	}

	/*
	 * There are new log entries, which means there are
	 * changes by other nodes. Replay txs are delegated to
	 * a poll tx whose thread context will be borrowed
	 * to replay the new log entries; log thread will
	 * enter replay state: all write txs are asked to
	 * try again and current poll tx are move to
	 * work[LOG_REPLAY_WAIT].
	 */
	PFS_ASSERT(TAILQ_EMPTY(req->r_otxq) == false);
	log->log_flags |= LOGF_REPLAY_WAIT;
	TAILQ_REMOVE(&work_req[LOG_POLL], req, r_next);
	pfs_log_reply(log, req, rv);
	TAILQ_CONCAT(&work_req[LOG_REPLAY_WAIT], &work_req[LOG_POLL], r_next);

	/*
	 * At last notify io thread(write tx) to unlock meta and try again.
	 * It could increase the probability that io thread(replay tx) gets
	 * meta lock.
	 */
	pfs_log_reply_queue(log, &work_req[LOG_WRITE], -EAGAIN);
	return LOG_IO_CONT;
}

static int
pfs_log_handle_try_reset_lock(pfs_log_t *log, struct req_qhead *work_req)
{
	log_req_t *req;
	pfs_mount_t *mnt = log->log_mount;

	PFS_ASSERT(log->log_state == LOGST_SERVING);

	if (log->log_flags & LOGF_REPLAY_WAIT) {
		/* handle the request in next loop. */
		return LOG_IO_STOP;
	}

	req = TAILQ_FIRST(&work_req[LOG_TRY_RESET_LOCK]);

	pfs_itrace("mnt_host_id:%u, host_id: %d, next_hostid:"
	    " %d \n",
	    mnt->mnt_host_id, req->r_hostid,
	    req->r_next_hostid);
	if(mnt->mnt_host_id == (uint32_t)req->r_hostid) {
		if(pfs_log_paxos_try_release(log) < 0) {
			pfs_etrace("release paxos failed, but we will not use"
			     "host_id: %d but next_hostid: %d\n",
				   req->r_hostid, req->r_next_hostid);
		}
		mnt->mnt_host_id = (uint32_t)req->r_next_hostid;
	}
	TAILQ_REMOVE(&work_req[LOG_TRY_RESET_LOCK], req, r_next);
	pfs_log_reply(log, req, 0);
	return LOG_IO_CONT;
}
static int
pfs_log_handle_write(pfs_log_t *log, struct req_qhead *work_req)
{
	pfs_leader_record_t *lr = &log->log_leader;
	pfs_leader_record_t *latest = NULL;
	log_req_t *req;
	pfs_tx_t *tx;
	int rv, err;
	uint32_t txspace;

	PFS_ASSERT(log->log_state == LOGST_SERVING);
	/*
	 * There is new log entries to be replayed. Write
	 * tx holds the meta lock. Ask them to fail and release
	 * the lock. They can try again later with write on
	 * new meta data that has been replayed.
	 */
	if (log->log_flags & LOGF_REPLAY_WAIT) {
		pfs_log_reply_queue(log, &work_req[LOG_WRITE], -EAGAIN);
		return LOG_IO_CONT;
	}
	MNT_STAT_BEGIN();
	rv = pfs_log_paxos_try_acquire(log, &latest);
	if (rv < 0) {
		/* handle LOG_WRITE in next loop. */
		return LOG_IO_STOP;
	}

	/*
	 * LOG_TRIM_POINT
	 * trimrecords in (lr->tail_txid, latest->tail_txid] need to free
	 * from memory. Add a LOG_TRIM request into work_req[LOG_TRIM],
	 * step back to the first work_req index.
	 */
	if (lr->tail_txid < latest->tail_txid) {
		TAILQ_INSERT_TAIL(&work_req[LOG_TRIM], &log->log_trimreq, r_next);
		return LOG_IO_BACK;
	}

	/*
	 * Although there is only one LOG_WRITE, but it CANT be removed
	 * because log thread may step back to LOG_TRIM.
	 */
	req = TAILQ_FIRST(&work_req[LOG_WRITE]);

	PFS_ASSERT(lr->head_txid <= latest->head_txid);
	if (lr->head_txid < latest->head_txid) {
		/*
		 * There are new log entries. Poll the new log
		 * entries into the replay tx and embed the
		 * replay tx in one write tx. All other write
		 * tx are waiters for the replay host write tx.
		 * The host write tx will replay polled new
		 * entries and notify all others to try again.
		 */
		pfs_itrace("LOG_WRITE found lr lags %lld tx in (%llu, %llu],"
		    " pull them and retry\n",
		    (long long)(latest->head_txid - lr->head_txid),
		    (unsigned long long)lr->head_txid,
		    (unsigned long long)latest->head_txid);
		rv = pfs_log_poll(log, latest, req);
		PFS_ASSERT(rv != 0);
		if (rv < 0) {
			pfs_log_reply_queue(log, &work_req[LOG_WRITE], rv);
			return LOG_IO_STOP;
		}
		log->log_flags |= LOGF_REPLAY_WAIT;
		pfs_log_reply_queue(log, &work_req[LOG_WRITE], -EAGAIN);
		TAILQ_CONCAT(&work_req[LOG_REPLAY_WAIT], &work_req[LOG_POLL], r_next);
		return LOG_IO_CONT;
	}

	/* LOG_TRIM_POINT */
	tx = req->r_itx;
	txspace = tx->t_nops * sizeof(pfs_logentry_phy_t);
	PFS_ASSERT(tx->t_nops > 0 && txspace <= lr->log_size);
	if (txspace >= pfs_log_space(log)) {
		/* trim journal and make room for current LOG_WRITE. */
		log->log_flags |= LOGF_SPACE_NEEDED;
		TAILQ_INSERT_TAIL(&work_req[LOG_TRIM], &log->log_trimreq, r_next);
		return LOG_IO_BACK;
	}

	rv = pfs_log_commit(log, tx, lr);
	if (rv < 0) {
		pfs_etrace("log commit failed, rv=%d\n", rv);
		goto out;
	}

	pfs_tx_apply(tx);
	/*
	 * LOG_WRITE is done successfully, then cut its sectbufs into
	 * trimrecord_queue. Otherwise io thread needs to send back write
	 * tx and log thread cuts sectbufs into trimrecord queue.
	 */
	err = pfs_log_add_trimentry(log, tx->t_id, txspace, &tx->t_ops);
	/* TRIM_SWAP_CHECKPOINT */
	(void)pfs_log_tryswap_trimgroup(log, false, LOG_WRITE);
	PFS_ASSERT(err == 0 && log->log_workgrp->g_roffset == lr->head_offset);

	/*
	 * Only ONE LOG_WRITE could be received.
	 * Reply to this LOG_WRITE and all LOG_POLL in work_req.
	 */
	TAILQ_REMOVE(&work_req[LOG_WRITE], req, r_next);
	PFS_ASSERT(TAILQ_EMPTY(&work_req[LOG_WRITE]) == true);
	pfs_log_reply(log, req, 0);
	pfs_log_reply_queue(log, &work_req[LOG_POLL], 0);
	MNT_STAT_END(MNT_STAT_JOURNAL_WRITE);
	return LOG_IO_CONT;

out:
	TAILQ_REMOVE(&work_req[LOG_WRITE], req, r_next);
	PFS_ASSERT(TAILQ_EMPTY(&work_req[LOG_WRITE]) == true);
	pfs_log_reply(log, req, rv);
	MNT_STAT_END(MNT_STAT_JOURNAL_WRITE);
	return LOG_IO_STOP;
}

static int
pfs_log_handle_trim(pfs_log_t *log, struct req_qhead *work_req)
{
	int rv;
	pfs_leader_record_t *lr = &log->log_leader;
	pfs_leader_record_t *latest = NULL;
	log_req_t *req;

	PFS_ASSERT(log->log_state == LOGST_SERVING);

	clock_gettime(CLOCK_REALTIME, &log->log_trimts);
	if (log->log_flags & LOGF_REPLAY_WAIT)
		return LOG_IO_CONT;

	/*
	 * LOG_TRIM ONLY is sent by log thread itself, eache LOG_TRIM
	 * request always points to log->log_trimreq, so no reply is necessary.
	 */
	req = TAILQ_FIRST(&work_req[LOG_TRIM]);
	TAILQ_REMOVE(&work_req[LOG_TRIM], req, r_next);

	rv = pfs_log_paxos_try_acquire(log, &latest);
	if (rv < 0) {
		/* Needn't to respond to any LOG_TRIM request. */
		return LOG_IO_STOP;
	}

	/*
	 * Another instance has trimmed the journal, if lr and
	 * latest has intersection, we could free relevant sectors
	 * in (lr->tail_txid, latest->tail_txid] from memory.
	 */
	PFS_ASSERT(latest->tail_txid <= lr->head_txid);
	if (lr->tail_txid < latest->tail_txid) {
		pfs_itrace("LOG_TRIM: others have trimmed tx, local lr"
		    " (%llu, %llu], global lr (%llu, %llu]\n",
		    (unsigned long long)lr->tail_txid,
		    (unsigned long long)lr->head_txid,
		    (unsigned long long)latest->tail_txid,
		    (unsigned long long)latest->head_txid);
		pfs_log_del_trimentry(log, latest->tail_txid);
		lr->tail_txid = latest->tail_txid;
		lr->tail_offset = latest->tail_offset;
	}

	/*
	 * When new log entries are found, they should be pulled into memory
	 * firstly. Otherwise local leader whose head is stale would be
	 * written to pbd and cover the correct global leader.
	 * But replaying new entries is not allowed when handling LOG_TRIM,
	 * so wake up poll thread to send a LOG_POLL request. LOG_TRIM
	 * will try again.
	 */
	PFS_ASSERT(lr->head_txid <= latest->head_txid);
	if (lr->head_txid < latest->head_txid) {
		pfs_itrace("LOG_TRIM found lr lags %ld tx in (%llu, %llu], wake"
		    " up poll thread\n",
		    (long long)(latest->head_txid - lr->head_txid),
		    (unsigned long long)lr->head_txid,
		    (unsigned long long)latest->head_txid);
		pfs_mount_signal_sync(log->log_mount);
		/*
		 * Maybe LOG_WRITE or LOG_POLL exist and then pull new entries,
		 * just continue.
		 */
		return LOG_IO_CONT;
	}

	/*
	 * If trim is forced and trimgrp is empty, swap workgrp and waitgrp.
	 */
	if ((log->log_flags & LOGF_TRIM_FORCED)) {
		/* TRIM_SWAP_CHECKPOINT */
		(void)pfs_log_tryswap_trimgroup(log, true, LOG_TRIM);
		log->log_flags &= ~LOGF_TRIM_FORCED;
		rv = pfs_log_trim(log);
	} else if ((log->log_flags & LOGF_SPACE_NEEDED)) {
		/* TRIM_SWAP_CHECKPOINT */
		(void)pfs_log_tryswap_trimgroup(log, true, LOG_WRITE);
		log->log_flags &= ~LOGF_SPACE_NEEDED;
		rv = pfs_log_trim(log);
	}else if (pfs_log_need_trim(log)) {
		rv = pfs_log_trim(log);
	} else
		rv = 0;

	return (rv < 0) ? LOG_IO_STOP : LOG_IO_CONT;
}

static int
pfs_log_handle_flush(pfs_log_t *log, struct req_qhead *work_req)
{
	log_req_t *req;

	PFS_ASSERT(log->log_state == LOGST_SERVING);
	if (log->log_flags & LOGF_REPLAY_WAIT)
		return LOG_IO_CONT;

	req = TAILQ_FIRST(&work_req[LOG_FLUSH]);
	TAILQ_REMOVE(&work_req[LOG_FLUSH], req, r_next);

	/* no entries need to be flushed */
	if (log->log_leader.tail_txid == log->log_leader.head_txid) {
		pfs_log_reply(log, req, -ENODATA);
		return LOG_IO_CONT;
	}

	/*
	 * LOG_TRIM_POINT
	 * LOG_FLUSH sends a LOG_TRIM to log thread itself.
	 * It only trim journal once.
	 */
	log->log_flags |= LOGF_TRIM_FORCED;
	TAILQ_INSERT_HEAD(&work_req[LOG_TRIM], &log->log_trimreq, r_next);
	pfs_log_reply(log, req, -EAGAIN);
	return LOG_IO_BACK;
}

static int
pfs_log_handle_replaydone(pfs_log_t *log, struct req_qhead *work_req)
{
	log_req_t *req;

	PFS_ASSERT((log->log_flags & LOGF_REPLAY_WAIT) != 0);

	/*
	 * ONLY ONE REPLAYDONE can exists.
	 * Move TXT_REPLAY's meta sectors in LOG_REPLAYDONE to trimrecord_queue.
	 * All txs in LOG_REPLAYDONE are created by log thread,
	 * so recycles their resources here.
	 */
	req = TAILQ_FIRST(&work_req[LOG_REPLAYDONE]);
	TAILQ_REMOVE(&work_req[LOG_REPLAYDONE], req, r_next);
	PFS_ASSERT(TAILQ_EMPTY(&work_req[LOG_REPLAYDONE]) == true);


	/* Count number of txop trimmed by others during LOG_LOAD. */
	if (log->log_state == LOGST_NOTLOADED) {
		/*
		 * NOTE:
		 * LOG_REPLAYDONE is sent during mount, but tail_txid may move
		 * during log_load, so remove sectors in
		 * (tail_txid_after_preload, tail_txid_after_load] after all
		 * replay txs are done.
		 */
		pfs_log_replaytx_put(log, req->r_otxq, true);
		pfs_log_del_trimentry(log, log->log_leader.tail_txid);
		log->log_state = LOGST_SERVING;
	} else
		pfs_log_replaytx_put(log, req->r_otxq, true);
	PFS_ASSERT(log->log_workgrp->g_rtxid == (pfs_txid_t)log->log_leader.head_txid &&
	    log->log_workgrp->g_roffset == log->log_leader.head_offset);

	log->log_flags &= ~LOGF_REPLAY_WAIT;
	pfs_log_reply_queue(log, &work_req[LOG_REPLAY_WAIT], 0);
	pfs_log_reply(log, req, 0);
	return LOG_IO_CONT;
}

static int
pfs_log_handle_stop(pfs_log_t *log, struct req_qhead *work_req)
{
	pfs_itrace("stop mark got, exiting...\n");
	log->log_state = LOGST_STOP;
	pfs_log_reply_queue(log, &work_req[LOG_STOP], 0);
	return LOG_IO_CONT;
}

static int
pfs_log_handle_suspend(pfs_log_t *log, struct req_qhead *work_req)
{
	pfs_itrace("pause log thread\n");
	PFS_ASSERT(log->log_state == LOGST_SERVING);
	log->log_state = LOGST_SUSPENDED;
	pfs_log_paxos_try_release(log);
	pfs_log_reply_queue(log, &work_req[LOG_SUSPEND], 0);
	return LOG_IO_CONT;
}

static int
pfs_log_handle_resume(pfs_log_t *log, struct req_qhead *work_req)
{
	pfs_itrace("wakeup log thread\n");
	PFS_ASSERT(log->log_state == LOGST_SUSPENDED);
	log->log_state = LOGST_SERVING;
	/* TRIM_SWAP_CHECKPOINT */
	(void)pfs_log_tryswap_trimgroup(log, true, LOG_RESUME);
	pfs_log_reply_queue(log, &work_req[LOG_RESUME], 0);
	return LOG_IO_CONT;
}

static int
pfs_log_handle_req(pfs_log_t *log, struct req_qhead *work_req, uint32_t reqmask)
{
	log_req_handler_t *hdl;
	int i, rv = 0;

	for (i = 1; i < LOG_NREQ;) {
		hdl = &log_req_handlers[i];
		if ((reqmask & (1 << i)) == 0 || TAILQ_EMPTY(&work_req[i])) {
			if (!TAILQ_EMPTY(&work_req[i])) {
				pfs_etrace("reqmask %#x, unexpected req %s\n",
				    reqmask, hdl->hdl_name);
			}
			i++;
			continue;
		}

		rv = (*hdl->hdl_func)(log, work_req);
		if (rv == LOG_IO_STOP)
			break;
		else if (rv == LOG_IO_BACK) {
			/* LOG_WRITE/FLUSH need to step back to LOG_TRIM. */
			pfs_itrace("LOG_IO_BACK from [%d]%s\n", i, hdl->hdl_name);
			i = LOG_TRIM;
		} else
			i++;
	}

	pfs_log_paxos_try_release(log);
	return rv;
}

static void *
pfs_log_thread_entry(void *arg)
{
	int i, err;
	pfs_log_t *log = (pfs_log_t *)arg;
	struct req_qhead work_req[LOG_NMAX];
	log_req_t *req, *next;
	uint32_t reqmask = 0;
	struct timespec ts, curts, swap_ts;

	pfs_itrace("log thread start\n");
	swap_ts.tv_sec = 0;
	for (i = 0; i < LOG_NMAX; i++)
		TAILQ_INIT(&work_req[i]);

	do {
		clock_gettime(CLOCK_REALTIME, &ts);

		/* TRIM_SWAP_CHECKPOINT */
		if ((reqmask & LOG_BIT_TRIM) && TAILQ_EMPTY(&work_req[0])
		    && (log->log_flags & LOGF_REPLAY_WAIT) == 0
		    && ts.tv_sec - swap_ts.tv_sec >= 1
		    && pfs_log_tryswap_trimgroup(log, false, LOG_NREQ) >= 0)
			swap_ts = ts;

		ts.tv_sec += MIN(log_paxos_lease, log_trim_interval);

		err = 0;
		mutex_lock(&log->log_mtx);
		while (err == 0 && TAILQ_EMPTY(&work_req[0]) &&
		    TAILQ_EMPTY(&log->log_reqhead))
		       err = pthread_cond_timedwait(&log->log_cond,
			   &log->log_mtx, &ts);
		TAILQ_CONCAT(&work_req[0], &log->log_reqhead, r_next);
		mutex_unlock(&log->log_mtx);

		for (req = TAILQ_FIRST(&work_req[0]); req; req = next) {
			next = TAILQ_NEXT(req, r_next);
			TAILQ_REMOVE(&work_req[0], req, r_next);
			TAILQ_INSERT_TAIL(&work_req[req->r_type], req, r_next);
		}

		switch (log->log_state) {
		case LOGST_NOTLOADED:
			reqmask = LOG_BIT_LOAD | LOG_BIT_STOP | LOG_BIT_REPLAYDONE;
			break;

		case LOGST_SERVING:
			reqmask = LOG_BIT_POLL | LOG_BIT_STOP | LOG_BIT_REPLAYDONE
				  | LOG_BIT_SUSPEND | LOG_BIT_TRY_RESET_LOCK;
			if (pfs_writable(log->log_mount))
				reqmask |= LOG_BIT_TRIM | LOG_BIT_WRITE | LOG_BIT_FLUSH;
			break;

		case LOGST_SUSPENDED:
			reqmask = LOG_BIT_RESUME;
			break;

		default:
			reqmask = 0;
			pfs_etrace("unknown log state %d\n", log->log_state);
			PFS_ASSERT("unknown log state" == NULL);
			break;
		}

		/*
		 * LOG_TRIM_POINT
		 * If time from last LOG_TRIM is bigger than log_trim_interval,
		 * log thread attempts to send a LOG_TRIM if need.
		 */
		if ((reqmask & LOG_BIT_TRIM) && TAILQ_EMPTY(&work_req[LOG_TRIM]) &&
		    pfs_log_need_trim(log)) {
			clock_gettime(CLOCK_REALTIME, &curts);
			if ((curts.tv_sec - log->log_trimts.tv_sec >= log_trim_interval) ||
			    pfs_log_need_trim_hard(log))
				TAILQ_INSERT_TAIL(&work_req[LOG_TRIM], &log->log_trimreq, r_next);
		}

		pfs_log_handle_req(log, work_req, reqmask);

		for (i = 1; i < LOG_NREQ; i++)
			TAILQ_CONCAT(&work_req[0], &work_req[i], r_next);

		/* always clear IO req deadline. it is harmless */
		pfs_tls_set_ttl(0);
	} while (log->log_state != LOGST_STOP);

	PFS_ASSERT(TAILQ_EMPTY(&log->log_reqhead) == true);
	for (i = 0; i < LOG_NMAX; i++)
		PFS_ASSERT(TAILQ_EMPTY(&work_req[i]) == true);
	pfs_itrace("log thread stop\n");
	return NULL;
}

void
pfs_log_suspend(pfs_log_t *log)
{
	int err;
	err = pfs_log_request(log, LOG_SUSPEND, NULL, NULL);
	PFS_VERIFY(err == 0);
}

void
pfs_log_resume(pfs_log_t *log)
{
	int err;
	err = pfs_log_request(log, LOG_RESUME, NULL, NULL);
	PFS_VERIFY(err == 0);
}

int
pfs_log_start(pfs_log_t *log)
{
	int err, fd;
	char *buf;

	pfs_itrace("log trim group's sector threshold=%ld, tx threshold=%ld\n",
	    trimgroup_nsect_threshold, trimgroup_ntx_threshold);
	fd = pfs_file_open_impl(log->log_mount, JOURNAL_FILE_MONO, 0,
	    &log->log_file, INNER_FILE_BTIME);
	if (fd < 0)
		return fd;

	log->log_state = LOGST_NOTLOADED;
	mutex_init(&log->log_mtx);
	cond_init(&log->log_cond, NULL);
	TAILQ_INIT(&log->log_reqhead);

	clock_gettime(CLOCK_REALTIME, &log->log_trimts);

	memset(&log->log_trimreq, 0, sizeof(log->log_trimreq));
	log->log_trimreq.r_type = LOG_TRIM;
	mutex_init(&log->log_trimreq.r_mtx);
	cond_init(&log->log_trimreq.r_cond, NULL);

	buf = (char *)pfs_mem_malloc(PFS_FRAG_SIZE, M_FRAG);
	if (buf == NULL)
		ERR_RETVAL(ENOMEM);
	log->log_workbuf = buf;
	log->log_workbufsz = PFS_FRAG_SIZE;
	memset(log->log_workbuf, 0, log->log_workbufsz);
	log->log_paxos_got = false;
	log->log_paxos_ts.tv_sec = 0;
	log->log_paxos_ts.tv_nsec = 0;
	memset(&log->log_leader_latest, 0, sizeof(log->log_leader_latest));

	err = pthread_create(&log->log_tid, NULL, pfs_log_thread_entry, log);
	if (err) {
		log->log_tid = 0;
		pfs_etrace("cant create log io thread: %d, %s\n", err,
		    strerror(err));
		pfs_log_stop(log);
		return -err;
	}

	return err;
}

void
pfs_log_stop(pfs_log_t *log)
{
	int rv;

	if (log->log_tid) {
		pfs_log_request(log, LOG_STOP, NULL, NULL);
		rv = pthread_join(log->log_tid, NULL);
		PFS_VERIFY(rv == 0);
		log->log_tid = 0;
	}

	// close fd of log file
	if (log->log_file) {
		pfs_file_close(log->log_file);
		log->log_file = NULL;
	}

	if (log->log_workbuf) {
		pfs_mem_free(log->log_workbuf, M_FRAG);
		log->log_workbuf = NULL;
		log->log_workbufsz = 0;
	}

	pfs_trimgroup_fini(log->log_workgrp);
	pfs_trimgroup_fini(log->log_waitgrp);
	log->log_workgrp = log->log_waitgrp = NULL;

	mutex_destroy(&log->log_trimreq.r_mtx);
	cond_destroy(&log->log_trimreq.r_cond);

	mutex_destroy(&log->log_mtx);
	cond_destroy(&log->log_cond);
}

/*
 * Load leader by direct device I/O.
 * In leader record, the tail_txid corresponding to a checkpoint is updated by
 * trimming journal operation. In other words, transactions in the range of
 * (0, tail_txid] were applied to pbd while creating a checkpoint.
 */
int
pfs_log_preload(pfs_log_t *log)
{
	int rv;
	char buf[PBD_SECTOR_SIZE];
	pfs_mount_t *mnt = log->log_mount;
	pfs_leader_record_t *lr = &log->log_leader;

	/*
	 * DON'T use mnt->mnt_blksize, because its value maybe zero during mount().
	 */
	memset(buf, 0, PBD_SECTOR_SIZE);
	rv = pfsdev_pread(mnt->mnt_ioch_desc, buf, sizeof(buf), PFS_BLOCK_SIZE);
	if (rv < 0) {
		pfs_etrace("Read leader @ bda %llu failed, rv=%d\n",
		    PFS_BLOCK_SIZE, rv);
		return rv;
	}
	memcpy(lr, buf, sizeof(*lr));

	/*
	 * Init workgrp parameters by leader record.
	 */
	log->log_workgrp = &log->log_grpbuf[0];
	pfs_trimgroup_init(log->log_workgrp);
	log->log_waitgrp = &log->log_grpbuf[1];
	pfs_trimgroup_init(log->log_waitgrp);
	log->log_workgrp->g_ltxid = log->log_workgrp->g_rtxid = lr->tail_txid;
	log->log_workgrp->g_roffset = lr->tail_offset;

	pfs_itrace("Load leader txid (%llu, %llu], offset (%llu, %llu]"
	    " head_lsn=%llu\n", (unsigned long long)lr->tail_txid,
	    (unsigned long long)lr->head_txid,
	    (unsigned long long)lr->tail_offset,
	    (unsigned long long)lr->head_offset,
	    (unsigned long long)lr->head_lsn);
	return 0;
}

int
pfs_log_request_impl(pfs_log_t *log, int type, pfs_tx_t *itx, struct tx_qhead
    *otxq, int host_id, int next_host_id)
{
	log_req_t req;

	/* log thread must start. */
	PFS_ASSERT(log->log_tid != 0);

	memset(&req, 0, sizeof(req));
	req.r_type = type;
	mutex_init(&req.r_mtx);
	cond_init(&req.r_cond, NULL);
	req.r_error = 0;
	req.r_done = false;
	req.r_itx = itx;
	req.r_otxq = otxq;
	req.r_hostid = host_id;
	req.r_next_hostid = next_host_id;

	mutex_lock(&log->log_mtx);
	TAILQ_INSERT_TAIL(&log->log_reqhead, &req, r_next);
	cond_signal(&log->log_cond);
	mutex_unlock(&log->log_mtx);

	mutex_lock(&req.r_mtx);
	while (!req.r_done)
		cond_wait(&req.r_cond, &req.r_mtx);
	mutex_unlock(&req.r_mtx);

	mutex_destroy(&req.r_mtx);
	cond_destroy(&req.r_cond);
	return req.r_error;
}

void
pfs_log_replaytx_put(pfs_log_t *log, struct tx_qhead *otxq, bool trim)
{
	int err;
	pfs_tx_t *tx;
	uint32_t txspace;

	while ((tx = TAILQ_FIRST(otxq)) != NULL) {
		TAILQ_REMOVE(otxq, tx, t_next);
		if (trim) {
			txspace = tx->t_nops * sizeof(pfs_logentry_phy_t);
			err = pfs_log_add_trimentry(log, tx->t_id, txspace,
			    &tx->t_ops);
			PFS_ASSERT(err == 0);
			/* TRIM_SWAP_CHECKPOINT */
			(void)pfs_log_tryswap_trimgroup(log, false,
			    LOG_REPLAYDONE);
		}
		pfs_tx_put(tx);
	}
}

void
pfs_log_reply(pfs_log_t *log, log_req_t *req, int rv)
{
	/*
	 * Usually r_otxq in request are created by log thread,
	 * they should be recycled before signaling io thread
	 * if error occurs.
	 * But in one specified case we can't do this. New log
	 * entries are found when handling a write tx. Log thread
	 * sends back -EAGAIN to io thread. Replay tx will be
	 * inserted into r_otxq and be done by io thread.
	 */
	if (rv < 0 && rv != -EAGAIN && !TAILQ_EMPTY(req->r_otxq))
		pfs_log_replaytx_put(log, req->r_otxq, false);

	mutex_lock(&req->r_mtx);
	req->r_error = rv;
	req->r_done = true;
	cond_signal(&req->r_cond);
	mutex_unlock(&req->r_mtx);
}

void
pfs_log_reply_queue(pfs_log_t *log, struct req_qhead *reqhead, int rv)
{
	log_req_t *req;

	while ((req = TAILQ_FIRST(reqhead)) != NULL) {
		TAILQ_REMOVE(reqhead, req, r_next);
		pfs_log_reply(log, req, rv);
	}
}
