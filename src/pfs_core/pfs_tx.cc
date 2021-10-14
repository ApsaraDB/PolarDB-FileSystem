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
#include <errno.h>

#include <assert.h>
#include <pthread.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pfs_meta.h"
#include "pfs_dir.h"
#include "pfs_devio.h"
#include "pfs_inode.h"
#include "pfs_mount.h"
#include "pfs_tx.h"
#include "pfs_log.h"
#include "pfs_trace.h"
#include "pfs_stat.h"

#define	TX_DEBUG_VERBOSE 0

/*
 * Tx is to protect the integrity of meta data. A read tx acquires the
 * rdlock of meta data before reading, and simply releases it after
 * reading.
 *
 * A write tx is more complex. Before modifying data, a write tx
 * acquires the wrlock. With the lock held, it accesses and modifies
 * the data, and then submits the write tx to the log thread and
 * waits. The log thread checks if its local log header is up to date
 * with respect to other hosts.
 *
 * If not, the log thread scans the new log entries into a replay tx
 * and embeds the replay tx into the write tx. The write tx is waken
 * up. It undoes its previous modification, replays the new log
 * entries, releases the wrlock, runs the txop callbacks, and returns
 * an error code to user indicating try the operation again.
 *
 * If so, the log thread converts tx ops into log entries and writes
 * the log entries. After that, the write tx is signaled and its
 * thread continues running. The thread releases the meta data lock,
 * runs the txop callbacks, and returns an error code indicating
 * success.
 *
 * Typical usage of tx is like below:
 *      TX_ENTER(mnt, tx-type)
 *      access or/and modify the meta data
 *      TX_SUBMIT(mnt, error-code)
 */

#define	TOP_FLG_RECREATE	0x00000001	/* the txop is recreated from log */
#define	TOP_FLG_INITED		0x00000002	/* undo flag: top old is set */
#define	TOP_FLG_DONE		0x00000004	/* undo flag: top new is set */

static pfs_txop_t *pfs_tx_index_op(pfs_tx_t *tx, pfs_metaobj_phy_t *mo);
static pfs_metaobj_phy_t *pfs_tx_find_mo(pfs_tx_t *tx, pfs_metaobj_phy_t *mo);

void
pfs_sectbuf_bind(pfs_sectbuf_t *sb, const pfs_txop_t *top)
{
	sb->s_txid = top->top_tx->t_id;
	sb->s_bda = top->top_bda;
	sb->s_metabuf = (char*)top->top_buf;
	sb->s_buf = NULL;
}

void
pfs_sectbuf_sync(pfs_sectbuf_t *sb, const pfs_txop_t *top)
{
	if (sb->s_buf)
		memcpy(((pfs_metaobj_phy_t*)(sb->s_buf)) + top->top_idx,
		    &top->top_remote, sizeof(top->top_remote));
}

pfs_sectbuf_t *
pfs_sectbuf_get()
{
	return (pfs_sectbuf_t *)pfs_mem_malloc(sizeof(pfs_sectbuf_t), M_SECTHDR);
}

void
pfs_sectbuf_put(pfs_sectbuf_t *sb)
{
	pfs_mem_free(sb->s_buf, M_SECTBUF);
	pfs_mem_free(sb, M_SECTHDR);
}

static void
txop_dump(pfs_txop_t *top, pfs_logentry_phy_t *le, const char *caller)
{
	pfs_dbgtrace("%s: txop %s/%d/%s buf %p, bda %#lx, oi %u, hd %#x, shdw %#x\n",
	    caller, top->top_func, top->top_line, top->top_name, top->top_buf,
	    top->top_bda, top->top_idx, top->top_dup_head, top->top_shadow);
	if (le)
		pfs_dbgtrace("%s: log le lsn %lld\n", caller,
		    (long long)le->le_lsn);
}

pfs_txop_t *
pfs_txop_create(pfs_tx_t *tx, const char *func, const char *name,
    int line, int flags)
{
	pfs_txop_t *top;

	top = (pfs_txop_t *)pfs_mem_malloc(sizeof(*top), M_TXOP);
	if (top) {
		memset(top, 0, sizeof(*top));
		top->top_tx = tx;
		top->top_dup_head = NULL;
		top->top_shadow = NULL;
		top->top_cb = NULL;
		top->top_flags = flags;
		top->top_func = func;
		top->top_name = name;
		top->top_line = line;
	}
	return top;
}

pfs_metaobj_phy_t*
pfs_txop_init(pfs_txop_t *top, pfs_metaobj_phy_t *buf, int oid, pfs_bda_t bda)
{
	pfs_txop_t *duphead;
	pfs_metaobj_phy_t *obj_tx = NULL, *obj_meta = buf + oid;
	/*
	 * We CANT check metaboj's checksum here, because a metaobj may be
	 * modified more than one time during a tx, such as the deleted inode
	 * metaobj in pfs_inode_release().
	 */
	PFS_ASSERT(top->top_flags == 0);
	top->top_buf = buf;
	top->top_bda = bda;
	top->top_idx = oid;
	top->top_flags |= TOP_FLG_INITED;

	top->top_local.mo_type = obj_meta->mo_type;
	top->top_local.mo_number = obj_meta->mo_number;

	duphead = pfs_tx_index_op(top->top_tx, &top->top_local);
	obj_tx = &duphead->top_local;
	/*
	 * duplicated txop does not need to init top_local.
	 */
	if (duphead == top)
		top->top_local = *obj_meta;
	top->top_dup_head = duphead;
	top->top_dup_cnt = 0;
	top->top_dup_idx = duphead->top_dup_cnt;
	duphead->top_dup_cnt++;

	return obj_tx;
}

/*
 * If tx is not created or is "done"(eg. REPLAY tx or tx_end), return object in
 * meta cache.
 * If tx is not done and object is not indexed, return object in meta cache.
 * If tx is not done and object is indexed, return object indexed in tx.
 */
pfs_metaobj_phy_t *
pfs_tx_get_mo(pfs_tx_t *tx, pfs_metaobj_phy_t *obj_meta)
{
	pfs_metaobj_phy_t *obj_tx = NULL;
	if (tx == NULL || tx->t_done)
		return obj_meta;
	obj_tx = pfs_tx_find_mo(tx, obj_meta);
	if (obj_tx != NULL)
		return obj_tx;
	return obj_meta;
}

/*
 * pfs_txop_recreate:
 *
 *	Recrete a transaction op from a redo log entry @le.
 *	The new op is then inserted into @tx.
 */
pfs_txop_t *
pfs_txop_recreate(pfs_tx_t *tx, pfs_logentry_phy_t *le, const char *func,
    const char *name, int line)
{
	pfs_txop_t *top;

	top = (pfs_txop_t *)pfs_mem_malloc(sizeof(*top), M_TXOP);
	if (top) {
		memset(top, 0, sizeof(*top));
		top->top_tx = tx;
		top->top_flags |= TOP_FLG_RECREATE;

		top->top_func = func;
		top->top_name = name;
		top->top_line = line;
		top->top_cb = NULL;

		top->top_buf = NULL;
		top->top_idx = le->le_obj_idx;
		top->top_bda = le->le_sector_bda;
		top->top_remote = le->le_obj_val;
		pfs_metaobj_check_crc(&top->top_remote);
		PFS_ASSERT(top->top_remote.mo_type != MT_NONE);

		top->top_dup_head = NULL;
		top->top_shadow = NULL;
	}
	return top;
}

static void
pfs_txop_update(pfs_txop_t *top, pfs_txop_callback_t *cb)
{
	pfs_txop_t *duphead;
	pfs_metaobj_phy_t *mo;

	PFS_ASSERT(top->top_buf != NULL);
	PFS_ASSERT((top->top_flags & (TOP_FLG_INITED|TOP_FLG_DONE)) ==
		   TOP_FLG_INITED);

	/* set new mo's checksum firstly */
	mo = &top->top_dup_head->top_local;
	mo->mo_checksum = crc32c_compute(mo, sizeof(*mo),
	    offsetof(struct pfs_metaobj_phy, mo_checksum));
	top->top_cb = cb;
	top->top_flags |= TOP_FLG_DONE;

	duphead = top->top_dup_head;
	duphead->top_dup_cnt--;
	PFS_ASSERT(top->top_dup_idx == duphead->top_dup_cnt);
	PFS_ASSERT(top->top_dup_cnt == 0);
}

/*
 * pfs_txop_log:
 *
 *	Fill in the redo log entry.
 */
void
pfs_txop_log(pfs_txop_t *top, pfs_lsn_t lsn, pfs_logentry_phy_t *le)
{
	PFS_ASSERT(top->top_flags & TOP_FLG_DONE);
	pfs_metaobj_check_crc(&top->top_local);

	le->le_lsn = lsn;
	le->le_txid = top->top_tx->t_id;
	le->le_sector_bda = top->top_bda;
	le->le_obj_idx = top->top_idx;
	PFS_ASSERT(top->top_local.mo_type != MT_NONE);
	le->le_obj_val = top->top_local;	/* structure copy */
	le->le_more = (TAILQ_NEXT(top, top_next) != NULL);
	le->le_checksum = crc32c_compute(le, sizeof(*le),
	    offsetof(struct pfs_logentry_phy, le_checksum));

#if 0
	txop_dump(top, le, "txop-log");
#endif
}

/*
 * pfs_txop_rollback
 *
 *	Rollbak the effect of @top, called within a tx semantic context.
 *	It is different from txop_undo, which is called within a meta data
 *	undo context.
 */
static void
pfs_txop_rollback(pfs_txop_t *top)
{
	pfs_mount_t *mnt = top->top_tx->t_mnt;
	pfs_metaobj_phy_t *mo = NULL;

	PFS_ASSERT((top->top_flags & TOP_FLG_RECREATE) == 0);

	/*
	 * Not inited txop or duplicated txop does not need rollback.
	 */
	if ((top->top_flags & TOP_FLG_INITED) == 0 || top != top->top_dup_head)
		return;

	mo = &top->top_local;
	pfs_meta_undo(mnt, mo->mo_type, mo->mo_number, top);
}


static void
pfs_txop_replay(pfs_txop_t *top)
{
	pfs_mount_t *mnt = top->top_tx->t_mnt;
	pfs_metaobj_phy_t *mo = NULL;

	PFS_ASSERT((top->top_flags & TOP_FLG_RECREATE) != 0);

	mo = &top->top_remote;
	pfs_meta_redo(mnt, mo->mo_type, mo->mo_number, top);
}

/*
 * pfs_txop_destroy:
 *
 *	Destroy a transaction operation.
 */
static void
pfs_txop_destroy(pfs_txop_t *top)
{
	pfs_txop_t *shadow;

	do {
		shadow = top->top_shadow;
		top->top_tx = NULL;
		pfs_mem_free(top, M_TXOP);
		top = shadow;
	} while (top);
}

int
pfs_txop_redo(pfs_txop_t *top, pfs_metaobj_phy_t *mo, void *buf)
{
	int nfree_delta;

	PFS_ASSERT((top->top_flags & TOP_FLG_RECREATE) != 0);

	/*
	 * RECREATE txop's top_buf is NULL, set its value here.
	 */
	PFS_ASSERT(top->top_buf == NULL);
	top->top_buf = (pfs_metaobj_phy_t *)buf;

	nfree_delta = mo->mo_used - top->top_remote.mo_used;
	*mo = top->top_remote;
	return nfree_delta;
}

/*
 * pfs_txop_undo:
 *
 *	Undo a txop. Return delta change of the free state.
 *	This function should only be applied on new-txop,
 *	never on recreated-txop.
 */
int
pfs_txop_undo(pfs_txop_t *top, pfs_metaobj_phy_t *mo)
{
	int nfree_delta = 0;

	PFS_ASSERT((top->top_flags & TOP_FLG_RECREATE) == 0);

	PFS_ASSERT(mo != &top->top_local);
	nfree_delta = top->top_local.mo_used - mo->mo_used;

	return nfree_delta;
}


/*
 * Merge @top with @duphead.
 * Only following order between 'dup' and 'top' are legal:
 *   1. SEQUENTIAL
 * 	dup:	inited --- done
 * 	top:			inited --- done
 *   2. NESTED
 * 	dup:	inited ------------------- done
 * 	top:		inited --- done
 * In either case, let 'top' shadowed by 'dup' in merge().
 *
 * Another case is illegal:
 *   3. INTERLEAVING
 * 	dup:	inited ----------- done
 * 	top:		inited ----------- done
 * If it happens, assertion will fail when pfs_tx_done_op(dup).
 */
static void
pfs_txop_merge(pfs_txop_t *duphead, pfs_txop_t *top)
{
	/*
	 * There is already an txop recording modification
	 * on the same object. Merge new txop to be shadow of
	 * the old one.
	 */
	PFS_ASSERT(duphead->top_flags & TOP_FLG_INITED);
	PFS_ASSERT(top->top_flags & TOP_FLG_DONE);
	PFS_ASSERT(top->top_shadow == NULL);

	txop_dump(duphead, NULL, "txop-dedup");
	txop_dump(top, NULL, "txop-dedup");

	if (top->top_cb) {
		/* To keep callback, link txop with top_shadow. */
		top->top_shadow = duphead->top_shadow;
		duphead->top_shadow = top;
	} else
		pfs_txop_destroy(top);
}

static void
pfs_txop_do_callback(pfs_txop_t *top, pfs_metaobj_phy_t *mo, int err)
{
	pfs_tx_t *tx = top->top_tx;
	pfs_txop_t *cbtop;

	/* XXX: the calling of top_cb is not in order */
	cbtop = (top->top_cb) ? top : top->top_shadow;
	for (; cbtop; cbtop = cbtop->top_shadow) {
		PFS_ASSERT(cbtop->top_flags & TOP_FLG_DONE);
		PFS_ASSERT(cbtop->top_dup_head == top);
		(cbtop->top_cb)(tx->t_mnt, mo, err);
	}
}

int
pfs_tx_log(pfs_tx_t *tx, uint64_t head_txid, uint64_t head_lsn,
    uint64_t head_offset, char *buf, int buflen)
{
	pfs_mount_t *mnt = tx->t_mnt;
	pfs_log_t *log = &mnt->mnt_log;
	pfs_txop_t *top;
	uint64_t len, offset;
	int rv;
	int nle;

	PFS_ASSERT(!TAILQ_EMPTY(&tx->t_ops));

	nle = 0;
	len = 0;
	offset = head_offset;
	memset(buf, 0, buflen);
	tx->t_id = head_txid + 1;

	TAILQ_FOREACH(top, &tx->t_ops, top_next) {
		nle++;
		pfs_txop_log(top, head_lsn + nle, (pfs_logentry_phy_t *)(buf + len));

		/*
		 * Ensure there is buffer space to write at least one log entry.
		 * Otherwise, flush the bufer to free space.
		 */
		len += sizeof(pfs_logentry_phy_t);
		if (len >= (uint64_t)buflen) {
			PFS_ASSERT(len == (uint64_t)buflen);
			rv = pfs_log_write(log, buf, len, offset);
			if (rv < 0)
				return rv;
			memset(buf, 0, buflen);
			len = 0;
			offset += rv;
		}
	}
	PFS_ASSERT(nle == tx->t_nops);
	if (len != 0) {
		rv = pfs_log_write(log, buf, len, offset);
		if (rv < 0)
			return rv;
		offset += rv;
	}
	return (int)(offset - head_offset);
}

/*
 * pfs_tx_commit:
 *
 *	Write the modifed data in the tx ops onto PBD.
 */
int
pfs_tx_commit(pfs_tx_t *tx)
{
	pfs_mount_t *mnt = tx->t_mnt;
	int ioch_desc = mnt->mnt_ioch_desc;
	pfs_txop_t *top;
	int err = 0;

	/* only write tx can commit data to disk */
	PFS_ASSERT(tx->t_type == TXT_WRITE);
	pfs_tx_apply(tx);
	TAILQ_FOREACH(top, &tx->t_ops, top_next) {
		PFS_ASSERT((top->top_flags & TOP_FLG_DONE) ||
		    (top->top_flags & TOP_FLG_RECREATE));

		pfs_metaobj_check_crc_buf(top->top_buf,
		    mnt->mnt_sectsize / sizeof(pfs_metaobj_phy_t));

		txop_dump(top, NULL, "txop-commit");
		err = pfsdev_pwrite(ioch_desc, top->top_buf, mnt->mnt_sectsize,
		    top->top_bda);
		if (err < 0)
			break;
	}

	return err;
}

void
pfs_tx_rollback(pfs_tx_t *tx)
{
	pfs_txop_t *top;

	TAILQ_FOREACH_REVERSE(top, &tx->t_ops, txop_qhead, top_next) {
		pfs_txop_rollback(top);
	}
}

int
_pfs_tx_new_op(pfs_tx_t *tx, pfs_txop_t **topp, const char *func,
    const char *name, int line)
{
	pfs_txop_t *top;

	top = pfs_txop_create(tx, func, name, line, 0);
	if (top == NULL)
		ERR_RETVAL(ENOMEM);

	/*
	 * pfs_mount_check_root() will create a txop with a NULL tx.
	 */
	if (tx) {
		tx->t_nops++;
		TAILQ_INSERT_TAIL(&tx->t_ops, top, top_next);
	}
	*topp = top;
	return 0;
}

static int
txop_index_compare(const void *a, const void *b)
{
	pfs_metaobj_phy_t *moa = (pfs_metaobj_phy_t *)a;
	pfs_metaobj_phy_t *mob = (pfs_metaobj_phy_t *)b;

	if (moa->mo_type > mob->mo_type)
		return 1;
	if (moa->mo_type < mob->mo_type)
		return -1;

	if (moa->mo_number > mob->mo_number)
		return 1;
	if (moa->mo_number < mob->mo_number)
		return -1;
	return 0;
}

static pfs_txop_t *
pfs_tx_index_op(pfs_tx_t *tx, pfs_metaobj_phy_t *mo)
{
	tnode_t *node;

	node = (tnode_t *)tsearch(mo, &tx->t_opsroot, txop_index_compare);
	return (pfs_txop_t *)TNODE_KEY(node);
}

static pfs_metaobj_phy_t *
pfs_tx_find_mo(pfs_tx_t *tx, pfs_metaobj_phy_t *mo)
{
	tnode_t *node;

	node = (tnode_t *)tfind(mo, &tx->t_opsroot, txop_index_compare);
	if (node == NULL)
		return NULL;
	return (pfs_metaobj_phy_t *)TNODE_KEY(node);
}

int
_pfs_tx_recreate_op(pfs_tx_t *tx, pfs_logentry_phy_t *le, pfs_txop_t **topp,
    const char *func, const char *name, int line)
{
	pfs_txop_t *top;

	top = pfs_txop_recreate(tx, le, func, name, line);
	if (top == NULL)
		ERR_RETVAL(ENOMEM);
	TAILQ_INSERT_TAIL(&tx->t_ops, top, top_next);
	tx->t_nops++;
	*topp = top;
	return 0;
}

void
_pfs_tx_done_op(pfs_tx_t *tx, pfs_txop_t *top, pfs_txop_callback_t *cb)
{
	pfs_txop_update(top, cb);
	if (top != top->top_dup_head) {
		TAILQ_REMOVE(&tx->t_ops, top, top_next);
		tx->t_nops--;
		pfs_txop_merge(top->top_dup_head, top);
	}
}

void
pfs_tx_add_callback(pfs_tx_t *tx, pfs_tx_callback_t *cbfunc, int64_t cbdata)
{
	pfs_txcb_t *tcb;
	PFS_ASSERT(tx->t_type == TXT_WRITE);

	tcb = (pfs_txcb_t *)pfs_mem_malloc(sizeof(*tcb), M_TXCB);
	PFS_VERIFY(tcb != NULL);

	tcb->tcb_func = cbfunc;
	tcb->tcb_data = cbdata;
	TAILQ_INSERT_TAIL(&tx->t_cbs, tcb, tcb_next);
	tx->t_ncbs++;
}

static void
pfs_tx_do_callback(pfs_tx_t *tx, int err)
{
	pfs_txop_t *top;
	pfs_txcb_t *tcb;

	/*
	 * metaobj first, then memory structure.
	 * XXX
	 * Last callback must control the inode sync condition.
	 */
	TAILQ_FOREACH(top, &tx->t_ops, top_next) {
		pfs_txop_do_callback(top, &top->top_remote, err);
	}

	TAILQ_FOREACH(tcb, &tx->t_cbs, tcb_next) {
		PFS_ASSERT(tx->t_type == TXT_WRITE);
		(tcb->tcb_func)(tx->t_mnt, tcb->tcb_data, err);
	}
}

static void
pfs_tx_replay(pfs_tx_t *rtx)
{
	pfs_txop_t *top;
	rtx->t_done = true;
	pfs_tls_set_tx(rtx);
	TAILQ_FOREACH(top, &rtx->t_ops, top_next) {
		txop_dump(top, NULL, "txop-replay");
		pfs_txop_replay(top);
	}
	pfs_meta_redo_fini(rtx);
}

/*
 * pfs_txlist_replay:
 *
 *	Apply the tx change into memory.
 */
void
pfs_txlist_replay(pfs_mount_t *mnt, struct tx_qhead *replaytxq)
{
	int err;
	pfs_tx_t *otx, *rtx;
	int64_t starttid, stoptid;
	int ntxs;
	MNT_STAT_BEGIN();
	PFS_ASSERT(TAILQ_EMPTY(replaytxq) == false);

	/*
	 * Set up the replay tx if necessary. For write tx, it must
	 * have already locked the meta data, since it has updated meta
	 * data holding the meta data lock; for read tx, it is polling new
	 * log entries and has not locked the meta data; for load tx, it
	 * is the same as the read tx.
	 */
	otx = pfs_tls_get_tx();
	if (otx) {
		PFS_ASSERT(otx->t_type == TXT_WRITE);
	} else {
		rtx = TAILQ_FIRST(replaytxq);
		pfs_tls_set_tx(rtx);
		pfs_meta_lock(mnt);
	}

	starttid = stoptid = -1;
	ntxs = 0;
	TAILQ_FOREACH(rtx, replaytxq, t_next) {
		PFS_ASSERT(rtx->t_type == TXT_REPLAY);
		if (starttid < 0)
			starttid = rtx->t_id;
		stoptid = rtx->t_id;
		ntxs++;
		pfs_tx_replay(rtx);
	}
	PFS_ASSERT(stoptid - starttid + 1 == ntxs);

	if (otx)
		pfs_tls_set_tx(otx);
	else {
		pfs_meta_unlock(mnt);
		pfs_tls_set_tx(NULL);
	}

	err = pfs_log_request(&mnt->mnt_log, LOG_REPLAYDONE, NULL, replaytxq);
	PFS_ASSERT(err == 0 && TAILQ_EMPTY(replaytxq) == true);
	MNT_STAT_END(MNT_STAT_JOURNAL_REPLAY);
}

int
pfs_tx_submit(pfs_tx_t *tx, int err)
{
	pfs_mount_t *mnt = tx->t_mnt;
	struct tx_qhead rplhead;
	int rv;

	PFS_ASSERT(mnt != NULL);
	PFS_ASSERT(tx->t_type == TXT_WRITE);

	if (pfs_tx_empty(tx))
		return err;

	if (err) {
		pfs_tx_rollback(tx);
		return err;
	}

	MNT_STAT_BEGIN();
	TAILQ_INIT(&rplhead);
	rv = pfs_log_request(&mnt->mnt_log, LOG_WRITE, tx, &rplhead);
	MNT_STAT_END_BANDWIDTH(MNT_STAT_TX_WRITE,
	    tx->t_nops * sizeof(pfs_logentry_phy_t));
	if (rv < 0) {
		pfs_tx_rollback(tx);

		if (!TAILQ_EMPTY(&rplhead)) {
			if (pfs_writable(mnt) && pfs_loggable(mnt))
				pfs_etrace("new log entries found, another writer exists!\n");
			pfs_txlist_replay(mnt, &rplhead);
		}

		/*
		 * Most API can be retried safely when tx gets an ETIMEDOUT error.
		 * If t_timeoutfail is set true, which means retry API maybe
		 * dangerous, tx layer should expose original error code to API.
		 */
		if (rv == -ETIMEDOUT && !tx->t_timeoutfail)
			rv = -EAGAIN;
	}
	PFS_ASSERT(TAILQ_EMPTY(&rplhead) == true);
	return rv;
}

pfs_tx_t *
pfs_tx_get(pfs_mount_t *mnt, int type, bool timeoutfail)
{
	pfs_tx_t *tx;

	tx = (pfs_tx_t *)pfs_mem_malloc(sizeof(*tx), M_TX);
	if (tx) {
		memset(tx, 0, sizeof(*tx));
		tx->t_type = type;
		tx->t_mnt = mnt;
		tx->t_id = -1;
		tx->t_done = false;
		tx->t_error = 0;
		tx->t_timeoutfail = timeoutfail;

		tx->t_nops = 0;
		TAILQ_INIT(&tx->t_ops);
		tx->t_opsroot = NULL;
		tx->t_ncbs = 0;
		TAILQ_INIT(&tx->t_cbs);
	}
	PFS_ASSERT(tx != NULL);
	return tx;
}

static void
txop_index_free(void *nodep)
{
	/*
	 * tx->t_opsroot is used as index of txop, do nothing
	 */
}

void
pfs_tx_put(pfs_tx_t *tx)
{
	pfs_txop_t *top;
	pfs_txcb_t *tcb;

	tdestroy(tx->t_opsroot, txop_index_free);

	while ((top = TAILQ_FIRST(&tx->t_ops)) != NULL) {
		TAILQ_REMOVE(&tx->t_ops, top, top_next);
		tx->t_nops--;
		pfs_txop_destroy(top);
	}
	PFS_ASSERT(tx->t_nops == 0);

	while ((tcb = TAILQ_FIRST(&tx->t_cbs)) != NULL) {
		TAILQ_REMOVE(&tx->t_cbs, tcb, tcb_next);
		tx->t_ncbs--;
		pfs_mem_free(tcb, M_TXCB);
	}
	PFS_ASSERT(tx->t_ncbs == 0);

	pfs_mem_free(tx, M_TX);
}

int
pfs_tx_begin(pfs_mount_t *mnt, bool timeoutfail)
{
	pfs_tx_t *tx;

	if (!pfs_writable(mnt))
		ERR_RETVAL(EROFS);

	tx = pfs_tx_get(mnt, TXT_WRITE, timeoutfail);
	pfs_tls_set_tx(tx);
	return 0;
}

int
pfs_tx_end(int err)
{
	pfs_tx_t *tx = pfs_tls_get_tx();

	PFS_ASSERT(tx != NULL && tx->t_type == TXT_WRITE);
	tx->t_done = true;
	if (pfs_loggable(tx->t_mnt))
		err = pfs_tx_submit(tx, err);
	else
		err = pfs_tx_commit(tx);
	pfs_meta_unlock(tx->t_mnt);
	pfs_tls_set_tx(NULL);
	pfs_tx_do_callback(tx, err);

	pfs_tx_put(tx);
	return err;
}

void
pfs_tx_apply(pfs_tx_t *tx)
{
	pfs_txop_t *top;
	pfs_metaobj_phy_t* obj;
	TAILQ_FOREACH(top, &tx->t_ops, top_next) {
		obj = ((pfs_metaobj_phy_t*)(top->top_buf)) + top->top_idx;
		pfs_metaobj_cp(&top->top_remote, obj);
	}
}
