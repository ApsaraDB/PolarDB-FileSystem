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
#include <sys/stat.h>
#include <sys/param.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/fnv_hash.h"

#include "pfs_alloc.h"
#include "pfs_inode.h"
#include "pfs_file.h"
#include "pfs_meta.h"
#include "pfs_mount.h"
#include "pfs_namecache.h"
#include "pfs_dir.h"
#include "pfs_tls.h"
#include "pfs_version.h"
#include "pfs_option.h"
#include "pfs_stat.h"

/*
 * Be carefull! Do not change BLK_TABLE_BLK_CNT without discussion.
 * dblk_cnt use the lowest 4 bits of dblk_vect to save the count.
 * It asserts that malloc/realloc result is 16 aligned in 64 bit platform.
 */

#define BLK_TABLE_BLK_CNT	16l
#define BLK_TABLE_BLK_CNT_MASK	(~(BLK_TABLE_BLK_CNT - 1))
#define	INODE_BLK_TABLE_INC	256l

struct pfs_inode_blk_table {
	union {
		pfs_dblk_t	*dblk_vect;
		struct {
			uint32_t dblk_cnt : 4;
		};
		uintptr_t	dblk_vect_alias;
	};
};

static int64_t du_nblk_limit = 1;
PFS_OPTION_REG(du_nblk_limit, pfs_check_ival_normal);

static const 	pfs_dblk_t zerodblk = { 0, 0, 0 };

static inline void
pfs_dblk_init(pfs_dblk_t *dblk, int64_t blkno, int32_t holeoff, int32_t holelen)
{
	dblk->db_blkno = blkno;
	dblk->db_holeoff = holeoff;
	dblk->db_holelen = holelen;
}

static inline void
pfs_dblk_fini(pfs_dblk_t *dblk)
{
	*dblk = zerodblk;
}

static inline bool
pfs_dblk_empty(pfs_dblk_t *dblk)
{
	return dblk->db_blkno == zerodblk.db_blkno;
}

static inline void
pfs_dblk_change(pfs_dblk_t *dblk, off_t off, ssize_t len)
{
	PFS_ASSERT(dblk->db_blkno > 0);
	dblk->db_holeoff = (int32_t)off;
	dblk->db_holelen = (int32_t)len;
}

static inline off_t
pfs_dblk_holeoff(const pfs_dblk_t *dblk)
{
	PFS_ASSERT(dblk->db_blkno >= 0);
	if (dblk->db_blkno == 0)
		return 0;
	/*
	 * Both db_holelen and db_holeoff are zero in old version.
	 * To be backward-compatible, return an INT_MAX db_holeoff
	 * to caller if db_holelen is zero.
	 */
	return dblk->db_holelen > 0 ? dblk->db_holeoff : INT_MAX;
}

static inline pfs_dblk_t*
pfs_get_dblk_vect(pfs_inode_blk_table_t* table)
{
	return (pfs_dblk_t*)(table->dblk_vect_alias & BLK_TABLE_BLK_CNT_MASK);
}

static void
pfs_inode_blk_table_free_blkvec(pfs_inode_blk_table_t *blk_table)
{
	pfs_mem_free(pfs_get_dblk_vect(blk_table), M_DBLKV);
	blk_table->dblk_vect = NULL;
	blk_table->dblk_cnt = 0;
}

static inline int64_t
pfs_inode_blk_table_idx(const pfs_blkid_t blkid)
{
	return blkid / BLK_TABLE_BLK_CNT;
}

static inline int64_t
pfs_inode_blk_vec_idx(const pfs_blkid_t blkid)
{
	return blkid % BLK_TABLE_BLK_CNT;
}

static pfs_inode_blk_table_t*
pfs_inode_blk_table_get(const pfs_inode_t *in, const pfs_blkid_t blkid)
{
	int idx;
	PFS_ASSERT(blkid >= 0);
	idx = pfs_inode_blk_table_idx(blkid);
	if (idx >= in->in_blk_table_nsoft)
		return NULL;

	return in->in_blk_tables + idx;
}

static void
pfs_inode_realloc_blk_table(pfs_inode_t *in, int64_t expect)
{
	if (expect > 1)
		expect = roundup(expect, INODE_BLK_TABLE_INC);
	if (in->in_blk_table_nhard == expect)
		return;
	in->in_blk_tables = (pfs_inode_blk_table_t *)pfs_mem_realloc(
	    in->in_blk_tables, expect * sizeof(pfs_inode_blk_table_t),
	    M_INODE_BLK_TABLE);
	if (in->in_blk_table_nhard < expect)
		memset(in->in_blk_tables + in->in_blk_table_nhard, 0,
		    sizeof(pfs_inode_blk_table_t) * (expect - in->in_blk_table_nhard));
	in->in_blk_table_nhard = expect;
}

static void
pfs_inode_tryremove_blk_table(pfs_inode_t *in, pfs_inode_blk_table_t* blk_table)
{
	int64_t table_idx = blk_table - in->in_blk_tables;
	PFS_ASSERT(table_idx >= 0 && table_idx < in->in_blk_table_nsoft);
	if (blk_table->dblk_cnt == 0) {
		pfs_inode_blk_table_free_blkvec(blk_table);
		if (table_idx == in->in_blk_table_nsoft - 1) {
			for (--table_idx; table_idx >= 0 &&
			    !in->in_blk_tables[table_idx].dblk_vect;)
				--table_idx;
			in->in_blk_table_nsoft = table_idx + 1;
			pfs_inode_realloc_blk_table(in, in->in_blk_table_nsoft);
		}
	}
}

static void
pfs_inode_remove_blk(pfs_inode_t *in, pfs_blkid_t blkid)
{
	pfs_inode_blk_table_t *blk_table = pfs_inode_blk_table_get(in, blkid);
	pfs_dblk_t *blk;
	if (!blk_table || !blk_table->dblk_vect)
		return;
	blk = pfs_get_dblk_vect(blk_table) + pfs_inode_blk_vec_idx(blkid);
	if (!pfs_dblk_empty(blk)) {
		--blk_table->dblk_cnt;
		pfs_dblk_fini(blk);
	}
	pfs_inode_tryremove_blk_table(in, blk_table);
}

static void
pfs_inode_trycreate_blkvec(pfs_inode_blk_table_t *blk_table)
{
	int i;
	if (blk_table->dblk_vect)
		return;

	blk_table->dblk_vect = (pfs_dblk_t *)pfs_mem_malloc(
	    BLK_TABLE_BLK_CNT * sizeof(pfs_dblk_t), M_DBLKV);

	for (i = 0; i < BLK_TABLE_BLK_CNT; i++)
		pfs_dblk_fini(&blk_table->dblk_vect[i]);
}

static pfs_inode_blk_table_t *
pfs_inode_tryadd_blk_table(pfs_inode_t *in, pfs_blkid_t blkid)
{
	int64_t blk_table_idx;
	pfs_inode_blk_table_t *result;

	blk_table_idx = pfs_inode_blk_table_idx(blkid);
	if (in->in_blk_table_nsoft <= blk_table_idx) {
		in->in_blk_table_nsoft = blk_table_idx + 1;
		pfs_inode_realloc_blk_table(in, in->in_blk_table_nsoft);
	}
	result = in->in_blk_tables + blk_table_idx;
	pfs_inode_trycreate_blkvec(result);
	return result;
}

static pfs_dblk_t*
pfs_inode_add_blk(pfs_inode_t *in, pfs_blkid_t blkid)
{
	pfs_inode_blk_table_t *blk_table = pfs_inode_tryadd_blk_table(in, blkid);
	pfs_dblk_t* result = NULL;
	int idx = pfs_inode_blk_vec_idx(blkid);
	result = &pfs_get_dblk_vect(blk_table)[idx];
	if (pfs_dblk_empty(result))
		++blk_table->dblk_cnt;
	return result;
}

static pfs_dblk_t*
pfs_inode_get_blk(const pfs_inode_t *in, const pfs_blkid_t blkid)
{
	pfs_inode_blk_table_t *blk_table = NULL;
	int idx;

	blk_table = pfs_inode_blk_table_get(in, blkid);
	if (!blk_table || !blk_table->dblk_vect)
		return NULL;

	idx = pfs_inode_blk_vec_idx(blkid);
	return &pfs_get_dblk_vect(blk_table)[idx];
}

static int
pfs_inode_check_stale(pfs_inode_phy_t *phyin, pfs_inode_t *in)
{
	//Following order and priority is very important:
	//ENOENT always has higher returning priority because when
	//in->in_btime != phyin->in_btime, the error can not be handled via
	//reload in and it will not happen in pfs_inode_sync for the
	//re-allocated inode.

	if (phyin && phyin->in_type == PFS_INODET_NONE)
		ERR_RETVAL(ENOENT);
	if (phyin && in && in->in_btime != phyin->in_btime)
		ERR_RETVAL(ENOENT);
	if (in && (in->in_stale || in->in_sync_ver < in->in_rpl_ver))
		ERR_RETVAL(EAGAIN);
	return 0;
}

static int
pfs_inode_phy_get(pfs_mount_t* mnt, pfs_inode_t *in, pfs_inode_phy_t **pphyin,
    pfs_ino_t ino, pfs_txop_t *top)
{
	int err;
	bool rpl_lock_op = in && (!pfs_meta_islocked(mnt));
	pfs_inode_phy_t *phyin;

	if (rpl_lock_op)
		rpl_lock_op &= pfs_inode_rpl_unlock(in);
	phyin = pfs_meta_get_inode(mnt, ino, top);

	if (rpl_lock_op)
		pfs_inode_rpl_lock(in);
	err = pfs_inode_check_stale(phyin, in);
	if (err == 0 && pphyin)
		*pphyin = phyin;
	return err;
}

int
pfs_inode_phy_check(pfs_inode_t *in)
{
	return pfs_inode_phy_get(in->in_mnt, in, NULL, in->in_ino, NULL);
}

void
pfs_inode_mark_stale(pfs_inode_t *in)
{
	__atomic_store_n(&in->in_stale, true, __ATOMIC_RELEASE);
}

static void
pfs_inode_del_committed(pfs_mount_t *mnt, pfs_metaobj_phy_t *mo, int err)
{
	pfs_blktag_phy_t *bt = MO2BT(mo);
	pfs_inode_t *in;

	in = pfs_get_inode(mnt, bt->bt_ino);
	PFS_ASSERT(in != NULL);
	pfs_inode_lock(in);

	PFS_ASSERT(in->in_nblk_ip < 0);
	if (++in->in_nblk_ip == 0)
		cond_broadcast(&in->in_cond);

	pfs_inode_unlock(in);
	pfs_put_inode(mnt, in);
}

static int
pfs_inode_del(pfs_inode_t *in, pfs_dblk_t *dblk)
{
	int err = 0;
	pfs_blktag_phy_t *bt;
	pfs_inode_phy_t *phyin;
	pfs_txop_t *bttop, *phyintop;
	pfs_mount_t *mnt = in->in_mnt;
	pfs_blkno_t blkno = dblk->db_blkno;
	uint64_t btno;
	pfs_tx_t *tx = pfs_tls_get_tx();

	if ((err = pfs_tx_new_op(tx, bttop)) < 0 ||
		(err = pfs_tx_new_op(tx, phyintop)) < 0) {
		return err;
	}

	err = pfs_inode_phy_get(mnt, in, &phyin, in->in_ino, phyintop);
	if (err < 0)
		return err;
	btno = blkno2btno(mnt, blkno);
	bt = pfs_meta_get_blktag(mnt, btno, bttop);
	PFS_ASSERT(GETMO(bt)->mo_number == btno);
	err = pfs_meta_list_delete(mnt, GETMO(phyin), GETMO(bt));
	if (err < 0)
		return err;
	pfs_meta_free_blktag(mnt, bt, NULL);
	phyin->in_nblock--;

	in->in_nblk_ip--;
	pfs_inode_sync_blk_meta(in, bt);
	pfs_tx_done_op_callback(tx, bttop, pfs_inode_del_committed);
	pfs_tx_done_op(tx, phyintop);
	return 0;
}

int
pfs_inode_del_from(pfs_inode_t *in, pfs_blkid_t from)
{
	int err;
	int64_t idx, table_idx;
	pfs_dblk_t *dblk;

	PFS_ASSERT(in->in_type == PFS_INODET_FILE);
	for (table_idx = pfs_inode_blk_table_idx(from);
	    table_idx < in->in_blk_table_nsoft; ++table_idx) {
		for (idx = pfs_inode_blk_vec_idx(from); idx < BLK_TABLE_BLK_CNT;
		    ++idx, ++from) {
			dblk = pfs_inode_get_blk(in, from);
			if (dblk == NULL || pfs_dblk_empty(dblk))
				continue;
			err = pfs_inode_del(in, dblk);
			if (err < 0)
				return err;
		}
	}
	return 0;
}

static void
pfs_inode_init_blktable(pfs_inode_t *in)
{
	in->in_blk_tables = NULL;
	in->in_blk_table_nsoft = 0;
	in->in_blk_table_nhard = 0;
}

static void
pfs_inode_create_blktable(pfs_inode_t *in, int64_t blkcnt)
{
	int64_t ntable = blkcnt / BLK_TABLE_BLK_CNT;
	PFS_ASSERT(in->in_blk_tables == NULL);
	if (ntable > 0)
		pfs_inode_realloc_blk_table(in, ntable);
	in->in_blk_table_nsoft = 0;
}

static void
pfs_inode_destroy_blk_table(pfs_inode_t *in)
{
	int i;

	for (i = 0; i < in->in_blk_table_nsoft; i++)
		pfs_inode_blk_table_free_blkvec(&in->in_blk_tables[i]);

	pfs_mem_free(in->in_blk_tables, M_INODE_BLK_TABLE);
	in->in_blk_tables = NULL;
	in->in_blk_table_nsoft = 0;
	in->in_blk_table_nhard = 0;
}

static void
pfs_inode_add_committed(pfs_mount_t *mnt, pfs_metaobj_phy_t *mo, int err)
{
	pfs_blktag_phy_t *bt;
	pfs_inode_t *in;

	bt = MO2BT(mo);

	in = pfs_get_inode(mnt, bt->bt_ino);
	PFS_ASSERT(in != NULL);
	pfs_inode_lock(in);

	PFS_ASSERT(in->in_nblk_ip > 0);
	if (--in->in_nblk_ip == 0) {
		cond_broadcast(&in->in_cond);
	}

	pfs_inode_unlock(in);
	pfs_put_inode(mnt, in);
}

int
pfs_inode_add(pfs_inode_t *in, pfs_blkid_t blkid)
{
	int err;
	pfs_blktag_phy_t *bt;
	pfs_inode_phy_t *phyin;
	pfs_txop_t *bttop, *phyintop;
	pfs_tx_t *tx = pfs_tls_get_tx();

	err = 0;
	if ((err = pfs_tx_new_op(tx, bttop)) < 0 ||
		(err = pfs_tx_new_op(tx, phyintop)) < 0) {
		return err;
	}

	err = pfs_inode_phy_get(in->in_mnt, in, &phyin, in->in_ino, phyintop);
	if (err < 0)
		return err;

	bt = pfs_meta_alloc_blktag(in->in_mnt, bttop);
	if (bt == NULL)
		ERR_RETVAL(ENOSPC);
	bt->bt_ino = in->in_ino;
	bt->bt_blkid = blkid;

	err = pfs_meta_list_insert(in->in_mnt, GETMO(phyin), GETMO(bt));
	if (err < 0)
		return err;
	phyin->in_nblock++;

	in->in_nblk_ip++;
	pfs_inode_sync_blk_meta(in, bt);

	pfs_tx_done_op_callback(tx, bttop, pfs_inode_add_committed);
	pfs_tx_done_op(tx, phyintop);
	return 0;
}

static void
pfs_inode_set_callback(pfs_inode_t *in, pfs_tx_callback_t *txcb)
{
	pfs_tx_t *tx = pfs_tls_get_tx();

	PFS_ASSERT(in->in_cbdone == true);
	pfs_tx_add_callback(tx, txcb, in->in_ino);
	in->in_cbdone = false;
}

static void
pfs_inode_modify_dblk_hole_done(pfs_mount_t *mnt, pfs_metaobj_phy_t *mo, int err)
{
	pfs_blktag_phy_t *bt;
	pfs_inode_t *in;

	bt = MO2BT(mo);
	in = pfs_get_inode(mnt, bt->bt_ino);
	PFS_ASSERT(in != NULL);
	pfs_inode_lock(in);

	PFS_ASSERT(in->in_nblk_modify > 0);
	if (--in->in_nblk_modify == 0)
		cond_broadcast(&in->in_cond);

	pfs_inode_unlock(in);
	pfs_put_inode(mnt, in);
}

static void
pfs_inode_modify_dblk_hole(pfs_inode_t *in, pfs_dblk_t *dblk)
{
	pfs_mount_t *mnt = in->in_mnt;
	pfs_tx_t *tx = pfs_tls_get_tx();
	pfs_blktag_phy_t *bt;
	pfs_txop_t *bttop;
	int err;
	uint64_t btno;

	PFS_ASSERT(pfs_version_has_features(mnt, PFS_FEATURE_BLKHOLE));
	PFS_ASSERT(dblk->db_holeoff + dblk->db_holelen == (int32_t)mnt->mnt_blksize);

	err = pfs_tx_new_op(tx, bttop);
	PFS_ASSERT(err == 0);
	btno = blkno2btno(mnt, dblk->db_blkno);
	bt = pfs_meta_get_blktag(mnt, btno, bttop);
	bt->bt_holeoff = dblk->db_holeoff;
	bt->bt_holelen = dblk->db_holelen;
	pfs_tx_done_op_callback(tx, bttop, pfs_inode_modify_dblk_hole_done);

	in->in_nblk_modify++;
}

void
pfs_inode_expand_dblk_hole(pfs_inode_t *in, pfs_blkid_t blkid, off_t newbhoff,
    int32_t newbhlen)
{
	pfs_dblk_t *dblk;

	PFS_ASSERT(newbhoff + newbhlen == in->in_mnt->mnt_blksize);

	dblk = pfs_inode_get_blk(in, blkid);
	PFS_ASSERT(dblk->db_blkno > 0);
	PFS_ASSERT(newbhoff < pfs_dblk_holeoff(dblk));
	pfs_dblk_change(dblk, newbhoff, newbhlen);
	pfs_inode_modify_dblk_hole(in, dblk);
}

void
pfs_inode_shrink_dblk_hole(pfs_inode_t *in, pfs_blkid_t blkid, off_t newbhoff,
    int32_t newbhlen)
{
	pfs_dblk_t *dblk;

	PFS_ASSERT(newbhoff + newbhlen == in->in_mnt->mnt_blksize);

	dblk = pfs_inode_get_blk(in, blkid);
	PFS_ASSERT(dblk->db_blkno > 0);
	PFS_ASSERT(newbhoff > pfs_dblk_holeoff(dblk));
	pfs_dblk_change(dblk, newbhoff, newbhlen);
	pfs_inode_modify_dblk_hole(in, dblk);
}

static void
pfs_inode_writemodify_init(pfs_writemodify_t *wm)
{
	PFS_ASSERT(wm->wm_dblkv == NULL);
	PFS_ASSERT(wm->wm_dblki == 0);
	PFS_ASSERT(wm->wm_dblkn == 0);
	PFS_ASSERT(wm->wm_sizeinc == 0);
	PFS_ASSERT(wm->wm_thread == 0);
}

static void
pfs_inode_writemodify_fini(pfs_writemodify_t *wm)
{
	pfs_mem_free(wm->wm_dblkv, M_DBLKV);
	wm->wm_dblkv = NULL;
	wm->wm_dblki = 0;
	wm->wm_dblkn = 0;
	wm->wm_sizeinc = 0;
	wm->wm_thread = 0;
}

static inline bool
pfs_inode_writemodify_inprogress(const pfs_writemodify_t *wm)
{
	return (wm->wm_dblkv || wm->wm_sizeinc);
}

void
pfs_inode_writemodify_shrink_dblk_hole(pfs_inode_t *in, pfs_blkid_t blkid,
    off_t newbhoff, int32_t newbhlen)
{
	pfs_mount_t *mnt = in->in_mnt;
	pfs_writemodify_t *wm = &in->in_write_modify;
	pthread_t tid = pthread_self();
	pfs_dblk_t *dblk;

	PFS_ASSERT(pfs_version_has_features(mnt, PFS_FEATURE_BLKHOLE));
	PFS_ASSERT(newbhoff + newbhlen == in->in_mnt->mnt_blksize);
	PFS_ASSERT(wm->wm_thread == 0 || wm->wm_thread == tid);

	dblk = pfs_inode_get_blk(in, blkid);
	pfs_dblk_change(dblk, newbhoff, newbhlen);

	if (wm->wm_dblkv == NULL || wm->wm_dblki >= wm->wm_dblkn) {
		wm->wm_dblkn += 8;
		void *tmp = pfs_mem_realloc(wm->wm_dblkv,
		    wm->wm_dblkn * sizeof(pfs_dblk_t), M_DBLKV);
		PFS_VERIFY(tmp != NULL);
		wm->wm_dblkv = (pfs_dblk_t *)tmp;
	}

	PFS_ASSERT(0 <= wm->wm_dblki && wm->wm_dblki < wm->wm_dblkn);
	wm->wm_dblkv[wm->wm_dblki++] = *dblk;
	wm->wm_thread = tid;
}

void
pfs_inode_writemodify_increment_size(pfs_inode_t *in, int64_t sizeinc)
{
	pfs_writemodify_t *wm = &in->in_write_modify;
	pthread_t tid = pthread_self();

	PFS_ASSERT(sizeinc > 0 && sizeinc >= wm->wm_sizeinc);
	PFS_ASSERT(wm->wm_thread == 0 || wm->wm_thread == tid);

	wm->wm_sizeinc = sizeinc;
	wm->wm_thread = tid;
}

int
pfs_inode_writemodify_commit(pfs_inode_t *in)
{
	pfs_writemodify_t *wm = &in->in_write_modify;
	pfs_dblk_t *dblk;
	int err;

	if (!pfs_inode_writemodify_inprogress(wm))
	       return 0;

	/*
	 * Only the owner thread can commit the writemodify.
	 */
	if (wm->wm_thread != pthread_self())
		return 0;
	/*
	 * The variables in_nblk_modify and in_size/in_size2
	 * must satisfy the assertion below. wrtiemodify_commit()
	 * will relegate its modified info to them, through
	 * inode_modify_dblk_hole() and inode_chage(). After that,
	 * write modify is done. However, other threads have to
	 * wait until in_nblk_modify and in_size/in_size2 are
	 * set as the assertion below.
	 */
	PFS_ASSERT(wm->wm_thread == pthread_self());
	PFS_ASSERT(in->in_nblk_modify == 0);
	PFS_ASSERT(in->in_size == in->in_size2);

	/*
	 * Even if pfs_inode_change() may return error, it is still
	 * OK. In that case, tx would be non empty. Then the inode
	 * would be set as stale when undoing metadata change in
	 * pfs_tx_rollback(). At last the inode would be reloaded
	 * by another thread.
	 */
	PFS_ASSERT(wm->wm_dblki <= wm->wm_dblkn);
	if (wm->wm_dblkv) {
		err = pfs_inode_phy_check(in);
		/*
		 * Here we need to mark inode stale, because inode blk idx may 
		 * change.
		 */
		if (err) {
			pfs_inode_mark_stale(in);
			goto fini;
		}

		for (int i = 0; i < wm->wm_dblki; i++) {
			dblk = &wm->wm_dblkv[i];
			pfs_inode_modify_dblk_hole(in, dblk);
		}
	} else {
		PFS_ASSERT(wm->wm_dblkv == NULL);
		PFS_ASSERT(wm->wm_dblki == 0);
		PFS_ASSERT(wm->wm_dblkn == 0);
	}

	/*
	 * inode must be modified and added into tx by force except
	 * that current inode is already stale for 2 reasons:
	 * 1. If we only change blktags, other PFS processes will not
	 * be notified the staleness of inode.
	 * 2. If we want to cancel writemodify, we still need to
	 * involve physical inode in tx to set inode stale.
	 */
	err = pfs_inode_change(in, wm->wm_sizeinc, true);

fini:
	/*
	 * Clear write modify info since they are relegated to in_nblk_modify
	 * and/or in_size/in_size2, if the above calls are successfull.
	 *
	 * All waiting thread should be notified in case pfs_inode_change()
	 * failed, because there may be no callback to notify them if
	 * pfs_inode_change() failed.
	 */
	pfs_inode_writemodify_fini(wm);
	cond_broadcast(&in->in_cond);
	return err;
}

/*
 * pfs_inode_map:
 *
 *	Get the device block number for the file @offset. The return
 *	value is
 *	> 0 for valid mapped blocks,
 *	= 0 for hole blocks
 *
 * 	NOTE:
 *	If there is read tx when a write tx is still in progress,
 *	the read tx may get stale data.
 */
void
pfs_inode_map(pfs_inode_t *in, pfs_blkid_t blkid, pfs_blkno_t *dblkno,
    off_t *dbhoff)
{
	pfs_dblk_t *dblk;
	dblk = pfs_inode_get_blk(in, blkid);
	if (dblk) {
		*dblkno = dblk->db_blkno;
		*dbhoff = pfs_dblk_holeoff(dblk);
	} else {
		*dblkno = 0;
		*dbhoff = 0;
	}
}

typedef struct pfs_dxent {
	pfs_avl_node_t	e_avlnode;

	uint32_t	e_nmhash;
	pfs_ino_t	e_ino;
	pfs_inode_t	*e_in;		/* maintain the existence of child inode */
	struct pfs_dxent *e_next;	/* subfile with same hash */
} pfs_dxent_t;

static inline uint32_t
dx_calc_hash(const char *name)
{
	return fnv_32_buf(name, strlen(name), FNV1_32_INIT);
}

static int
pfs_inode_dx_compare(const void *keya, const void *keyb)
{
	pfs_dxent_t *e1 = (pfs_dxent_t *)keya;
	pfs_dxent_t *e2 = (pfs_dxent_t *)keyb;

	if (e1->e_nmhash > e2->e_nmhash)
		return 1;
	if (e1->e_nmhash < e2->e_nmhash)
		return -1;
	return 0;
}

static void
pfs_inode_dx_add(pfs_mount_t *mnt, pfs_avl_tree_t *dxroot, uint32_t nmhash,
    pfs_ino_t ino, bool isdir)
{
	pfs_dxent_t *ent, *first;

	/* alloc dx entry and reference mem-inode */
	ent = (pfs_dxent_t *)pfs_mem_malloc(sizeof(*ent), M_DXENT);
	PFS_VERIFY(ent != NULL);
	ent->e_nmhash = nmhash;
	ent->e_ino = ino;
	ent->e_in = isdir ? pfs_inode_get(mnt, ino) : NULL;
	ent->e_next = NULL;

	first = (pfs_dxent_t *)pfs_avl_find(dxroot, ent, NULL);
	if (first == NULL) {
		pfs_avl_add(dxroot, ent);
	} else {
		// XXX for convenience, we do not append to tail
		ent->e_next = first->e_next;
		first->e_next = ent;
	}
}

static void
pfs_inode_dx_del(pfs_avl_tree_t *dxroot, uint32_t nmhash, pfs_ino_t ino, bool isdir)
{
	pfs_dxent_t fent, *ent, *first, *prev;

	fent.e_nmhash = nmhash;
	first = (pfs_dxent_t *)pfs_avl_find(dxroot, &fent, NULL);
	for (prev = NULL, ent = first; ent != NULL; ent = ent->e_next) {
		if (ent->e_ino == ino)
			break;
		prev = ent;
	}
	PFS_ASSERT(ent != NULL);

	if (ent == first) {
		pfs_avl_remove(dxroot, ent);
		/* tree updated here and do not use pfs_avl_insert */
		if (ent->e_next != NULL)
			pfs_avl_add(dxroot, ent->e_next);
	} else {
		PFS_ASSERT(prev != NULL && prev->e_next == ent);
		prev->e_next = ent->e_next;
	}

	/* dereference mem-inode and free dx entry */
	if (isdir)
		pfs_inode_put(ent->e_in);
	pfs_mem_free(ent, M_DXENT);
}

static void
pfs_inode_dx_del_self(pfs_avl_tree_t *dxroot, uint32_t nmhash, pfs_ino_t ino, bool isdir)
{
	pfs_dxent_t fent, *ent, *first, *prev;

	fent.e_nmhash = nmhash;
	first = (pfs_dxent_t *)pfs_avl_find(dxroot, &fent, NULL);
	for (prev = NULL, ent = first; ent != NULL; ent = ent->e_next) {
		if (ent->e_ino == ino)
			break;
		prev = ent;
	}
	PFS_ASSERT(ent != NULL);

	if (ent == first) {
		pfs_avl_remove(dxroot, ent);
		/* tree updated here and do not use pfs_avl_insert */
		if (ent->e_next != NULL)
			pfs_avl_add(dxroot, ent->e_next);
	} else {
		PFS_ASSERT(prev != NULL && prev->e_next == ent);
		prev->e_next = ent->e_next;
	}

	/* dereference mem-inode and free dx entry */
	/* XXX only difference, do not follow inode ptr reference
	if (isdir)
		pfs_inode_put(ent->e_in);
		*/
	pfs_mem_free(ent, M_DXENT);
}


static int
pfs_inode_dx_find(pfs_mount_t *mnt, pfs_avl_tree_t *dxroot, const char *name,
    pfs_ino_t *tgtinop, uint64_t *denop, int *typep, uint64_t *btimep)
{
	pfs_dxent_t fent, *ent, *first;
	pfs_direntry_phy_t *de;
	pfs_inode_phy_t *phyin;
	char nm[PFS_MAX_NAMELEN];

	fent.e_nmhash = dx_calc_hash(name);
	first = (pfs_dxent_t *)pfs_avl_find(dxroot, &fent, NULL);
	for (ent = first; ent != NULL; ent = ent->e_next) {
		phyin = pfs_meta_get_inode(mnt, ent->e_ino, NULL);
		de = pfs_meta_get_direntry(mnt, phyin->in_deno, NULL);
		pfs_direntry_getname(mnt, de, nm, sizeof(nm));
		if (strcmp(name, nm) == 0) {
			*tgtinop = ent->e_ino;
			*denop = phyin->in_deno;
			if (typep)
				*typep = phyin->in_type;
			if (btimep)
				*btimep = phyin->in_btime;
			return 0;
		}
	}

	return -ENOENT;
}

static void
pfs_inode_dxredo_init(pfs_dxredo_t *dxr)
{
	PFS_ASSERT(dxr->r_thread == 0);
	PFS_ASSERT(dxr->r_cnt == 0);
}

static void
pfs_inode_dxredo_fini(pfs_dxredo_t *dxr)
{
	memset(dxr, 0, sizeof(*dxr));
	dxr->r_thread = 0;
	dxr->r_cnt = 0;
}

static void
pfs_inode_dxredo_record(pfs_dxredo_t *dxr, int op, const char *name,
    pfs_ino_t ino, bool isdir)
{
	struct dxredo_rec *rec;
	pthread_t tid = pthread_self();

	/* the ADD/DEL of directory tree within a tx is limited */
	PFS_ASSERT(dxr->r_cnt < DXR_MAX_NREC);
	PFS_ASSERT(dxr->r_thread == 0 || dxr->r_thread == tid);

	rec = &dxr->r_rec[dxr->r_cnt];
	rec->rr_op = op;
	rec->rr_nmhash = dx_calc_hash(name);
	rec->rr_ino = ino;
	rec->rr_isdir = isdir;

	dxr->r_thread = tid;
	dxr->r_cnt++;
}

static inline bool
pfs_inode_dxredo_inprogress(const pfs_dxredo_t *dxr)
{
	return (dxr->r_cnt > 0);
}

static void
pfs_inode_dxredo_apply(pfs_inode_t *dirin)
{
	pfs_dxredo_t *dxr = &dirin->in_dx_redo;
	struct dxredo_rec *rec;
	ssize_t szdelta;

	PFS_ASSERT(dxr->r_thread == pthread_self());

	szdelta = 0;
	for (int i = 0; i < dxr->r_cnt; i++) {

		/*
		 * Apply changes on dir index, failure is unacceptable
		 * since meta is committed.
		 */
		rec = &dxr->r_rec[i];
		switch (rec->rr_op) {
		case DXOP_ADD:
			pfs_inode_dx_add(dirin->in_mnt, &dirin->in_dx_root,
			    rec->rr_nmhash, rec->rr_ino, rec->rr_isdir);
			szdelta += sizeof(pfs_metaobj_phy_t);
			break;

		case DXOP_DEL:
			pfs_inode_dx_del(&dirin->in_dx_root,
			    rec->rr_nmhash, rec->rr_ino, rec->rr_isdir);
			szdelta -= sizeof(pfs_metaobj_phy_t);
			break;

		default:
			pfs_etrace("invalid dxredo op %d\n", rec->rr_op);
			PFS_ASSERT("unsupported dxredo op" == NULL);
		}
	}

	dirin->in_size += szdelta;
	dirin->in_size2 += szdelta;
}

static void
pfs_inode_dir_update_done(pfs_mount_t *mnt, pfs_ino_t ino, int err)
{
	pfs_inode_t *in;

	in = pfs_get_inode(mnt, ino);
	PFS_ASSERT(in != NULL);
	pfs_inode_lock(in);
	PFS_ASSERT(in->in_cbdone == false);

	if (err == 0)
		pfs_inode_dxredo_apply(in);
	pfs_inode_dxredo_fini(&in->in_dx_redo);

	in->in_cbdone = true;
	cond_broadcast(&in->in_cond);
	pfs_inode_unlock(in);
	pfs_put_inode(mnt, in);
}

int
pfs_inode_dir_add(pfs_inode_t *dirin, const char *name, bool isdir,
    pfs_ino_t *inop, uint64_t *btimep)
{
	pfs_mount_t *mnt = dirin->in_mnt;
	pfs_ino_t ino;
	int err;
	uint64_t btime;

	PFS_ASSERT(pfs_meta_islocked(mnt));
	err = pfs_inode_check_stale(NULL, dirin);
	if (err < 0)
		return err;

	err = pfs_dir_add(mnt, dirin->in_ino, name, isdir, &ino, &btime);
	if (err < 0)
		return err;

	*inop = ino;
	*btimep = btime;
	pfs_inode_dxredo_record(&dirin->in_dx_redo, DXOP_ADD, name, ino, isdir);
	pfs_inode_set_callback(dirin, pfs_inode_dir_update_done);
	return 0;
}

int
pfs_inode_dir_find(pfs_inode_t *dirin, const char *name, pfs_ino_t *tgtinop,
    int *typep, uint64_t *btimep)
{
	pfs_mount_t *mnt = dirin->in_mnt;
	pfs_inode_phy_t *phyin;
	uint64_t deno;
	int err;

	PFS_ASSERT(pfs_meta_islocked(mnt));
	err = pfs_namecache_lookup(mnt, dirin->in_ino, name, tgtinop);
	if (err < 0 && err != -ENOENT) {
		return err;
	}
	if (err == 0) {
		phyin = pfs_meta_get_inode(mnt, *tgtinop, NULL);
		if (typep)
			*typep = phyin->in_type;
		if (btimep)
			*btimep = phyin->in_btime;
		return 0;
	}

	err = pfs_inode_check_stale(NULL, dirin);
	if (err < 0)
		return err;

	err = pfs_inode_dx_find(mnt, &dirin->in_dx_root, name, tgtinop,
	    &deno, typep, btimep);
	if (err < 0)
		return err;

	pfs_namecache_enter(mnt, dirin->in_ino, *tgtinop, name, deno);
	return 0;
}

int
pfs_inode_dir_del(pfs_inode_t *dirin, pfs_ino_t ino, const char *name,
    bool isdir)
{
	pfs_mount_t *mnt = dirin->in_mnt;
	int err;

	PFS_ASSERT(pfs_meta_islocked(mnt));
	// Removing root dir is not allowed.
	if (ino == 0)
		ERR_RETVAL(EINVAL);

	err = pfs_inode_check_stale(NULL, dirin);
	if (err < 0)
		return err;

	err = pfs_dir_del(mnt, dirin->in_ino, ino, name, isdir);
	if (err < 0)
		return err;

	pfs_inode_dxredo_record(&dirin->in_dx_redo, DXOP_DEL, name, ino, isdir);
	pfs_inode_set_callback(dirin, pfs_inode_dir_update_done);
	return 0;
}

int
pfs_inode_dir_rename(pfs_mount_t *mnt, bool isdir,
    pfs_inode_t *odirin, pfs_ino_t oino, const char *oldname,
    pfs_inode_t *ndirin, pfs_ino_t nino, const char *newname)
{
	int err;

	PFS_ASSERT(pfs_meta_islocked(mnt));
	if (oino == 0 || nino == 0)
		ERR_RETVAL(EBUSY);
	if (oino == nino)
		return 0;		/* dont rename the same path */

	err = pfs_inode_check_stale(NULL, odirin);
	if (err < 0)
		return err;
	err = pfs_inode_check_stale(NULL, ndirin);
	if (err < 0)
		return err;

	err = pfs_dir_rename(mnt, odirin->in_ino, oino, oldname,
	    ndirin->in_ino, nino, newname);
	if (err < 0)
		return err;

	if (nino != INVALID_INO) {
		pfs_inode_dxredo_record(&ndirin->in_dx_redo, DXOP_DEL,
		    newname, nino, isdir);
	}
	pfs_inode_dxredo_record(&odirin->in_dx_redo, DXOP_DEL, oldname,
	    oino, isdir);
	pfs_inode_dxredo_record(&ndirin->in_dx_redo, DXOP_ADD, newname,
	    oino, isdir);

	pfs_inode_set_callback(odirin, pfs_inode_dir_update_done);
	if (ndirin != odirin)
		pfs_inode_set_callback(ndirin, pfs_inode_dir_update_done);
	return 0;
}

static void
pfs_inode_destroy_findex(pfs_inode_t *in)
{
	pfs_inode_destroy_blk_table(in);
}

static void
pfs_inode_destroy_dindex(pfs_inode_t *in)
{
	pfs_dxent_t *ent;
	while (!pfs_avl_is_empty(&in->in_dx_root)) {
		ent = (pfs_dxent_t *)pfs_avl_first(&in->in_dx_root);
		pfs_inode_dx_del(&in->in_dx_root, ent->e_nmhash, ent->e_ino,
		    ent->e_in != NULL);
	}
	pfs_avl_destroy(&in->in_dx_root);
}

static void
pfs_inode_destroy_dindex_self(pfs_inode_t *in)
{
	pfs_dxent_t *ent;
	while (!pfs_avl_is_empty(&in->in_dx_root)) {
		ent = (pfs_dxent_t *)pfs_avl_first(&in->in_dx_root);
		pfs_inode_dx_del_self(&in->in_dx_root, ent->e_nmhash, ent->e_ino,
		    ent->e_in != NULL);	// XXX only difference
	}
	pfs_avl_destroy(&in->in_dx_root);
}

static inline void
pfs_inode_destroy_index(pfs_inode_t *in)
{
	switch (in->in_type) {
	case PFS_INODET_FILE:
		pfs_inode_destroy_findex(in);
		break;

	case PFS_INODET_DIR:
		pfs_inode_destroy_dindex(in);
		break;

	default:
		/* maybe first reload */
		;
	}
}

static inline void
pfs_inode_destroy_index_self(pfs_inode_t *in)
{
	switch (in->in_type) {
	case PFS_INODET_FILE:
		pfs_inode_destroy_findex(in);
		break;

	case PFS_INODET_DIR:
		pfs_inode_destroy_dindex_self(in);	// XXX only difference
		break;

	default:
		/* maybe first reload */
		;
	}
}

static void
pfs_inode_build_findex(pfs_inode_t *in)
{
	pfs_mount_t *mnt = in->in_mnt;
	pfs_inode_phy_t *phyin = in->in_phyin;
	pfs_blktag_phy_t *bt;
	uint64_t btno;
	uint64_t blkcnt = 0;

	pfs_inode_create_blktable(in, phyin->in_nblock);
	for (btno = MONO_FIRST(phyin); btno != 0; btno = MONO_NEXT(bt)) {
		bt = pfs_meta_get_blktag(mnt, btno, NULL);
		PFS_ASSERT(bt->bt_ino == in->in_ino);
		PFS_ASSERT(bt->bt_blkid >= 0);
		pfs_inode_sync_blk_meta(in, bt);
		blkcnt++;
	}
	PFS_ASSERT(blkcnt == IN_FIELD(in, in_nblock));
	(void)blkcnt;
}

static void
pfs_inode_build_dindex(pfs_inode_t *in)
{
	pfs_mount_t *mnt = in->in_mnt;
	pfs_inode_phy_t *dphyin, *phyin;
	pfs_direntry_phy_t *de;
	uint64_t deno;
	char name[PFS_MAX_NAMELEN];
	uint32_t nmhash;

	dphyin = pfs_meta_get_inode(mnt, in->in_ino, NULL);

	for (deno = MONO_FIRST(dphyin); MONO_VALID(deno); deno = MONO_NEXT(de)) {
		de = pfs_meta_get_direntry(mnt, deno, NULL);
		pfs_direntry_getname(mnt, de, name, sizeof(name));
		nmhash = dx_calc_hash(name);
		phyin = pfs_meta_get_inode(mnt, de->de_ino, NULL);
		pfs_inode_dx_add(mnt, &in->in_dx_root, nmhash, de->de_ino,
		    phyin->in_type == PFS_INODET_DIR);
	}
}

static inline void
pfs_inode_build_index(pfs_inode_t *in)
{
	switch (in->in_type) {
	case PFS_INODET_FILE:
		pfs_inode_build_findex(in);
		break;

	case PFS_INODET_DIR:
		pfs_inode_build_dindex(in);
		break;

	default:
		PFS_ASSERT("unreachable" == NULL);
	}
}

/*
 * pfs_inode_load
 *
 *	Load the inode content. We must lock the meta data,
 *	since there may be another thread syncing meta data.
 *	Note that the inode may be invalidated by others.
 */
static int
pfs_inode_load(pfs_inode_t *in, pfs_ino_t ino, bool force_unlck_meta)
{
	int err = 0;
	pfs_mount_t *mnt = in->in_mnt;
	pfs_inode_phy_t *phyin;
	bool unlock;

	unlock = pfs_inode_rpl_unlock(in);
	phyin = pfs_meta_get_inode(mnt, in->in_ino, NULL);
	if (unlock)
		pfs_inode_rpl_lock(in);
	err = pfs_inode_check_stale(phyin, NULL);
	if (err < 0)
		goto out;

	in->in_size = in->in_size2 = phyin->in_size;
	in->in_type = phyin->in_type;
	in->in_ctime = phyin->in_ctime;
	in->in_btime = phyin->in_btime;
	in->in_phyin = phyin;
	in->in_nblk_ip = 0;
	in->in_nblk_modify = 0;
	pfs_inode_writemodify_init(&in->in_write_modify);
	pfs_inode_dxredo_init(&in->in_dx_redo);

	/* build block index (file) or subfile index (directory) */
	pfs_inode_build_index(in);
	in->in_stale = false;

out:
	/*
	 * The inode is accessed without tx, so there
	 * is no need to obey 2 phase locking and
	 */
	if (pfs_tls_get_tx() == NULL || force_unlck_meta)
		pfs_meta_unlock(in->in_mnt);
	return err;
}

/*
 * pfs_inode_reload:
 *
 *	Because meta data syncing among PFS instances occurs
 *	at the log level and meta data level, and there is no way
 *	to notify the file level, the file level must check if
 *	the file size has changed. If so, rebuild its inode index.
 */
static int
pfs_inode_reload(pfs_inode_t *in, bool force_unlck_meta)
{
	int err;
	MNT_STAT_BEGIN();
	/*
	 * The # of data blocks has changed. Have to rebuild
	 * the block index in the core memory.
	 */
	PFS_ASSERT(in->in_stale == true);
	PFS_ASSERT(in->in_refcnt != 0);
	pfs_inode_destroy_index(in);
	pfs_inode_writemodify_fini(&in->in_write_modify);
	pfs_inode_dxredo_fini(&in->in_dx_redo);
	err = pfs_inode_load(in, in->in_ino, force_unlck_meta);
	MNT_STAT_END(MNT_STAT_SYNC_INODE_RELOAD);
	return err;
}

void
pfs_inode_destroy(pfs_inode_t *in)
{
	PFS_ASSERT(in->in_cbdone == true);
	mutex_destroy(&in->in_mtx);
	cond_destroy(&in->in_cond);
	pfs_inode_destroy_index(in);
	pfs_inode_writemodify_fini(&in->in_write_modify);
	pfs_inode_dxredo_fini(&in->in_dx_redo);

	pfs_mem_free(in, M_INODE);
}

void
pfs_inode_destroy_self(pfs_inode_t *in)
{
	PFS_ASSERT(in->in_cbdone == true);
	mutex_destroy(&in->in_mtx);
	cond_destroy(&in->in_cond);
	pfs_inode_destroy_index_self(in);	// XXX only difference
	pfs_inode_writemodify_fini(&in->in_write_modify);
	pfs_inode_dxredo_fini(&in->in_dx_redo);

	pfs_mem_free(in, M_INODE);
}

static pfs_inode_t *
pfs_inode_create(pfs_mount_t *mnt, pfs_ino_t ino)
{
	pfs_inode_t *in;

	in = (pfs_inode_t *)pfs_mem_malloc(sizeof(pfs_inode_t), M_INODE);
	if (in) {
		in->in_ino = ino;
		in->in_type = PFS_INODET_NONE;
		in->in_size = in->in_size2 = 0;
		in->in_ctime = 0;
		in->in_btime = 0;
		in->in_mnt = mnt;
		in->in_refcnt = 0;
		in->in_nblk_ip = 0;
		in->in_nblk_modify = 0;
		in->in_cbdone = true;
		in->in_blk_tables = NULL;
		mutex_init(&in->in_mtx);
		mutex_init(&in->in_mtx_rpl);
		cond_init(&in->in_cond, NULL);
		in->in_rpl_lock_thd = 0;
		in->in_sync_ver = 0;
		in->in_rpl_ver = 0;
		in->in_stale = true;
		pfs_inode_writemodify_init(&in->in_write_modify);
		pfs_avl_create(&in->in_dx_root, pfs_inode_dx_compare,
		    offsetof(pfs_dxent_t, e_avlnode));
		pfs_inode_dxredo_init(&in->in_dx_redo);
		pfs_inode_init_blktable(in);
	}
	return in;
}

static void
pfs_inode_change_size_done(pfs_mount_t *mnt, pfs_metaobj_phy_t *mo, int err)
{
	pfs_inode_t *in;

	in = pfs_get_inode(mnt, mo->mo_number);
	PFS_ASSERT(in != NULL);
	pfs_inode_lock(in);
	/*
	 * To support multi write we need add rpl lock here and do not assert
	 * in->in_size != in->in_size2
	 */
	pfs_inode_rpl_lock(in);
	in->in_size = in->in_size2;
	cond_broadcast(&in->in_cond);
	pfs_inode_rpl_unlock(in);
	pfs_inode_unlock(in);
	pfs_put_inode(mnt, in);
}

/*
 * pfs_inode_change:
 *
 *	The in memory inode has changed. Sync the change onto the disk copy.
 *	It doesn't flush the data onto pbd, but save the change in
 *	pfs_inode_phy_t. The saving will be logged in the journal file.
 */
int
pfs_inode_change(pfs_inode_t *in, ssize_t szdelta, bool force)
{
	int err;
	time_t ctime;
	pfs_inode_phy_t *phyin = NULL;
	pfs_txop_t *phyintop;
	pfs_tx_t *tx;

	ctime = time(NULL);
	if (szdelta == 0 && ctime - in->in_ctime <= PFS_CTIME_SYNC && !force)
		return 0;

	tx = pfs_tls_get_tx();		/* mata file's tx is NULL */
	if (tx) {
		err = pfs_tx_new_op(tx, phyintop);
		PFS_VERIFY(err == 0);
		err = pfs_inode_phy_get(in->in_mnt, in, &phyin, in->in_ino,
		    phyintop);
		if (err < 0)
			return err;
	}

	PFS_ASSERT(in->in_size == in->in_size2);
	in->in_size2 += szdelta;
	in->in_ctime = ctime;
	if (!phyin)
		phyin = in->in_phyin;
	phyin->in_size += szdelta;
	/*
	 * Modifying in_atime to make sure physical inode is changed,
	 * so its modification would be recorded into journal and other
	 * pfs instances can notice that.
	 * XXX:
	 * ugly code but simple and useful.
	 */
	if (szdelta == 0 && (time_t)phyin->in_ctime == ctime && force)
		phyin->in_atime++;	/* make sure phy inode is changed */
	phyin->in_ctime = ctime;
	phyin->in_mtime = ctime;

	if (tx) {
		pfs_tx_done_op_callback(tx, phyintop,
		    szdelta ? pfs_inode_change_size_done : NULL);
	}
	return 0;
}

void
pfs_inodephy_init(pfs_inode_phy_t *phyin, uint64_t deno, bool isdir)
{
	PFS_ASSERT(phyin->in_type == PFS_INODET_NONE);
	PFS_ASSERT(phyin->in_nlink == 0);
	PFS_ASSERT(phyin->in_deno == INVALID_DENO);
	PFS_ASSERT(phyin->in_pvtid == 0);

	phyin->in_type = isdir ? PFS_INODET_DIR : PFS_INODET_FILE;
	phyin->in_pvtid = 0;
	phyin->in_deno = deno;
	phyin->in_nlink = 1;	/* must have used for a new direntry */
	phyin->in_size = 0;
	phyin->in_nblock = 0;
	phyin->in_atime = 0;
	phyin->in_mtime = 0;
	phyin->in_ctime = 0;
	INPHY_UPDATE_TIME(phyin, IN_MTIME | IN_CTIME);
	phyin->in_btime = gettimeofday_us();
}

void
pfs_inodephy_fini(pfs_inode_phy_t *phyin)
{
	/* the inode must be emtpy */
	PFS_ASSERT(MONO_FIRST(phyin) == 0);

	phyin->in_type = PFS_INODET_NONE;
	phyin->in_pvtid = 0;
	phyin->in_deno = INVALID_DENO;
	phyin->in_flags = 0;
	phyin->in_nlink = 0;
	phyin->in_nblock = 0;
	phyin->in_size = 0;
	phyin->in_atime = 0;
	phyin->in_mtime = 0;
	phyin->in_ctime = 0;
	//We do not reset in_btime for future and debug usage.
}

/*
 * XXX
 * Should be an internal function, and not exposed to other module.
 * Otherwise, some data buffered in pfs_inode_t is skipped.
 * However, it is exposed to readdir_plus, leading input pfs_inode_t maybe NULL.
 */
int
pfs_inodephy_stat(pfs_mount_t *mnt, pfs_ino_t ino, pfs_inode_t *in, struct stat *st)
{
	int err;
	pfs_inode_phy_t *phyin;

	err = pfs_inode_phy_get(mnt, in, &phyin, ino, NULL);
	if (err < 0)
		return err;
	st->st_ino = ino;
	st->st_blksize = mnt->mnt_blksize;
	st->st_dev = strtoull(mnt->mnt_pbdname, NULL, 0);
	st->st_nlink = phyin->in_nlink;
	st->st_size = phyin->in_size;
	st->st_blocks = phyin->in_nblock * (PFS_BLOCK_SIZE >> 9); // unit is 512B
	st->st_atime = phyin->in_atime;
	st->st_mtime = phyin->in_mtime;
	st->st_ctime = phyin->in_ctime;

	/* Set type and permission */
	PFS_ASSERT(phyin->in_type == PFS_INODET_DIR ||
	       phyin->in_type == PFS_INODET_FILE);
	st->st_mode = 0;
	st->st_mode |= ((phyin->in_type == PFS_INODET_DIR) ? S_IFDIR : S_IFREG);
	st->st_mode |= (S_IRWXU | S_IRWXG | S_IRWXO);
	return 0;
}

int
pfs_inode_stat(pfs_inode_t *in, struct stat *st)
{
	return pfs_inodephy_stat(in->in_mnt, in->in_ino, in, st);
}

int
pfs_inode_release(pfs_mount_t *mnt, pfs_ino_t ino, uint64_t btime,
    pfs_inode_t *in)
{
	int err;
	do {
		tls_write_begin(mnt);
		if (in) {
			pfs_inode_lock(in);
			err = pfs_inode_sync_first(in, PFS_INODET_FILE, btime, false);
			if (err < 0)
				goto end;

			if (in->in_size >= file_shrink_size) {
				err = -EAGAIN;
				pfs_etrace("allocate blks while release inode? "
				   "inode: %ld\n", ino);
				goto end;
			}
		}
		err = pfs_inodephy_release(mnt, ino, btime);
	end:
		if (in)
			pfs_inode_unlock(in);
		tls_write_end(err);
		if (err == -ENOENT) {
			pfs_etrace("inode %ld, seems to be remotely removed "
			   "according to orphan inodes reclaiming!\n", ino);
			err = 0;
		}
		//For folder release we have to retry here.
	} while(err == -EAGAIN && in == NULL);
	return err;
}

int
pfs_inodephy_release(pfs_mount_t *mnt, pfs_ino_t ino, uint64_t btime)
{
	pfs_tx_t *tx = pfs_tls_get_tx();
	int err;
	pfs_inode_phy_t *phyin;
	pfs_blktag_phy_t *bt;
	pfs_txop_t *intop;
	pfs_txop_t *bttop;
	uint64_t btno;

	err = pfs_tx_new_op(tx, intop);
	if (err < 0)
		return err;
	phyin = pfs_meta_get_inode(mnt, ino, intop);
	err = pfs_inode_check_stale(phyin, NULL);
	if (err < 0)
		return err;
	if (btime != phyin->in_btime)
		ERR_RETVAL(ENOENT);

	PFS_ASSERT(phyin->in_nlink == 0);
	if (phyin->in_type == PFS_INODET_FILE &&
	    ((int64_t)phyin->in_size) >= file_shrink_size) {
		pfs_etrace("allocate blks while release inode? inode : %ld\n",
		    ino);
		ERR_RETVAL(EAGAIN);
	}
	pfs_inode_invalidate(ino, mnt);
	//Dir should clears its sub dirs or files first.
	PFS_ASSERT(phyin->in_type == PFS_INODET_FILE || MONO_FIRST(phyin) == 0);
	while ((btno = MONO_FIRST(phyin)) != 0) {
		PFS_ASSERT(phyin->in_type == PFS_INODET_FILE);
		err = pfs_tx_new_op(tx, bttop);
		if (err < 0)
			return err;
		bt = pfs_meta_get_blktag(mnt, btno, bttop);
		err = pfs_meta_list_delete(mnt, GETMO(phyin), GETMO(bt));
		if (err < 0)
			return err;
		pfs_meta_free_blktag(mnt, bt, NULL);
		pfs_tx_done_op(tx, bttop);
	}
	pfs_inodephy_fini(phyin);
	pfs_meta_free_inode(mnt, phyin, NULL);
	pfs_tx_done_op(tx, intop);
	return err;
}

int
pfs_inode_compare(const void *keya, const void *keyb)
{
	pfs_inode_t *in1 = (pfs_inode_t *)keya;
	pfs_inode_t *in2 = (pfs_inode_t *)keyb;

	if (in1->in_ino > in2->in_ino)
		return 1;
	if (in1->in_ino < in2->in_ino)
		return -1;
	return 0;
}

int
pfs_inodephy_setxattr(pfs_mount_t *mnt, pfs_ino_t ino, const char *name,
    const void *value, size_t size)
{
	pfs_tx_t *tx = pfs_tls_get_tx();
	pfs_inode_phy_t *phyin;
	pfs_txop_t *intop;
	int err;

	if (!pfs_version_has_features(mnt, PFS_FEATURE_PVTID))
		ERR_RETVAL(ENOTSUP);

	// XXX now we only allow user to set a 32-bit 'user.privateid'
	if (strcmp(name, "user.privateid") != 0 || size != sizeof(int32_t))
		ERR_RETVAL(EINVAL);

	err = pfs_tx_new_op(tx, intop);
	if (err < 0)
		return err;
	err = pfs_inode_phy_get(mnt, NULL, &phyin, ino, intop);
	if (err < 0)
		return err;

	PFS_ASSERT(size == sizeof(phyin->in_pvtid));
	pfs_inodephy_set_pvtid(mnt, phyin, *(uint32_t *)value);
	pfs_tx_done_op(tx, intop);
	return 0;
}

void
pfs_inode_put(pfs_inode_t *in)
{
	pfs_put_inode(in->in_mnt, in);
}

static pfs_inode_t *
pfs_inode_get_flags(pfs_mount_t *mnt, pfs_ino_t ino, bool needload)
{
	pfs_inode_t *in, *in2;

	while ((in = pfs_get_inode(mnt, ino)) == NULL) {
		in = pfs_inode_create(mnt, ino);
		if (in == NULL)
			return NULL;
		if (needload)
			pfs_inode_load(in, ino, false);
		in2 = pfs_add_inode(mnt, in);
		if (in != in2)
			pfs_inode_destroy(in);
	}
	return in;
}

pfs_inode_t *
pfs_inode_get(pfs_mount_t *mnt, pfs_ino_t ino)
{
	return pfs_inode_get_flags(mnt, ino, false);
}

pfs_inode_t *
pfs_inode_get_and_load(pfs_mount_t *mnt, pfs_ino_t ino)
{
	/*
	 * XXX
	 * This procedure is specialized for reloading inode ASAP, outside of
	 * write transactions. By doing this, inode will be reloaded while
	 * holding meta wrlock less often.
	 *
	 * Note that meta lock, if acquired, will not be released when return.
	 */
	return pfs_inode_get_flags(mnt, ino, true);
}

pfs_inode_t *
pfs_get_inode_tx(pfs_tx_t* tx, pfs_ino_t ino)
{
	int i = 0;
	pfs_inode_t *in;
	for (; i < TX_RPL_MAX_INODES; ++i) {
		in = tx->t_rpl_ctx.r_inodes[i];
		if (in == NULL)
			break;
		if (in->in_ino == ino)
			return in;
	}
	PFS_ASSERT(i < TX_RPL_MAX_INODES);
	in = pfs_get_inode(tx->t_mnt, ino);
	if (in) {
		tx->t_rpl_ctx.r_inodes[i] = in;
		pfs_inode_rpl_lock(in);
	}
	return in;
}

void
pfs_put_inode_tx_all(pfs_tx_t* tx)
{
	int i = 0;
	pfs_inode_t *in;
	for (; i < TX_RPL_MAX_INODES; ++i) {
		in = tx->t_rpl_ctx.r_inodes[i];
		if (in) {
			tx->t_rpl_ctx.r_inodes[i] = NULL;
			++in->in_rpl_ver;
			pfs_inode_rpl_unlock(in);
			pfs_put_inode(tx->t_mnt, in);
		} else
			break;
	}
}

void
pfs_inode_invalidate(pfs_ino_t ino, pfs_mount_t *mnt)
{
	pfs_inode_t *in;

	/*
	 * When it is called, we are still in tx and the
	 * meta lock is still in hold, so we can't lock the
	 * inode. Otherwise, there will be deadlock.
	 *
	 * The inode may be nonexistent. For example, its file
	 * has not been opened, or creat file tx has aborted.
	 */
	in = pfs_get_inode(mnt, ino);
	if (in == NULL)
		return;

	pfs_inode_mark_stale(in);

	pfs_put_inode(mnt, in);
}

/*
 * Check if the inode is stale. If so, we should reload it.
 *
 * This function is called before both read and write operations.
 * For a read operation, we first sync the all meta data by
 * pfs_mount_sync, then sync the file meta data by pfs_inode_sync,
 * and finally do the block mapping by the file meta data.
 *
 * For a write operation, we still have to sync the file meta data,
 * even if we may have just committed meta data changes, because
 * the sync thread may have polled new changes by other nodes.
 *
 * When reloading the inode, we check the validity of the inode
 * since it may be invalidated by other nodes. If the inode is
 * invalid, we return an error rather than throw an exception,
 * because invalidity can be handled here easily. An exception is
 * thrown only when it is difficult to handle the error, for example,
 * when traversing a directory tree. After successful reloading,
 * we will return -EAGAIN UNTIL FOLLOWING CONDITIONS SATISFIED:
 * when the pfs_inode_t object needs to be synced first time during
 * the call stack of an inode oriented pfs API, we can use
 * pfs_inode_sync_first instead of pfs_inode_sync to ignore the inode
 * version matching check(leading an -EAGAIN returning) after pfs_inode_t
 * reloading mentioned above.
 */
static int
pfs_inode_sync_impl(pfs_inode_t *in, int type, bool first_sync, uint64_t btime,
    bool force_unlck_meta)
{
	int err = 0;
	bool reloaded = false;
	pfs_inode_rpl_lock(in);
	while (in->in_nblk_ip != 0 || in->in_nblk_modify ||
	    in->in_size != in->in_size2 || !in->in_cbdone ||
	    (pfs_inode_writemodify_inprogress(&in->in_write_modify) &&
	    in->in_write_modify.wm_thread != pthread_self()) ||
	    (pfs_inode_dxredo_inprogress(&in->in_dx_redo) &&
	    in->in_dx_redo.r_thread != pthread_self())) {
		pfs_inode_rpl_unlock(in);
		MNT_STAT_BEGIN();
		cond_wait(&in->in_cond, &in->in_mtx);
		MNT_STAT_END(MNT_STAT_SYNC_INODE_WAIT);
		pfs_inode_rpl_lock(in);
	}
	if (in->in_stale) {
		err = pfs_inode_reload(in, force_unlck_meta);
		if (err)
			return err;
		reloaded = true;
	}
	if (pfs_inode_writemodify_inprogress(&in->in_write_modify) &&
	    in->in_sync_ver < in->in_rpl_ver)
		return -EAGAIN;

	in->in_sync_ver = in->in_rpl_ver;
	PFS_ASSERT(in->in_type != PFS_INODET_NONE);
	if (in->in_btime != btime) {
		err = -ENOENT;
	} else if (type != PFS_INODET_NONE && in->in_type != type) {
		err = (type == PFS_INODET_FILE) ? -EISDIR : -ENOTDIR;
		pfs_etrace("Fatal! inode_sync type mismatched: request type: "
		    "%d, inode type: %d\n", type, (int)(in->in_type));
	}
	else if (reloaded && (!first_sync))
		err = -EAGAIN;
	else if (in->in_type == PFS_INODET_DIR)
		pfs_inode_rpl_unlock(in);

	return err;
}

int
pfs_inode_sync(pfs_inode_t *in, int type, uint64_t btime, bool force_unlck_meta)
{
	return pfs_inode_sync_impl(in, type, false, btime, force_unlck_meta);
}

int
pfs_inode_sync_first(pfs_inode_t *in, int type, uint64_t btime, bool force_unlck_meta)
{
	return pfs_inode_sync_impl(in, type, true, btime, force_unlck_meta);
}

void
pfs_inode_lock(pfs_inode_t *in)
{
	PFS_ASSERT(!pfs_meta_islocked(in->in_mnt));
	mutex_lock(&in->in_mtx);
}

void
pfs_inode_rpl_lock(pfs_inode_t *in)
{
	pthread_t this_thd = pthread_self();
	if (this_thd == in->in_rpl_lock_thd)
		return;
	mutex_lock(&in->in_mtx_rpl);
	in->in_rpl_lock_thd = this_thd;
}

bool
pfs_inode_rpl_unlock(pfs_inode_t *in)
{
	if (pthread_self() == in->in_rpl_lock_thd) {
		in->in_rpl_lock_thd = 0;
		mutex_unlock(&in->in_mtx_rpl);
		return true;
	}

	return false;
}

void
pfs_inode_unlock(pfs_inode_t *in)
{
	pfs_inode_rpl_unlock(in);
	mutex_unlock(&in->in_mtx);
}

uint64_t
pfs_inodephy_diskusage(pfs_mount_t *mnt, pfs_inode_phy_t *phyin)
{
	uint64_t btno, nblk_soft, sum;
	pfs_blktag_phy_t *bt;

	PFS_ASSERT(phyin->in_type == PFS_INODET_FILE);
	if (!pfs_version_has_features(mnt, PFS_FEATURE_BLKHOLE) ||
	    phyin->in_nblock > (uint64_t)du_nblk_limit)
		return (phyin->in_nblock * mnt->mnt_blksize);

	/*
	 * The diskusage of small file is only calculated by non-blockhole
	 * parts in the range of size.
	 */
	sum = 0;
	nblk_soft = howmany(phyin->in_size, mnt->mnt_blksize);
	for (btno = MONO_FIRST(phyin); MONO_VALID(btno); btno = MONO_NEXT(bt)) {
		bt = pfs_meta_get_blktag(mnt, btno, NULL);
		PFS_ASSERT((uint64_t)bt->bt_ino == MONO_CURR(phyin));
		PFS_ASSERT(bt->bt_blkid >= 0);
		PFS_ASSERT((uint32_t)bt->bt_holelen <= mnt->mnt_blksize);
		if ((uint64_t)bt->bt_blkid < nblk_soft)
			sum += mnt->mnt_blksize - bt->bt_holelen;
	}

	/* round up to bsr unitsize(128KB) */
#define	DU_MINSIZE	(128 << 10)
	return roundup(sum, DU_MINSIZE);
}

ssize_t
pfs_inodephy_size(pfs_mount_t *mnt, pfs_ino_t ino)
{
	int err;
	pfs_inode_phy_t *phyin;
	err = pfs_inode_phy_get(mnt, NULL, &phyin, ino, NULL);
	if (err < 0 )
		return err;
	if (phyin->in_type == PFS_INODET_DIR)
		ERR_RETVAL(EISDIR);

	return (ssize_t)(phyin->in_size);
}

bool
pfs_inode_skip_sync(pfs_inode_t *in)
{
	return !pfs_writable(in->in_mnt) && in->in_stale;
}

void
pfs_inode_sync_blk_meta(pfs_inode_t *in, const pfs_blktag_phy_t *blktag)
{
	pfs_blkid_t blkid = blktag->bt_blkid;
	pfs_dblk_t *dblk = NULL;

	if (GETMO(blktag)->mo_used == 0) {
		pfs_inode_remove_blk(in, blkid);
		return;
	}
	dblk = pfs_inode_add_blk(in, blkid);
	pfs_dblk_init(dblk, btno2blkno(in->in_mnt, MONO_CURR(blktag)),
	    blktag->bt_holeoff, blktag->bt_holelen);
}

void
pfs_inode_sync_meta(pfs_inode_t *in, const pfs_inode_phy_t *phyin)
{
	if (in->in_size != in->in_size2) {
		/*
		 * multi-write detect! update inode only when we can keep the
		 * sync condition.
		 */
		if ((uint64_t)in->in_size != phyin->in_size)
			in->in_size2 = phyin->in_size;
		else
			pfs_inode_mark_stale(in);
	}
	else
		in->in_size = in->in_size2 = phyin->in_size;
	in->in_ctime = phyin->in_ctime;
}
