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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <search.h>
#include <stddef.h>
#include <sys/param.h>

#include "pfs_meta.h"
#include "pfs_devio.h"
#include "pfs_dir.h"
#include "pfs_inode.h"
#include "pfs_mount.h"
#include "pfs_option.h"
#include "pfs_tls.h"
#include "pfs_tx.h"
#include "pfs_util.h"
#include "pfs_version.h"
#include "pfs_stat.h"
#include "pfs_namecache.h"

#define	MAX_NTHRD	64
#define	MIN_NTHRD	8
static int64_t loadthread_count = MIN_NTHRD;
PFS_OPTION_REG(loadthread_count, pfs_check_ival_normal);

#define CHECK_META 0

typedef struct metatype {
	const char	*mt_name;
	pfs_metaobj_phy_t *(*mt_alloc) (pfs_mount_t *, int type, pfs_txop_t *);
	void		(*mt_free)(pfs_mount_t *, int type, pfs_metaobj_phy_t *,
			    pfs_txop_t *);
	void		(*mt_redo)(int64_t oid, pfs_mount_t *mnt);
	void		(*mt_redo_fini)(pfs_tx_t* tx);
	void		(*mt_undo)(int64_t oid, pfs_mount_t *mnt);
} metatype_t;

enum visit_type {
	VISIT_ONE,
	VISIT_ALL,
};

typedef struct metaset_visit {
	enum visit_type	msv_type;
	int64_t		msv_oid;
	void		(*msv_func)(void *, pfs_metaobj_phy_t *);
	void		*msv_data;
} metaset_visit_t;

static void 	pfs_meta_bd_change_index(pfs_mount_t *mnt, pfs_blktag_phy_t *bt);

static void 	pfs_metaobj_redo_inode(int64_t ino, pfs_mount_t *mnt);
static void	pfs_metaobj_undo_inode(int64_t ino, pfs_mount_t *mnt);

static pfs_metaobj_phy_t *
		pfs_metaobj_alloc_blktag(pfs_mount_t *, int, pfs_txop_t *);
static void 	pfs_metaobj_free_blktag(pfs_mount_t *, int, pfs_metaobj_phy_t *,
		    pfs_txop_t *);
static void 	pfs_metaobj_redo_blktag(int64_t btno, pfs_mount_t *mnt);
static void 	pfs_metaobj_undo_blktag(int64_t btno, pfs_mount_t *mnt);

static void		pfs_metaobj_redo_direntry(int64_t mono, pfs_mount_t *mnt);

static void 	pfs_metaobj_undo_common(int64_t mono, pfs_mount_t *mnt);
static pfs_metaobj_phy_t *
		pfs_metaobj_alloc_common(pfs_mount_t *, int, pfs_txop_t *);
static void 	pfs_metaobj_free_common(pfs_mount_t *, int, pfs_metaobj_phy_t *,
    		    pfs_txop_t *);

static void	pfs_metaobj_redo_fini_common(pfs_tx_t*);
static void	pfs_metaobj_redo_fini_inode(pfs_tx_t*);


static	metatype_t metatypes[] = {
	[MT_NONE] = {
		.mt_name = "none",
		.mt_alloc = NULL,
		.mt_free = NULL,
		.mt_redo = NULL,
		.mt_redo_fini = NULL,
		.mt_undo = NULL,
	},

	[MT_BLKTAG] = {
		.mt_name = "blktag",
		.mt_alloc = pfs_metaobj_alloc_blktag,
		.mt_free = pfs_metaobj_free_blktag,
		.mt_redo = pfs_metaobj_redo_blktag,
		.mt_redo_fini = pfs_metaobj_redo_fini_common,
		.mt_undo = pfs_metaobj_undo_blktag,
	},

	[MT_DIRENTRY] = {
		.mt_name = "direntry",
		.mt_alloc = pfs_metaobj_alloc_common,
		.mt_free = pfs_metaobj_free_common,
		.mt_redo = pfs_metaobj_redo_direntry,
		.mt_redo_fini = pfs_metaobj_redo_fini_common,
		.mt_undo = pfs_metaobj_undo_common,
	},

	[MT_INODE] = {
		.mt_name = "inode",
		.mt_alloc = pfs_metaobj_alloc_common,
		.mt_free = pfs_metaobj_free_common,
		.mt_redo = pfs_metaobj_redo_inode,
		.mt_redo_fini = pfs_metaobj_redo_fini_inode,
		.mt_undo = pfs_metaobj_undo_inode,
	},
};

void
pfs_meta_lock(pfs_mount_t *mnt)
{
	pfs_tx_t *tx;
	pfs_tls_t *tls;

	if (!pfs_inited(mnt)) {
		/*
		 * It is to lock during mount. It is trivial
		 * since there is only one thread doing mount.
		 * Do nothing in this case.
		 */
		return;
	}
	tls = pfs_current_tls();
	if (tls->tls_meta_locked)
		return;
	tx = tls->tls_tx;
	if (tx && (tx->t_type == TXT_WRITE || tx->t_type == TXT_REPLAY))
		MOUNT_META_WRLOCK(mnt);
	else
		MOUNT_META_RDLOCK(mnt);
	tls->tls_meta_locked = true;
}


void
pfs_meta_unlock(pfs_mount_t *mnt)
{
	pfs_tls_t *tls = pfs_current_tls();
	if (tls->tls_meta_locked) {
		tls->tls_meta_locked = false;
		rwlock_unlock(&mnt->mnt_meta_rwlock);
	}
}

bool
pfs_meta_islocked(pfs_mount_t *mnt)
{
	pfs_tls_t *tls = pfs_current_tls();
	return tls->tls_meta_locked;
}

#if 0
static bool
metaobj_check(const pfs_metaobj_phy_t *mo)
{
	return mo->mo_used > 0;
}
#endif

void
pfs_metaobj_check_crc(pfs_metaobj_phy_t *mo)
{
	uint32_t cksum;

	/* Skip old version metaobj whose checksum is zero */
	if (!mo->mo_checksum)
		return;

	cksum = crc32c_compute(mo, sizeof(*mo),
	    offsetof(struct pfs_metaobj_phy, mo_checksum));
	if (mo->mo_checksum != cksum) {
		pfs_etrace("metaobj %lld (type %d) checksum %u is invalid\n",
			   (long long)mo->mo_number, mo->mo_type, mo->mo_checksum);
		PFS_ASSERT("metaobj crc error" == NULL);
		abort();
	}
}

void
pfs_metaobj_check_crc_buf(pfs_metaobj_phy_t *mobuf, int nmo)
{
	pfs_metaobj_phy_t *mo;

	for (mo = mobuf; mo < mobuf + nmo; mo++)
		pfs_metaobj_check_crc(mo);
}

static void
pfs_metaobj_init(pfs_metaobj_phy_t *mo, int type)
{
	PFS_ASSERT(mo->mo_type == type);
	PFS_ASSERT(mo->mo_prev == 0);	/* a new meta object should have */
	PFS_ASSERT(mo->mo_next == 0);	/* no structure info */
	PFS_ASSERT(mo->mo_used == 0);

	mo->mo_used = 1;

	//mo->mo_version = 0;		/* XXX: version to be used later */
}

static void
pfs_metaobj_fini(pfs_metaobj_phy_t *mo, int type)
{
	PFS_ASSERT(mo->mo_type == type);
	PFS_ASSERT(mo->mo_prev == 0);	/* a to be freed object should have */
	PFS_ASSERT(mo->mo_next == 0);	/* no structure info */
	PFS_ASSERT(mo->mo_used == 1);

	mo->mo_used = 0;
}

static void
pfs_meta_inode_change(pfs_mount_t *mnt, const pfs_inode_phy_t *phyin)
{
	pfs_metaobj_phy_t *mo = GETMO(phyin);
	pfs_inode_t *in;

	in = pfs_get_inode_tx(pfs_tls_get_tx(), mo->mo_number);
	if (in == NULL || in->in_stale)
		return;
	if (in->in_type != PFS_INODET_FILE ||
	    phyin->in_type != PFS_INODET_FILE) {
		pfs_inode_mark_stale(in);
		return;
	}
	pfs_inode_sync_meta(in, phyin);
}

static void
pfs_metaobj_redo_inode(int64_t ino, pfs_mount_t *mnt)
{
	/* notify file level to update file index in memory inode */
	pfs_inode_phy_t *phyin;
	if (pfs_inited(mnt)) {
		phyin = pfs_meta_get_inode_flags(mnt, ino, NULL, 0);
		pfs_meta_inode_change(mnt, phyin);
	}
}

static void
pfs_metaobj_undo_inode(int64_t ino, pfs_mount_t *mnt)
{
	/* notify file level to update file index in memory inode */
	if (pfs_inited(mnt)) {
		/*
		 * In fact , this case we can use pfs_meta_inode_change as well.
		 * But to reduce understanding complexity, we still use the
		 * older interfaces.
		 */
		pfs_inode_invalidate(ino, mnt);
	}
}

static void
pfs_meta_inode_change_findex(const pfs_blktag_phy_t* bt)
{
	pfs_metaobj_phy_t *mo = GETMO(bt);
	pfs_inode_t *in;
	/*
	 * We do not update the inode index from discard tx.
	 */
	if (bt->bt_dstatus == BDS_INP ||
	    (bt->bt_dstatus == BDS_NONE && !mo->mo_used))
		return;
	in = pfs_get_inode_tx(pfs_tls_get_tx(), bt->bt_ino);
	if (in == NULL || in->in_stale)
		return;
	/*
	 * Before apply the blktag tx, the inode must be a file once it is
	 * not stale.
	 */
	PFS_ASSERT(in->in_type == PFS_INODET_FILE);
	pfs_inode_sync_blk_meta(in, bt);
}

static void
pfs_metaobj_redo_blktag(int64_t btno, pfs_mount_t *mnt)
{
#ifdef PFSDEBUG
	if (pfs_inited(mnt))
		pfs_itrace("redo blk %lu\n", btno);
#endif

	pfs_blktag_phy_t *bt;
	if (pfs_inited(mnt)) {
		bt = pfs_meta_get_blktag_flags(mnt, btno, NULL, 0);
		pfs_meta_bd_change_index(mnt, bt);
		pfs_meta_inode_change_findex(bt);
	}
}

static void
pfs_metaobj_undo_blktag(int64_t btno, pfs_mount_t *mnt)
{
#ifdef PFSDEBUG
	if (pfs_inited(mnt))
		pfs_itrace("undo blk %lu\n", btno);
#endif
	pfs_blktag_phy_t *bt;
	if (pfs_inited(mnt)) {
		bt = pfs_meta_get_blktag_flags(mnt, btno, NULL, 0);
		pfs_meta_bd_change_index(mnt, bt);
	}
}

/* ARGSUSED */
static void
pfs_metaobj_use_one(pfs_anode_t *an, uint64_t oid, void *data)
{
	pfs_anode_nfree_inc(an, oid, -1);
}

static pfs_metaobj_phy_t *
pfs_metaobj_alloc_blktag(pfs_mount_t *mnt, int mtype, pfs_txop_t *top)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[mtype];
	pfs_metaobj_phy_t *mo;
	pfs_blktag_phy_t *bt;
	uint64_t val;
	int err;
	bool reused;

	if ((val = pfs_bd_get(mnt, BDS_READY)) != (uint64_t)-1) {
		pfs_bd_del(mnt, BDS_READY, val);
		pfs_anode_visit(anroot, val, pfs_metaobj_use_one, NULL);
		reused = true;
	} else if ((err = pfs_anode_alloc(anroot, &val)) == 0)
		reused = false;
	else
		return NULL;

	mo = (pfs_metaobj_phy_t *)pfs_anode_get(anroot, val, top);
	pfs_metaobj_init(mo, mtype);

	bt = MO2BT(mo);
#ifdef PFSDEBUG
	pfs_itrace("%s blk %lu\n", reused ? "realloc" : "alloc", val);
#endif
	if (reused)
		PFS_ASSERT(bt->bt_dstatus == BDS_READY);
	else
		PFS_ASSERT(bt->bt_dstatus != BDS_INP);
	PFS_ASSERT(bt->bt_holeoff == 0);
	PFS_ASSERT(bt->bt_holelen == 0);
	bt->bt_dstatus = BDS_NONE;
	bt->bt_ndiscard = 0;
	bt->bt_holeoff = 0;
	bt->bt_holelen = pfs_version_has_features(mnt, PFS_FEATURE_BLKHOLE) ?
		mnt->mnt_blksize : 0;
	return mo;
}

static void
pfs_metaobj_free_blktag(pfs_mount_t *mnt, int mtype, pfs_metaobj_phy_t *mo,
    pfs_txop_t *top)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[mtype];
	pfs_blktag_phy_t *bt;

#ifdef PFSDEBUG
	pfs_itrace("free blk %lu\n", mo->mo_number);
#endif

	bt = MO2BT(mo);
	PFS_ASSERT(bt->bt_ndiscard == 0);
	PFS_ASSERT(bt->bt_dstatus == BDS_NONE);
	bt->bt_dstatus = BDS_READY;
	pfs_bd_add(mnt, BDS_READY, mo->mo_number);
	bt->bt_holeoff = 0;
	bt->bt_holelen = 0;

	pfs_metaobj_fini(mo, mtype);
	pfs_anode_free(anroot, mo->mo_number);
}

static void
pfs_metaobj_redo_fini_inode(pfs_tx_t* tx)
{
	pfs_put_inode_tx_all(tx);
}

static pfs_metaobj_phy_t *
pfs_metaobj_alloc_common(pfs_mount_t *mnt, int mtype, pfs_txop_t *top)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[mtype];
	pfs_metaobj_phy_t *mo;
	int err;
	uint64_t val;

	err = pfs_anode_alloc(anroot, &val);
	if (err == -ENOSPC)
		return NULL;
	mo = (pfs_metaobj_phy_t *)pfs_anode_get(anroot, val, top);
	pfs_metaobj_init(mo, mtype);
	return mo;
}

static void
pfs_metaobj_free_common(pfs_mount_t *mnt, int mtype, pfs_metaobj_phy_t *mo,
    pfs_txop_t *top)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[mtype];

	pfs_metaobj_fini(mo, mtype);
	pfs_anode_free(anroot, mo->mo_number);
}

static void
pfs_metaobj_redo_direntry(int64_t mono, pfs_mount_t *mnt)
{
    pfs_namecache_delete_by_deno(mnt, mono);
}

static void
pfs_metaobj_undo_common(int64_t mono, pfs_mount_t *mnt)
{
}

static void
pfs_metaobj_redo_fini_common(pfs_tx_t*)
{
}

static inline pfs_metaobj_phy_t *
pfs_metaset_getobject(pfs_metaset_t *ms, uint64_t oid, pfs_txop_t *top,
    void **bufp)
{
	uint64_t si, oi, sectsize;
	pfs_metaobj_phy_t* result = NULL;

	si = oid >> ms->ms_opps;
	oi = oid - (si << ms->ms_opps);
	sectsize = ms->ms_objsize << ms->ms_opps;

	PFS_ASSERT(si < ms->ms_nsect && oi < (1ULL << ms->ms_opps));
	if (bufp)
		*bufp = ms->ms_objbuf[si];
	if (top)
		result = pfs_txop_init(top, ms->ms_objbuf[si], oi,
		    ms->ms_sectbda + si * sectsize);
	else
		result = pfs_tx_get_mo(pfs_tls_get_tx(),
		    &ms->ms_objbuf[si][oi]);
	return result;
}

static bool
pfs_metaset_alloc(pfs_anode_t *an, uint64_t oid)
{
	pfs_metaset_t *ms = (pfs_metaset_t *)an->an_host;
	pfs_metaobj_phy_t *mo;

	mo = pfs_metaset_getobject(ms, oid, NULL, NULL);
	if (mo->mo_used)
		return false;
	if (mo->mo_type == MT_BLKTAG)
		return (MO2BT(mo)->bt_dstatus != BDS_INP);
	return true;
}

static void
pfs_metaset_free(pfs_anode_t *an, uint64_t oid)
{
	/**
	 * In local tx, visiting the meta object directly via
	 * "pfs_metaset_getobject" is dangerous(risk of visiting old version).
	 * So here we disable the following check logic.
	 */
#if 0
	pfs_metaset_t *ms = (pfs_metaset_t *)an->an_host;
	pfs_metaobj_phy_t *mo;

	mo = pfs_metaset_getobject(ms, oid, NULL, NULL);
	if (mo->mo_type != ms->ms_type)
		printf("internal error: mo type mismatch\n");
#endif
}

/* oid is a relative object id in metaset, which starts from 0 */
static void *
pfs_metaset_get(pfs_anode_t *an, uint64_t oid, pfs_txop_t *top)
{
	pfs_metaset_t *ms = (pfs_metaset_t *)an->an_host;
	pfs_metaobj_phy_t *mo;

	mo = pfs_metaset_getobject(ms, oid, top, NULL);
	return mo;
}

static int
pfs_metaset_undo(pfs_anode_t *an, uint64_t oid, pfs_txop_t *top)
{
	pfs_metaset_t *ms = (pfs_metaset_t *)an->an_host;
	pfs_mount_t *mnt = ms->ms_chunk->ck_mnt;
	pfs_metaobj_phy_t *mo;
	int nfree_delta;

	mo = pfs_metaset_getobject(ms, oid, NULL, NULL);
	nfree_delta = pfs_txop_undo(top, mo);
	metatypes[mo->mo_type].mt_undo(mo->mo_number, mnt);
	return nfree_delta;
}

static int
pfs_metaset_redo(pfs_anode_t *an, uint64_t oid, pfs_txop_t *top)
{
	pfs_metaset_t *ms = (pfs_metaset_t *)an->an_host;
	pfs_mount_t *mnt = ms->ms_chunk->ck_mnt;
	pfs_metaobj_phy_t *mo;
	int nfree_delta;
	void *sectbuf = NULL;

	mo = pfs_metaset_getobject(ms, oid, NULL, &sectbuf);
	nfree_delta = pfs_txop_redo(top, mo, sectbuf);
	metatypes[mo->mo_type].mt_redo(mo->mo_number, mnt);
	return nfree_delta;
}

void
pfs_metaset_used_oid(pfs_anode_t *an, uint64_t oidzero, void *data)
{
	pfs_metaset_t *ms = (pfs_metaset_t *)an->an_host;
	oidvect_t *ov = (oidvect_t *)data;
	uint64_t si, oi;
	uint64_t oid;
	pfs_mount_t* mnt = NULL;
	int holeoff = INT_MAX;
	int err;

	if (an->an_nchild != 0)
		return;	/* skip internal node */

	mnt = ms->ms_chunk->ck_mnt;

	for (si = 0; si < ms->ms_nsect; si++) {
		for (oi = 0; oi < (1ULL << ms->ms_opps); oi++) {
			if (ms->ms_objbuf[si][oi].mo_used) {
				oid = (si << ms->ms_opps) + oi;

				if ((ms->ms_type == MT_BLKTAG) &&
				    pfs_version_has_features(mnt,
				    PFS_FEATURE_BLKHOLE)) {
					pfs_blktag_phy_t *bt =
					    MO2BT(&ms->ms_objbuf[si][oi]);
					holeoff = bt->bt_holelen > 0 ?
						bt->bt_holeoff : INT_MAX;
				}

				err = oidvect_push(ov, oid, holeoff);
				PFS_ASSERT(err == 0);
			}
		}
	}
}

static void
pfs_metaset_init_anode(pfs_metaset *ms, uint64_t ckno)
{
	uint64_t si, oi;
	int next = -1;
	pfs_anode_t *an;

	an = &ms->ms_anode;
	memset(an, 0, sizeof(*an));
	an->an_host = ms;
	an->an_allocfunc = pfs_metaset_alloc;
	an->an_freefunc = pfs_metaset_free;
	an->an_getfunc = pfs_metaset_get;
	an->an_undofunc = pfs_metaset_undo;
	an->an_redofunc = pfs_metaset_redo;
	an->an_id = ckno;
	an->an_shift = ms->ms_opps + ffs(roundup_power2(ms->ms_nsect)) - 1;
	memset(&an->an_free_bmp, 0, sizeof(an->an_free_bmp));
	for (si = 0; si < ms->ms_nsect; si++) {
		for (oi = 0; oi < (1ULL << ms->ms_opps); oi++) {
			an->an_nall++;
			if (ms->ms_objbuf[si][oi].mo_used == 0) {
				pfs_anode_nfree_inc(an,
				    (si << ms->ms_opps) + oi, 1);
				/* save the val for the first free blktag */
				if (next < 0)
					next = (si << ms->ms_opps) + oi;
			}
		}
	}
	if (next >= 0)
		an->an_next = next;
}

#if CHECK_META
static void
metaset_check_nfree(pfs_anode_t *an, void *data)
{
	pfs_metaset_t *ms = (pfs_metaset_t *)an->an_host;
	uint64_t si, oi;
	int nfree;

	nfree = 0;
	for (si = 0; si < ms->ms_nsect; si++) {
		for (oi = 0; oi < (1ULL << ms->ms_opps); oi++) {
			if (ms->ms_objbuf[si][oi].mo_used == 0)
				nfree++;
		}
	}
	PFS_ASSERT(nfree == an->an_nfree);
	*(int *)data += nfree;
}
#endif	// CHECK_META

static void
pfs_metaset_check_crc(pfs_metaset_t *ms)
{
	int i;

	for (i = 0; i < (int)ms->ms_nsect; i++)
		pfs_metaobj_check_crc_buf(ms->ms_objbuf[i], 1 << ms->ms_opps);
}

static int
pfs_metaset_bd_build_index(pfs_anode_t *an, void *data)
{
	pfs_mount_t *mnt = (pfs_mount_t *)data;
	pfs_metaset_t *ms;
	pfs_metaobj_phy_t *mo;
	uint64_t si, oi;
	uint32_t status;

	if (an->an_nchild)
		return 0;

	ms = (pfs_metaset_t *)an->an_host;
	for (si = 0; si < ms->ms_nsect; si++) {
		for (oi = 0; oi < (1ULL << ms->ms_opps); oi++) {
			mo = &ms->ms_objbuf[si][oi];
			if (mo->mo_used)
				continue;

			status = MO2BT(mo)->bt_dstatus;
			switch (status) {
			case BDS_READY:
			case BDS_INP:
				pfs_bd_add(mnt, status, mo->mo_number);
				break;

			case BDS_NONE:
				break;

			default:
				pfs_etrace("blktag %llu has bad status %u",
				    mo->mo_number, status);
				PFS_ASSERT("blktag bad status" == NULL);
				break;
			}
		}
	}
	return 0;
}

static void
pfs_metaset_bd_select(pfs_anode_t *an, uint64_t firstoid, void *data)
{
	pfs_metaset_t *ms = (pfs_metaset_t *)an->an_host;
	discard_args_t *dargs = (discard_args_t *)data;
	pfs_metaobj_phy_t *mo;
	uint64_t si, oi;
	tnode_t *node;

	if (an->an_nchild != 0)
		return;	/* skip internal node */

	for (si = 0; si < ms->ms_nsect; si++) {
		for (oi = 0; oi < (1ULL << ms->ms_opps); oi++) {
			mo = &ms->ms_objbuf[si][oi];
			PFS_ASSERT(mo->mo_type == MT_BLKTAG);
			if (mo->mo_used)
				continue;

			/*
			 * If '--all' isn't set, then skip blk whose dstatus
			 * is BDS_NONE.
			 */
			if (!dargs->d_all && MO2BT(mo)->bt_dstatus == BDS_NONE)
				continue;

			node = tsearch((tkey_t *)mo->mo_number, &dargs->d_bdroot,
			    pfs_bd_compare);
			PFS_ASSERT(node != NULL);
			dargs->d_nblk++;
		}
	}
}

static void
pfs_metaset_visit(pfs_anode_t *an, uint64_t oid, void *data)
{
	metaset_visit_t *msv = (metaset_visit_t *)data;
	pfs_metaset_t *ms;
	pfs_metaobj_phy_t *mo;
	uint64_t si, oi;

	if (an->an_nchild != 0)
		return;	/* skip internal node */

	ms = (pfs_metaset_t *)an->an_host;
	switch (msv->msv_type) {
	case VISIT_ONE:
		mo = pfs_metaset_getobject(ms, oid, NULL, NULL);
		if (mo == NULL)
			return;
		(*msv->msv_func)(msv->msv_data, mo);
		break;

	case VISIT_ALL:
		for (si = 0; si < ms->ms_nsect; si++) {
			for (oi = 0; oi < (1ULL << ms->ms_opps); oi++) {
				mo = &ms->ms_objbuf[si][oi];
				(*msv->msv_func)(msv->msv_data, mo);
			}
		}
		break;

	default:
		PFS_ASSERT("unknown traverse type" == NULL);
		break;
	}
}


/*
 * metset_load:
 *
 * 	Load the disk content of a metaset into memory as a seperate copy.
 * 	The in-memory copy will act as an allocation node.
 */
static int
pfs_meta_load_set(pfs_mount_t *mnt, pfs_chunk_t *ck, int mtype)
{
	int i, err = 0, err1 = 0;
	pfs_chunk_phy_t *phyck = ck->ck_phyck;
	uint64_t sectsize = phyck->ck_sectsize;
	pfs_metaset_t *ms = &ck->ck_metaset[mtype];
	pfs_metaset_phy_t *physet = &phyck->ck_physet[mtype];
	uint64_t bda;
	ssize_t buflen, rsum, rlen;
	char *bufptr;

	ms->ms_type = mtype;
	ms->ms_sectbda = physet->ms_sectbda;
	ms->ms_nsect = physet->ms_nsect;
	ms->ms_objsize = physet->ms_objsize;
	ms->ms_opps = ffs(ck->ck_sectsize / ms->ms_objsize) - 1;
	PFS_ASSERT((ms->ms_objsize << ms->ms_opps) == ck->ck_sectsize);
	ms->ms_objbuf = (pfs_metaobj_phy_t **)pfs_mem_malloc(
	    ms->ms_nsect * sizeof(*ms->ms_objbuf), M_OBJBUFV);
	if (ms->ms_objbuf == NULL)
		ERR_RETVAL(ENOMEM);
	memset(ms->ms_objbuf, 0, ms->ms_nsect * sizeof(*ms->ms_objbuf));

	/*
	 * alloc consecutive memory for meta sectors and
	 * let ms->ms_objbuf[0] record it.
	 */
	PFS_ASSERT(sectsize % sizeof(pfs_metaobj_phy_t) == 0);
	buflen = ms->ms_nsect * sectsize;
	bufptr = (char *)pfs_mem_malloc(buflen, M_METASET);
	PFS_VERIFY(bufptr != NULL);
	/* set meta sectors pointers */
	for (i = 0; i < (int)ms->ms_nsect; i++) {
		ms->ms_objbuf[i] = (pfs_metaobj_phy_t *)(bufptr + i * sectsize);
	}

	/*
	 * issue nowait I/Os which are 4KB aligned to load
	 * meta sectors.
	 * Make sure that each I/O is in the range of one
	 * fragment.
	 */
	err = 0;
	bda = ms->ms_sectbda;
	for (rsum = 0; rsum < buflen; rsum += rlen, bda += rlen) {
		rlen = mnt->mnt_fragsize - (bda % mnt->mnt_fragsize);
		rlen = MIN(rlen, buflen - rsum);
		err = pfsdev_pread_flags(mnt->mnt_ioch_desc, bufptr + rsum,
		    rlen, bda, IO_NOWAIT);
		if (err < 0)
			break;
	}
	err1 = pfsdev_wait_io(mnt->mnt_ioch_desc);
	ERR_UPDATE(err, err1);
	return err;
}

void
pfs_meta_check_chunk(const pfs_chunk_phy_t *phyck)
{
	bool mismatch = false;

	/*
	 * Check phyck->checksum
	 * Old version of meta doesn't have checksum which value is zero,
	 * so we should skip this case for compatibility.
	 */
	if (phyck->ck_checksum == 0) {
		pfs_itrace("pfs chunk %llu checksum is zero, it maybe an old "
		    "version, skip checking it\n",
		    (unsigned long long)phyck->ck_number);
	} else {
		if (phyck->ck_checksum != crc32c_compute(phyck, sizeof(*phyck),
		    offsetof(struct pfs_chunk_phy, ck_checksum))) {
			pfs_etrace("pfs chunk checksum %u is invalid\n",
			    phyck->ck_checksum);
			mismatch = true;
		}
	}
	if (!chunk_magic_valid(phyck->ck_number, phyck->ck_magic)) {
		pfs_etrace("pfs magic mismatch %#llx vs %#llx\n",
		    (unsigned long long)phyck->ck_magic,
		    (unsigned long long)PFS_CHUNK_MAGIC);
		mismatch = true;
	}
	if (phyck->ck_chunksize != PBD_CHUNK_SIZE) {
		pfs_etrace("pfs chunk size mismatch %#llx vs %#llx\n",
		    (unsigned long long)phyck->ck_chunksize,
		    (unsigned long long)PBD_CHUNK_SIZE);
		mismatch = true;
	}
	if (phyck->ck_sectsize != PBD_SECTOR_SIZE) {
		pfs_etrace("pfs sector size mismatch %#llx vs %#llx\n",
		    (unsigned long long)phyck->ck_sectsize,
		    (unsigned long long)PBD_SECTOR_SIZE);
		mismatch = true;
	}

	if (mismatch) {
		pfs_etrace("pfs mismatch occurs in chunk %u."
		    " Make sure mkfs has run!\n", phyck->ck_number);
		exit(EIO);
	}
}

static int
pfs_meta_load_chunk(pfs_mount_t *mnt, uint32_t ckid)
{
	int i, err;
	pfs_chunk_t *ck;
	pfs_metaset_t *ms;
	pfs_chunk_phy_t *phyck;

	PFS_ASSERT(mnt->mnt_nchunk >= 0 && ckid < (uint32_t)mnt->mnt_nchunk);
	phyck = (pfs_chunk_phy_t *)pfs_mem_malloc(PBD_SECTOR_SIZE, M_SECTOR);
	if (phyck == NULL)
		ERR_RETVAL(ENOMEM);
	err = pfsdev_pread(mnt->mnt_ioch_desc, phyck, PBD_SECTOR_SIZE,
	    ckid * PBD_CHUNK_SIZE);
	if (err < 0)
		ERR_GOTO(EIO, out);

	pfs_meta_check_chunk(phyck);
	PFS_ASSERT(phyck->ck_number == ckid);

	ck = (pfs_chunk_t *)pfs_mem_malloc(sizeof(*ck), M_CHUNK);
	if (ck == NULL)
		ERR_GOTO(ENOMEM, out);
	ck->ck_mnt = mnt;
	ck->ck_phyck = phyck;
	ck->ck_number = phyck->ck_number;
	ck->ck_sectsize = phyck->ck_sectsize;
	mnt->mnt_chunkv[ckid] = ck;

	for (i = 0; i < MT_NTYPE; i++) {
		if (i == MT_NONE)
			continue;
		ms = &ck->ck_metaset[i];
		ms->ms_chunk = ck;
		err = pfs_meta_load_set(mnt, ck, i);
		if (err < 0)
			return err;
		pfs_metaset_check_crc(ms);
		pfs_metaset_init_anode(ms, ck->ck_number);
	}
	return 0;

out:
	pfs_mem_free(phyck, M_SECTOR);
	return err;
}

int
pfs_meta_list_insert(pfs_mount_t *mnt, pfs_metaobj_phy_t *headmo,
    pfs_metaobj_phy_t *mo)
{
	int err;
	pfs_metaobj_phy_t *tailmo;
	pfs_txop_t *top = NULL;
	pfs_tx_t *tx = pfs_tls_get_tx();

	PFS_ASSERT(headmo->mo_type == MT_INODE);

	if (headmo->mo_head == 0) {
		headmo->mo_head = mo->mo_number;
	} else {
		err = pfs_tx_new_op(tx, top);
		if (err < 0)
			return err;
		tailmo = pfs_meta_get(mnt, mo->mo_type, headmo->mo_tail, top,
		    MGF_CHECKVALID);
		mo->mo_prev = tailmo->mo_number;
		tailmo->mo_next = mo->mo_number;
		pfs_tx_done_op(tx, top);
	}
	headmo->mo_tail = mo->mo_number;
	return 0;
}

int
pfs_meta_list_delete(pfs_mount_t *mnt, pfs_metaobj_phy_t *headmo,
    pfs_metaobj_phy_t *mo)
{
	int err;
	pfs_metaobj_phy_t *prevmo, *nextmo;
	pfs_txop_t *top = NULL;
	pfs_tx_t *tx = pfs_tls_get_tx();

	PFS_ASSERT(headmo->mo_type == MT_INODE);

	/* Free the entry and unlink it from the entry chain. */
	if (mo->mo_prev) {
		err = pfs_tx_new_op(tx, top);
		if (err < 0)
			return err;
		prevmo = pfs_meta_get(mnt, mo->mo_type, mo->mo_prev, top,
		    MGF_CHECKVALID);
		prevmo->mo_next = mo->mo_next;
		pfs_tx_done_op(tx, top);
	} else {
		headmo->mo_head = mo->mo_next;
	}
	if (mo->mo_next) {
		err = pfs_tx_new_op(tx, top);
		if (err < 0)
			return err;
		nextmo = pfs_meta_get(mnt, mo->mo_type, mo->mo_next, top,
		    MGF_CHECKVALID);
		nextmo->mo_prev = mo->mo_prev;
		pfs_tx_done_op(tx, top);
	} else {
		headmo->mo_tail = mo->mo_prev;
	}

	mo->mo_prev = 0;	/* clear previous structure info */
	mo->mo_next = 0;
	return 0;
}

static void
pfs_meta_finish_set(pfs_metaset_t *ms)
{
	if (ms->ms_objbuf == NULL)
		return;

	if (ms->ms_objbuf[0]) {
		pfs_mem_free(ms->ms_objbuf[0], M_METASET);
		ms->ms_objbuf[0] = NULL;
	}
	pfs_mem_free(ms->ms_objbuf, M_OBJBUFV);
	ms->ms_objbuf = NULL;
}

void
pfs_meta_finish_chunk(pfs_chunk_t *ck)
{
	int i;

	for (i = 0; i < MT_NTYPE; i++)
		pfs_meta_finish_set(&ck->ck_metaset[i]);
	pfs_mem_free(ck->ck_phyck, M_SECTOR);
	pfs_mem_free(ck, M_CHUNK);
	return;
}


/*
 * All chunks are divided into several load_tasks in balance.
 * Every task loads superblocks of chunks in [lckid, rckid).
 * When reading metasets in superblock, all I/Os are issued
 * in asynchronous mode. I/O's length is 16KB and its block
 * device address is 4KB aligned.
 */
typedef struct load_task {
	pthread_t	t_thrid;
	pfs_mount_t	*t_mnt;
	int32_t		t_lckid;
	int32_t		t_rckid;
	int		t_err;
} load_task_t;

static void *
pfs_meta_loadtask_run(void *arg)
{
	int err = 0;
	load_task_t *task = (load_task_t *)arg;
	int32_t ckid, ndone;
	struct timeval start, end, delta;

	err = gettimeofday(&start, NULL);
	PFS_VERIFY(err == 0);

	ndone = 0;
	for (ckid = task->t_lckid; ckid < task->t_rckid; ckid++) {
		err = pfs_meta_load_chunk(task->t_mnt, ckid);
		if (err < 0)
			break;
		ndone++;
	}
	task->t_err = err;

	err = gettimeofday(&end, NULL);
	PFS_VERIFY(err == 0);
	timersub(&end, &start, &delta);

	pfs_itrace("load task [%d, %d) finished, loaded %d chunks, err=%d,"
	    " time=(%lds %ldus)\n", task->t_lckid, task->t_rckid, ndone,
	    task->t_err, delta.tv_sec, delta.tv_usec);
	return NULL;
}

static void
pfs_meta_loadtask_start(load_task_t *task, pfs_mount_t *mnt, uint32_t startckid,
    int nck)
{
	int rv;

	task->t_err = -EINVAL;
	task->t_thrid = 0;
	task->t_mnt = mnt;
	task->t_lckid = startckid;
	task->t_rckid = startckid + nck;

	rv = pthread_create(&task->t_thrid, NULL,
	    pfs_meta_loadtask_run, (void *)task);
	PFS_VERIFY(rv == 0);
}

static int
pfs_meta_loadtask_wait(load_task_t *task)
{
	int rv;

	PFS_ASSERT(task->t_thrid > 0);
	rv = pthread_join(task->t_thrid, NULL);
	PFS_VERIFY(rv == 0);
	return task->t_err;
}

static int
pfs_meta_load_chunks_parallel(pfs_mount_t *mnt, uint32_t oldnck,
    uint32_t newnck)
{
	int64_t nthrd = loadthread_count;
	int err, err1;
	int32_t nstep, nresd, nck;
	int32_t i, ckid;
	load_task_t taskv[MAX_NTHRD];

	PFS_ASSERT(oldnck < newnck);
	nthrd = MAX(nthrd, MIN_NTHRD);
	nthrd = MIN(nthrd, MAX_NTHRD);
	nthrd = MIN(nthrd, newnck - oldnck);
	pfs_itrace("load %u chunks by %d threads\n", newnck - oldnck, nthrd);

	/*
	 * Every task in [0, nthrd) loads nstep chunk at least.
	 * While task in [0, nresd) will get one more.
	 */
	nstep = (newnck - oldnck) / nthrd;
	nresd = (newnck - oldnck) % nthrd;
	ckid = oldnck;
	for (i = 0; i < nthrd; i++) {
		PFS_ASSERT(i < MAX_NTHRD);
		nck = (i < nresd) ? (nstep + 1) : nstep;
		pfs_meta_loadtask_start(&taskv[i], mnt, ckid, nck);
		ckid += nck;
	}

	/* wait all load workers done */
	err = 0;
	for (i = 0; i < nthrd; i++) {
		err1 = pfs_meta_loadtask_wait(&taskv[i]);
		ERR_UPDATE(err, err1);
	}
	return err;
}

int
pfs_meta_load_all_chunks(pfs_mount_t *mnt)
{
	int err;
	uint32_t i, oldnchunk, nchunk;
	char buf[PBD_SECTOR_SIZE];
	pfs_chunk_phy_t *phyck = (pfs_chunk_phy_t *)buf;
	pfs_chunk_t **newchunkv;

	/* read first chunk */
	err = pfsdev_pread(mnt->mnt_ioch_desc, buf, PBD_SECTOR_SIZE, 0);
	if (err < 0) {
		pfs_etrace("Get first chunk header failed, err=%d\n", err);
		return err;
	}
	pfs_meta_check_chunk(phyck);
	mnt->mnt_blksize = phyck->ck_blksize;
	mnt->mnt_sectsize = phyck->ck_sectsize;
	mnt->mnt_fragsize = PFS_FRAG_SIZE;

	nchunk = phyck->ck_nchunk;
	if ((uint32_t)mnt->mnt_nchunk == nchunk) {
		pfs_etrace("nchunk doesn't change, its value is %d\n",
		    mnt->mnt_nchunk);
		return 0;
	} else if ((uint32_t)mnt->mnt_nchunk > nchunk) {
		pfs_etrace("NOT support shrink chunk from %d to %u\n",
		    mnt->mnt_nchunk, nchunk);
		PFS_ASSERT("shrink is not support" == NULL);
		exit(EINVAL);
	}

	/* realloc mnt_chunkv */
	oldnchunk = mnt->mnt_nchunk;
	PFS_ASSERT((oldnchunk == 0 && mnt->mnt_chunkv == NULL) ||
		   (oldnchunk != 0 && mnt->mnt_chunkv != NULL));
	newchunkv = (pfs_chunk_t **)pfs_mem_realloc(mnt->mnt_chunkv,
	    nchunk * sizeof(pfs_chunk_t *), M_CHUNKV);
	if (newchunkv == NULL)
		ERR_RETVAL(ENOMEM);

	/* load extra chunks */
	pfs_itrace("try to load chunks in [%u, %u)\n", oldnchunk, nchunk);
	mnt->mnt_nchunk = nchunk;
	mnt->mnt_chunkv = newchunkv;
	for (i = oldnchunk; i < nchunk; i++) {
		mnt->mnt_chunkv[i] = NULL;
	}
	err = pfs_meta_load_chunks_parallel(mnt, oldnchunk, nchunk);
	mnt->mnt_disksize = nchunk * PBD_CHUNK_SIZE;
	return err;
}

pfs_metaobj_phy_t *
pfs_meta_alloc(pfs_mount_t *mnt, int mtype, pfs_txop_t *top)
{
	pfs_metaobj_phy_t *mo;

	pfs_meta_lock(mnt);

	mo = metatypes[mtype].mt_alloc(mnt, mtype, top);
	return mo;
}

void
pfs_meta_free(pfs_mount_t *mnt, int mtype, pfs_metaobj_phy_t *mo,
    pfs_txop_t *top)
{
	pfs_meta_lock(mnt);

	metatypes[mtype].mt_free(mnt, mtype, mo, top);
}

pfs_metaobj_phy_t *
pfs_meta_get(pfs_mount_t *mnt, int mtype, uint64_t objno, pfs_txop_t *top,
    int flags)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[mtype];
	void *obj;
	pfs_metaobj_phy_t *mo;

	pfs_meta_lock(mnt);

	obj = pfs_anode_get(anroot, objno, top);
	mo = (pfs_metaobj_phy_t *)obj;
	PFS_ASSERT(mo != NULL);
	/*
	 * Any member visiting of mo here will lead to hot cpu cache missing
	 * if we try to get large number of mo.
	 */
	return mo;
}

int
pfs_meta_undo(pfs_mount_t *mnt, int mtype, uint64_t objno, pfs_txop_t *top)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[mtype];

	pfs_meta_lock(mnt);

	/* pfs_anode_set() returns delta of an_nfree, it maybe negative */
	(void)pfs_anode_undo(anroot, objno, top);

#if CHECK_META
	(void)pfs_anode_walk(anroot, metaset_check_nfree, &nfree);
#endif

	return 0;
}

int
pfs_meta_redo(pfs_mount_t *mnt, int mtype, uint64_t objno, pfs_txop_t *top)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[mtype];

	pfs_meta_lock(mnt);

	/* pfs_anode_set() returns delta of an_nfree, it maybe negative */
	(void)pfs_anode_redo(anroot, objno, top);

#if CHECK_META
	(void)pfs_anode_walk(anroot, metaset_check_nfree, &nfree);
#endif
	return 0;
}

void
pfs_meta_redo_fini(pfs_tx* tx)
{
	int i = MT_NONE;
	for (++i; i < MT_NTYPE; ++i)
		metatypes[i].mt_redo_fini(tx);
}

void
pfs_metaobj_dump(const pfs_metaobj_phy_t *mo, int level)
{
	if (mo->mo_type > MT_NONE && mo->mo_type < MT_NTYPE)
		DUMP_VALUE("%s", level, mo_type, metatypes[mo->mo_type].mt_name);
	else
		DUMP_FIELD("%d", level, mo, mo_type);
	DUMP_FIELD("%lu", level, mo, mo_number);
	DUMP_FIELD("%u", level, mo, mo_checksum);
	DUMP_FIELD("%d", level, mo, mo_used);
	DUMP_FIELD("%lu", level, mo, mo_version);

	switch (mo->mo_type) {
	case MT_BLKTAG: {
		pfs_blktag_phy_t *bt = MO2BT(mo);

		DUMP_FIELD("%lu", level, mo, mo_next);
		DUMP_FIELD("%lu", level, mo, mo_prev);
		DUMP_FIELD("%lu", level+1, bt, bt_ino);
		DUMP_FIELD("%lu", level+1, bt, bt_blkid);
		DUMP_FIELD("%u", level+1, bt, bt_dstatus);
		DUMP_FIELD("%u", level+1, bt, bt_ndiscard);
		DUMP_FIELD("%d", level+1, bt, bt_holelen);
		DUMP_FIELD("%d", level+1, bt, bt_holeoff);
		break;
		}

	case MT_DIRENTRY: {
		pfs_direntry_phy_t *de = MO2DE(mo);

		DUMP_FIELD("%lu", level, mo, mo_next);
		DUMP_FIELD("%lu", level, mo, mo_prev);
		// XXX: not always null-terminated
		PFS_ASSERT(sizeof(de->de_name) == 64);
		DUMP_FIELD("%.64s", level+1, de, de_name);

		if (DE_ISEXT(de)) {
			/* extended direntry */
			DUMP_FIELD("%lu", level+1, de, de_headdeno);
		} else {
			/* head direntry or unused */
			DUMP_FIELD("%ld", level+1, de, de_dirino);
			DUMP_FIELD("%ld", level+1, de, de_ino);
		}
		DUMP_FIELD("%lu", level+1, de, de_extdeno);
		break;
		}

	case MT_INODE: {
		pfs_inode_phy_t *in = MO2IN(mo);

		DUMP_FIELD("%lu", level, mo, mo_head);
		DUMP_FIELD("%lu", level, mo, mo_tail);
		DUMP_FIELD("%u",  level+1, in, in_type);
		DUMP_FIELD("%lu",  level+1, in, in_deno);
		DUMP_FIELD("%u",  level+1, in, in_flags);
		DUMP_FIELD("%u",  level+1, in, in_pvtid); // use original value
		DUMP_FIELD("%lu", level+1, in, in_nlink);
		DUMP_FIELD("%lu", level+1, in, in_nblock);
		DUMP_FIELD("%lu", level+1, in, in_size);
		DUMP_FIELD("%lu", level+1, in, in_atime);
		DUMP_FIELD("%lu", level+1, in, in_ctime);
		DUMP_FIELD("%lu", level+1, in, in_mtime);
		break;
		}
	}
}

void
pfs_meta_used_oid(pfs_mount_t *mnt, int type, int ckid, oidvect_t *ov)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[type];
	uint64_t oid;

	MOUNT_META_RDLOCK(mnt);
	oid = MONO_MAKE((ckid << anroot->an_children[0]->an_shift), 0);
	pfs_anode_visit(anroot, oid, pfs_metaset_used_oid, ov);
	MOUNT_META_UNLOCK(mnt);
}

int
pfs_meta_info(pfs_mount_t *mnt, int depth, pfs_printer_t *printer)
{
	int i, err, err1;

	MOUNT_META_RDLOCK(mnt);
	err = 0;
	for (i = MT_NONE; i < MT_NTYPE; i++) {
		if (i == MT_NONE)
			continue;
		err1 = pfs_anode_dump(&mnt->mnt_anode[i], i, depth, 0, printer);
		ERR_UPDATE(err, err1);
	}
	MOUNT_META_UNLOCK(mnt);
	return err;
}

bool
pfs_meta_bd_mark_inp(pfs_mount_t *mnt, int64_t btno)
{
	int err;
	pfs_tx_t *tx;
	pfs_txop_t *bttop;
	pfs_blktag_phy_t *bt;
	bool marked = false;

	tx = pfs_tls_get_tx();
	err = pfs_tx_new_op(tx, bttop);
	PFS_ASSERT(err == 0);
	(void)err;

	bt = pfs_meta_get_blktag_flags(mnt, btno, bttop, 0);
	PFS_ASSERT(bt != NULL);

	/*
	 * This func just tries to mark blk discarding,
	 * because blktag's flags maybe modified to any
	 * status by others.
	 *
	 * If current blk is in both local bdroot and global
	 * ready/inp tree, it should be not marked and removed
	 * from local bdroot.
	 */
	switch (bt->bt_dstatus) {
	case BDS_READY:
		if (pfs_bd_find(mnt, bt->bt_dstatus, btno) < 0) {
			PFS_ASSERT(bt->bt_ndiscard == 0);
			bt->bt_dstatus = BDS_INP;
			bt->bt_ndiscard++;
			marked = true;
		}
		break;

	case BDS_INP:
		if (pfs_bd_find(mnt, bt->bt_dstatus, btno) < 0) {
			PFS_ASSERT(bt->bt_ndiscard > 0);
			bt->bt_ndiscard++; // force into tx
			marked = true;
		}
		break;

	case BDS_NONE:
		pfs_itrace("blk %llu has dstatus as %d when marking"
		    " discarding\n", btno, bt->bt_dstatus);
		break;

	default:
		pfs_etrace("blk %llu has bad status %d when marking"
		    " discarding\n", btno, bt->bt_dstatus);
		PFS_ASSERT("blk bad status" == NULL);
		break;
	}

#ifdef PFSDEBUG
	if (marked && pfs_inited(mnt))
		pfs_itrace("blk %lu status mark -> %d (ndiscard:%d)\n",
		    btno, bt->bt_dstatus, bt->bt_ndiscard);
#endif

	pfs_tx_done_op(tx, bttop);
	return marked;
}

bool
pfs_meta_bd_mark_done(pfs_mount_t *mnt, int64_t btno)
{
	int err;
	pfs_tx_t *tx;
	pfs_txop_t *bttop;
	pfs_blktag_phy_t *bt;
	bool marked = false;

	tx = pfs_tls_get_tx();
	err = pfs_tx_new_op(tx, bttop);
	PFS_ASSERT(err == 0);

	bt = pfs_meta_get_blktag_flags(mnt, btno, bttop, 0);
	PFS_ASSERT(bt != NULL);
	switch (bt->bt_dstatus) {
	case BDS_INP:
		if (pfs_bd_find(mnt, bt->bt_dstatus, btno) < 0) {
			PFS_ASSERT(bt->bt_ndiscard > 0);
			bt->bt_dstatus = BDS_NONE;
			marked = true;
		}
		break;

	case BDS_READY:
	case BDS_NONE:
		pfs_itrace("blk %llu has dstatus as %d when marking"
		    " discarded\n", btno, bt->bt_dstatus);
		break;

	default:
		pfs_etrace("blk %llu has bad status %d when marking"
		    " discarded\n", btno, bt->bt_dstatus);
		PFS_ASSERT("blk bad status" == NULL);
		break;
	}

#ifdef PFSDEBUG
	if (marked && pfs_inited(mnt))
		pfs_itrace("blk %lu status mark -> %d (ndiscard:%d)\n",
		    btno, bt->bt_dstatus, bt->bt_ndiscard);
#endif

	pfs_tx_done_op(tx, bttop);
	return marked;
}

static void
pfs_meta_bd_change_index(pfs_mount_t *mnt, pfs_blktag_phy_t *bt)
{
	int64_t btno = MONO_CURR(bt);
	switch (bt->bt_dstatus) {
	case BDS_READY:
		pfs_bd_add(mnt, bt->bt_dstatus, btno);
		pfs_bd_del(mnt, BDS_INP, btno);
		break;

	case BDS_INP:
		pfs_bd_add(mnt, bt->bt_dstatus, btno);
		pfs_bd_del(mnt, BDS_READY, btno);
		break;

	case BDS_NONE:
		pfs_bd_del(mnt, BDS_READY, btno);
		pfs_bd_del(mnt, BDS_INP, btno);
		break;

	default:
		pfs_etrace("blk %llu has bad status %d when changing"
		    " index\n", btno, bt->bt_dstatus);
		PFS_ASSERT("blk bad status" == NULL);
		break;
	}

#ifdef PFSDEBUG
	if (pfs_inited(mnt))
		pfs_itrace("blk %lu status change -> %d (ndiscard:%d)\n",
		    btno, bt->bt_dstatus, bt->bt_ndiscard);
#endif
}

void
pfs_meta_bd_build_index(pfs_mount_t *mnt)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[MT_BLKTAG];

	MOUNT_META_WRLOCK(mnt);
	pfs_anode_walk(anroot, pfs_metaset_bd_build_index, mnt);
	MOUNT_META_UNLOCK(mnt);
}

void
pfs_meta_bd_select(pfs_mount_t *mnt, int64_t ckid, void *data)
{
	pfs_anode_t *anroot = &mnt->mnt_anode[MT_BLKTAG];
	uint64_t oid;

	MOUNT_META_RDLOCK(mnt);
	oid = MONO_MAKE((ckid << anroot->an_children[0]->an_shift), 0);
	pfs_anode_visit(anroot, oid, pfs_metaset_bd_select, data);
	MOUNT_META_UNLOCK(mnt);
}

void
pfs_meta_visit(pfs_mount_t *mnt, int type, int ckid, int objid,
    pfs_meta_visitfn_t *visitfunc, void *visitdata)
{
	pfs_anode_t *anroot;
	uint64_t oid;
	metaset_visit_t msv;

	PFS_ASSERT(type > MT_NONE && type < MT_NTYPE);
	anroot = &mnt->mnt_anode[type];

	pfs_meta_lock(mnt);
	if (objid < 0) {
		oid = MONO_MAKE((ckid << anroot->an_children[0]->an_shift), 0);
		msv.msv_type = VISIT_ALL;
		msv.msv_oid = (int64_t)-1;
	} else {
		oid = MONO_MAKE((ckid << anroot->an_children[0]->an_shift), objid);
		msv.msv_type = VISIT_ONE;
		msv.msv_oid = (int64_t)objid;
	}
	msv.msv_func = visitfunc;
	msv.msv_data = visitdata;
	pfs_anode_visit(anroot, oid, pfs_metaset_visit, &msv);
	pfs_meta_unlock(mnt);
}

#define FIELD_CP_DEF(type, psrc, pdest) \
	const type *src = (const type *)psrc; \
	type *dest = (type *)pdest

/*
 * FIELD_CP_INT is atomic, so lock is not needed if the reader does not pay
 * attention to the version it reads while read/write is executed parallelly.
 */
#define FIELD_CP_INT(field) \
	__atomic_store_n(&dest->field, src->field, __ATOMIC_RELAXED)

/*
 * FIELD_CP_STR is not atomic, so lock is needed.
 */
#define FIELD_CP_STR(field) \
	memcpy(&dest->field, src->field, sizeof(src->field))

static inline void
pfs_metaobj_cp_base(const pfs_metaobj_phy_t *psrc, pfs_metaobj_phy_t *pdest)
{
	FIELD_CP_DEF(pfs_metaobj_phy_t, psrc, pdest);
	FIELD_CP_INT(mo_number);
	FIELD_CP_INT(mo_version);
	FIELD_CP_INT(mo_next);
	FIELD_CP_INT(mo_prev);
	FIELD_CP_INT(mo_type);
	FIELD_CP_INT(mo_used);
	FIELD_CP_INT(mo_padding[0]);
	FIELD_CP_INT(mo_padding[1]);
	FIELD_CP_INT(mo_checksum);
}

static void
pfs_metaobj_cp_blktag(const pfs_metaobj_phy_t *psrc, pfs_metaobj_phy_t *pdest)
{
	FIELD_CP_DEF(pfs_blktag_phy_t, &psrc->mo_data, &pdest->mo_data);
	pfs_metaobj_cp_base(psrc, pdest);
	FIELD_CP_INT(bt_ino);
	FIELD_CP_INT(bt_blkid);
	FIELD_CP_INT(bt_dstatus);
	FIELD_CP_INT(bt_ndiscard);
	FIELD_CP_INT(bt_holelen);
	FIELD_CP_INT(bt_holeoff);
}

static void
pfs_metaobj_cp_dentry(const pfs_metaobj_phy_t *psrc, pfs_metaobj_phy_t *pdest)
{
	FIELD_CP_DEF(pfs_direntry_phy_t, &psrc->mo_data, &pdest->mo_data);
	pfs_metaobj_cp_base(psrc, pdest);
	/*
	 * dentry name visiting is always not atomic if lock is not used.
	 * pay attention to the implementation of "pfs_direntry_getname".
	 */
	FIELD_CP_STR(de_name);
	FIELD_CP_INT(de_ino);
	FIELD_CP_INT(de_dirino);
	FIELD_CP_INT(de_extdeno);
}

static void
pfs_metaobj_cp_inode(const pfs_metaobj_phy_t *psrc, pfs_metaobj_phy_t *pdest)
{
	FIELD_CP_DEF(pfs_inode_phy_t, &psrc->mo_data, &pdest->mo_data);
	pfs_metaobj_cp_base(psrc, pdest);
	FIELD_CP_INT(in_type);
	FIELD_CP_INT(in_flags);
	FIELD_CP_INT(in_padding);
	FIELD_CP_INT(in_pvtid);
	FIELD_CP_INT(in_deno);
	FIELD_CP_INT(in_nlink);
	FIELD_CP_INT(in_nblock);
	FIELD_CP_INT(in_size);
	FIELD_CP_INT(in_atime);
	FIELD_CP_INT(in_ctime);
	FIELD_CP_INT(in_mtime);
	FIELD_CP_INT(in_btime);
}

void
pfs_metaobj_cp(const pfs_metaobj_phy_t *src, pfs_metaobj_phy_t *dest)
{
	static void (*pfs_meta_func_array[MT_NTYPE])(const pfs_metaobj_phy_t *,
	    pfs_metaobj_phy_t *) = {
	    NULL, pfs_metaobj_cp_blktag, pfs_metaobj_cp_dentry, pfs_metaobj_cp_inode};
	PFS_ASSERT(src->mo_type > 0 && src->mo_type < MT_NTYPE);
	pfs_meta_func_array[src->mo_type](src, dest);
}
