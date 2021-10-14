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

#ifndef	_PFS_TX_H_
#define	_PFS_TX_H_

#include <sys/queue.h>
#include <pthread.h>

#include "pfs_impl.h"
#include "pfs_tls.h"
#include "pfs_meta.h"

typedef struct pfs_mount pfs_mount_t;
typedef struct pfs_logentry_phy pfs_logentry_phy_t;
typedef struct pfs_inode pfs_inode_t;

enum {
	TXT_INVALID	= 0,
	TXT_WRITE,
	TXT_REPLAY,
};

typedef struct pfs_tx	pfs_tx_t;

typedef struct pfs_sectbuf {
	uint64_t			s_bda;
	TAILQ_ENTRY(pfs_sectbuf)	s_next;
	pfs_txid_t			s_txid;
	char *				s_buf;
	char *				s_metabuf;
} pfs_sectbuf_t;
TAILQ_HEAD(sectbuf_qhead, pfs_sectbuf);

struct pfs_txop;
struct pfs_txcb;
struct pfs_tx;
TAILQ_HEAD(txop_qhead, pfs_txop);
TAILQ_HEAD(txcb_qhead, pfs_txcb);
TAILQ_HEAD(tx_qhead, pfs_tx);

typedef void	pfs_txop_callback_t(pfs_mount_t *, pfs_metaobj_phy_t *, int);
typedef void	pfs_tx_callback_t(pfs_mount_t *, int64_t, int);

/*
 * rename a file from a dir to a new dir and replace a file, it will affect
 * the 4 inodes and this is the maximum affected inodes count in a pfs tx till
 * now.
 */
#define TX_RPL_MAX_INODES 4
typedef struct pfs_rpl_ctx {
	pfs_inode_t	*r_inodes[TX_RPL_MAX_INODES];
} pfs_rpl_ctx_t;

typedef struct pfs_tx {
	int			t_type;
	TAILQ_ENTRY(pfs_tx) 	t_next;
	pfs_mount_t 		*t_mnt;		/* fs of the tx */
	int64_t			t_id;
	int			t_error;
	bool			t_done;
	bool			t_timeoutfail;	/* whether return error
						   if ETIMEDOUT */

	int			t_nops;
	struct txop_qhead 	t_ops;
	tnode_t			*t_opsroot;

	int			t_ncbs;
	struct txcb_qhead	t_cbs;

	pfs_rpl_ctx_t		t_rpl_ctx;
} pfs_tx_t;

typedef struct pfs_txop {
	/*
	 * Following meta object should be put at first of the struct for index.
	 *
	 * For local tx, we should access the union via top_local before tx is
	 * committed. Once tx is committed, top_remote should be used.
	 *
	 * During replaying remote tx, top_remote should be the only interfaces
	 * because the tx has been committed remotely.
	 */
	union {
		pfs_metaobj_phy_t top_local;	/* value after modification */
		pfs_metaobj_phy_t top_remote;	/* value after committed */
	};

	/* debug info: func, line, and name */
	const char		*top_func;
	const char		*top_name;
	int			top_line;

	uint32_t		top_flags;
	pfs_tx_t		*top_tx;	/* tx of the op */
	TAILQ_ENTRY(pfs_txop) 	top_next;	/* op link in a tx */
	pfs_metaobj_phy_t 	*top_buf;	/* modified memory buffer */
	uint64_t		top_bda;	/* sector block address */
	int			top_idx;	/* object index */

	pfs_txop_callback_t 	*top_cb;	/* callback func, NEVER depend on mo */

	pfs_txop_t		*top_dup_head;	/* head of top shadow chain */
	pfs_txop_t		*top_shadow;	/* txops on same mo are shadowed */
	int			top_dup_cnt;	/* number of shadow txops that nested */
	int			top_dup_idx;	/* index in nested stack */
} pfs_txop_t;

typedef struct pfs_txcb {
	TAILQ_ENTRY(pfs_txcb)	tcb_next;
	pfs_tx_callback_t	*tcb_func;
	int64_t			tcb_data;
} pfs_txcb_t;

int		_pfs_tx_new_op(pfs_tx_t *tx, pfs_txop_t **topp, const char *user,
		    const char *name, int line);
void		_pfs_tx_done_op(pfs_tx_t *tx, pfs_txop_t *top, pfs_txop_callback_t *cb);
int		_pfs_tx_recreate_op(pfs_tx_t *tx, pfs_logentry_phy_t *le,
		    pfs_txop_t **topp, const char *func, const char *name,
		    int line);
int		pfs_tx_commit(pfs_tx_t *tx);
void		pfs_txlist_replay(pfs_mount_t *mnt, struct tx_qhead *txq);
int		pfs_tx_log(pfs_tx_t *tx, uint64_t head_txid, uint64_t head_lsn,
		    uint64_t head_offset, char *buf, int buflen);
pfs_tx_t *	pfs_tx_get(pfs_mount_t *mnt, int type, bool timeoutfail);
void		pfs_tx_put(pfs_tx_t *tx);
int		pfs_tx_begin(pfs_mount_t *mnt, bool timeoutfail);
int		pfs_tx_end(int err);
void		pfs_tx_add_callback(pfs_tx_t *tx, pfs_tx_callback_t *cbfunc, int64_t cbdata);
void		pfs_tx_apply(pfs_tx_t *tx);

pfs_sectbuf_t *	pfs_sectbuf_get();
void		pfs_sectbuf_bind(pfs_sectbuf_t *sbuf, const pfs_txop_t *top);
void		pfs_sectbuf_sync(pfs_sectbuf_t *sbuf, const pfs_txop_t *top);
void		pfs_sectbuf_put(pfs_sectbuf_t *sbuf);

/* api to meta layer */
pfs_metaobj_phy_t*
		pfs_txop_init(pfs_txop_t *top, pfs_metaobj_phy_t *buf,
		    int oid, pfs_bda_t bda);
pfs_metaobj_phy_t*
		pfs_tx_get_mo(pfs_tx_t *tx, pfs_metaobj_phy_t *obj);

int		pfs_txop_redo(pfs_txop_t *top, pfs_metaobj_phy_t *mo, void *buf);
int		pfs_txop_undo(pfs_txop_t *top, pfs_metaobj_phy_t *mo);
int		pfs_txop_load(pfs_txop_t *top, pfs_mount_t *mnt);

static inline bool
pfs_tx_empty(pfs_tx_t *tx)
{
	return TAILQ_EMPTY(&tx->t_ops);
}

#define	pfs_tx_new_op(tx, top) 				\
	_pfs_tx_new_op(tx, &top, __func__, #top, __LINE__)

#define	pfs_tx_recreate_op(tx, le, top) 		\
	_pfs_tx_recreate_op(tx, le, &top, __func__, #top, __LINE__)

#define	pfs_tx_done_op_callback(tx, top, callback)	\
	_pfs_tx_done_op(tx, top, callback)

#define	pfs_tx_done_op(tx, top)				\
	_pfs_tx_done_op(tx, top, NULL)

#endif
