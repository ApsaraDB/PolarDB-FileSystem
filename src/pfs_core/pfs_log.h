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

#ifndef	_PFS_LOG_H_
#define	_PFS_LOG_H_

#include <sys/queue.h>
#include <pthread.h>

#include "pfs_paxos.h"
#include "pfs_tx.h"

typedef struct pfs_mount pfs_mount_t;
typedef struct pfs_file	pfs_file_t;
typedef struct pfs_tx	pfs_tx_t;
typedef struct pfs_sectbuf pfs_sectbuf_t;

enum {
	LOG_MERGED = 0,

	LOG_LOAD,
	LOG_REPLAYDONE,
	LOG_TRIM,
	LOG_POLL,
	LOG_TRY_RESET_LOCK,
	LOG_WRITE,
	LOG_FLUSH,
	LOG_SUSPEND,
	LOG_RESUME,
	LOG_STOP,

	LOG_NREQ,

	LOG_REPLAY_WAIT,	/* private wait queue */

	LOG_NMAX,
};

struct log_req;
TAILQ_HEAD(req_qhead, log_req);
typedef	struct log_req {
	TAILQ_ENTRY(log_req) r_next;
	pthread_mutex_t	r_mtx;
	pthread_cond_t	r_cond;
	int		r_type;
	bool		r_done;
	int		r_error;
	pfs_tx_t 	*r_itx;
	struct tx_qhead	*r_otxq;
	int		r_hostid;
	int		r_next_hostid;
} log_req_t;

/*
 * A trimgroup collects dirty sectors of meta data that
 * should be flushed onto disk when log trim is performed.
 *
 * The meta data sectors are from transactions in the range
 * (g_ltxid, g_rtxid], as sorted in g_sects. These sectors
 * are also sorted by their block addresses in a search tree
 * g_rootp. The search tree helps to find out whether a sector
 * is modified multiple times.
 */
typedef struct pfs_trimgroup {
	pfs_txid_t			g_ltxid;
	pfs_txid_t			g_rtxid;
	uint64_t			g_roffset;
	int64_t				g_nsects;
	int64_t				g_nsects_empty;
	pfs_sectbuf_t			*g_sect_empty_first; /* before the pointer in g_sects,
							   every sect must have been memcpied.*/
	struct sectbuf_qhead		g_sects;	/* sort by txid in
							   non-descending order */
	void				*g_rootp;	/* bda search index */
} pfs_trimgroup_t;

typedef struct pfs_log {
	pfs_mount_t	*log_mount;
	int		log_state;
	int		log_flags;

	pthread_t	log_tid;	/* log IO thread */
	pthread_mutex_t	log_mtx;
	pthread_cond_t	log_cond;
	struct req_qhead log_reqhead;

	pfs_file_t	*log_file;
	pfs_leader_record_t	log_leader;
	char		*log_workbuf;
	ssize_t		log_workbufsz;

	log_req_t	log_trimreq;

	pfs_trimgroup_t	log_grpbuf[2];
	pfs_trimgroup_t	*log_workgrp;	/* somewhere to collect new tx */
	pfs_trimgroup_t	*log_waitgrp;	/* somewhere existed txs wait to be trimmed */

	struct timespec	log_trimts;

	bool		log_paxos_got;	/* whether got paxos */
	pfs_leader_record_t	log_leader_latest;/* cache of disk pfs_leader_record */
	struct timespec	log_paxos_ts;	/* timestamp of having got paxos */
} pfs_log_t;

typedef struct pfs_logentry_phy {
	pfs_metaobj_phy_t le_obj_val;
	int64_t		le_lsn;
	uint64_t	le_sector_bda;
	int64_t		le_txid;
	uint32_t	le_obj_idx;
	uint32_t	le_checksum;
	int		le_more;
} __attribute__((aligned(256))) pfs_logentry_phy_t;

void	pfs_log_dump(pfs_logentry_phy_t *lebuf, uint32_t nle, int level);

int 	pfs_log_start(pfs_log_t *log);
void 	pfs_log_stop(pfs_log_t *log);
int 	pfs_log_write(pfs_log_t *log, char *buf, size_t buflen,
	    uint64_t offset);
void	pfs_log_suspend(pfs_log_t *log);
void	pfs_log_resume(pfs_log_t *log);
int	pfs_log_commit(pfs_log_t *log, pfs_txid_t txid, pfs_lsn_t lsn);
void 	pfs_log_enqueue(pfs_log_t *log, pfs_tx_t *tx);
int	pfs_log_preload(pfs_log_t *log);

#define pfs_log_request(log, type, tx, rplhead) pfs_log_request_impl(log, \
	type, tx, rplhead, -1, -1)
int 	pfs_log_request_impl(pfs_log_t *log, int type, pfs_tx_t *tx,
	    struct tx_qhead *rplhead, int host_id, int next_host_id);

#endif	/* _PFS_LOG_H_ */
