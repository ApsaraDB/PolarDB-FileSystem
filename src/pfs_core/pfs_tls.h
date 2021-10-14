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

#ifndef	_PFS_TLS_H_
#define	_PFS_TLS_H_

#include <assert.h>
#include <setjmp.h>
#include <time.h>

#include "pfs_devio.h"
#include "pfs_impl.h"

typedef struct pfs_tx 		pfs_tx_t;
typedef struct pfs_mount	pfs_mount_t;

typedef struct pfs_bd_info {
	pfs_mount_t	*i_mnt;
	int		i_err;
	int		i_ntotal;
	int		i_ndone;
} pfs_bd_info_t;

/*
 * Thread Local Storage.
 *
 *
 */
typedef struct pfs_tls {
	pfs_tx_t	*tls_tx;		/* tx for meta data change */
	int64_t		tls_req_ttl;		/* ttl for io reqeusts;
						 * 0 means unlimited  */
	pfs_bd_info_t	*tls_bdi;
	void		*tls_orphan_data;

	int		tls_stat_file_type;
	int		tls_stat_api_type;
	uint32_t	tls_stat_ver;
	bool		tls_meta_locked;
	/*
	 * One thread may issues I/O to multiple devices,
	 * so each device should have private aio in tls,
	 * and aio is identified by unique id of the device
	 * it corresponds to.
	 */
	pfs_ioq_t	*tls_ioqueue[PFS_MAX_NCHD];	/* private data for dev */
	/*
	 * This field is only used by disk dev to convert
	 * unaligned ptr to aligned ptr.
	 */
	char		*tls_directio_buf;
} pfs_tls_t;

pfs_tls_t 	*pfs_current_tls();
pfs_ioq_t	*pfs_tls_get_ioq(int devi, uint64_t epoch);
void		pfs_tls_set_ioq(int devi, pfs_ioq_t *ioq);

/*
 * The macros below make tx as a thread local variable.
 * Tx will be retrieved when either a new tx op is added or
 * meta data need a lock protection.
 */
#define	tls_write_begin_flags(mnt, timeoutfail)	do {			\
	int _err = 0;							\
	do {								\
		if ((_err = pfs_tx_begin(mnt, timeoutfail)) != 0)	\
			break;

#define	tls_write_begin(mnt)						\
		tls_write_begin_flags(mnt, false)

#define	tls_write_end(err)						\
		_err = pfs_tx_end(err);					\
	} while (0);							\
	err = _err;							\
} while (0)

#define	tls_read_begin_flags(mnt, needsync)	do {			\
	int _err = 0;							\
	do {								\
		pfs_mount_t* _mnt = mnt;				\
		if (pfs_loggable(mnt) && pfs_inited(mnt) &&		\
		    (needsync) && (_err = pfs_mount_sync(mnt)) != 0) {	\
			break;						\
		}

#define	tls_read_begin(mnt)						\
		bool _needsync = pfs_mount_needsync(mnt);		\
		tls_read_begin_flags(mnt, _needsync)

#define	tls_read_end(err) 						\
		pfs_meta_unlock(_mnt);					\
		_err = err;						\
	} while (0);							\
	err = _err;							\
} while (0)

#if 0
/*
 * Set up the replay tx if necessary. For write, the thread must
 * have already locked the meta data, since it has updated meta
 * data while holding the meta data lock; for read, it is polling new
 * log entries and has not locked the meta data; for load tx, it
 * is the same as the read tx.
 */
#define	tls_replay_begin(mnt, replaytxq)	do {			\
	pfs_tx_t *_oldtx = pfs_tls_get_tx(); 				\
	pfs_tx_t *_newtx;						\
	if (_oldtx) {							\
		PFS_ASSERT(_oldtx->t_type == TXT_WRITE);		\
		_newtx = NULL;						\
	} else {							\
		_newtx = TAILQ_FIRST(replaytxq);			\
		pfs_tls_set_tx(_newtx);					\
		pfs_meta_lock(mnt);					\
	}

#define	tls_replay_end(err)						\
	if (_newtx) {							\
		pfs_meta_unlock(mnt);					\
		pfs_tls_set_tx(NULL);					\
	}
	err = pfs_log_request(&mnt->mnt_log, LOG_REPLAYDONE, NULL, replaytxq);
	PFS_ASSERT(err == 0 && TAILQ_EMPTY(replaytxq) == true);
} while (0)
#endif


static inline void
pfs_tls_set_tx(pfs_tx_t *tx)
{
	pfs_tls_t *tls = pfs_current_tls();

	tls->tls_tx = tx;
}

static inline pfs_tx_t *
pfs_tls_get_tx()
{
	pfs_tls_t *tls = pfs_current_tls();

	return tls->tls_tx;
}


static inline int64_t
pfs_tls_get_ttl()
{
	pfs_tls_t *tls = pfs_current_tls();

	return tls->tls_req_ttl;
}

/*
 * Set the request ttl. Log IO may hang and timeout is
 * the only way to detect failures of other hosts.
 *
 * rttl value is:
 * positive:	relative time since now;
 * zero:	no limited;
 * negative:	illegal;
 */
static inline void
pfs_tls_set_ttl(int64_t rttl)
{
	pfs_tls_t *tls = pfs_current_tls();

	PFS_ASSERT(rttl >= 0);
	if (rttl > 0)
		rttl += time(NULL);

	tls->tls_req_ttl = rttl;
}

static inline void
pfs_tls_add_ttl(int64_t delta)
{
	pfs_tls_t *tls = pfs_current_tls();

	tls->tls_req_ttl += delta;
	if (tls->tls_req_ttl < 0)
		tls->tls_req_ttl = 0;
}

static inline pfs_bd_info_t*
pfs_tls_get_bdinfo()
{
	pfs_tls_t *tls = pfs_current_tls();

	return tls->tls_bdi;
}

static inline void
pfs_tls_set_bdinfo(pfs_bd_info_t *bdi)
{
	pfs_tls_t *tls = pfs_current_tls();

	/* overwrite is not allowed */
	PFS_ASSERT(bdi == NULL || tls->tls_bdi == NULL);
	tls->tls_bdi = bdi;
}

static inline int
pfs_tls_get_stat_file_type()
{
	pfs_tls_t *tls = pfs_current_tls();

	return tls->tls_stat_file_type;
}

static inline void
pfs_tls_set_stat_file_type(int file_type)
{
	pfs_tls_t *tls = pfs_current_tls();

	tls->tls_stat_file_type = file_type;
}

static inline int
pfs_tls_get_stat_api_type()
{
	pfs_tls_t *tls = pfs_current_tls();

	return tls->tls_stat_api_type;
}

static inline void
pfs_tls_set_stat_api_type(int api_type)
{
	pfs_tls_t *tls = pfs_current_tls();

	tls->tls_stat_api_type = api_type;
}

static inline uint32_t
pfs_tls_get_stat_ver()
{
	pfs_tls_t *tls = pfs_current_tls();

	return tls->tls_stat_ver;
}

static inline void
pfs_tls_set_stat_ver(uint32_t stat_ver)
{
	pfs_tls_t *tls = pfs_current_tls();

	tls->tls_stat_ver = stat_ver;
}

#endif	/* _PFS_TLS_H_ */

// vim: ts=8 sw=8 noexpandtab
