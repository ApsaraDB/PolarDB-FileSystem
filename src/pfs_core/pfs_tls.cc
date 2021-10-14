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
#include <pthread.h>

#include "pfs_impl.h"
#include "pfs_tls.h"
#include "pfs_trace.h"
#include "pfs_stat.h"

/*
 * TLS manages txs, locks, and meta data exception handling.
 *
 * A tx is a description about the modification to meta data by one thread,
 * and is the unit to ensure aomicity of the modification. There are two
 * kinds of txs. One is write tx, that holds the modification by this node.
 * The other is replay tx, polled by log thread, that hold modification by
 * other node. TLS manages the write tx only.
 *
 * Locks are needed to access inode and meta data. All locks acquired by
 * the thread is saved in TLS, so that when meta data exception is encountered,
 * they can be released.
 *
 * Meta data exception means invalid meta data caused by replay tx is encountered
 * when traversing the meta data cache. In such a case, there is no simple and
 * clean way to handle it, since we may be deep in the dirtory entry tree. We
 * exploy longjmp to return to our starting point, alougth it is not elegant.
 */

static pthread_key_t	pfs_tls_key;

static pfs_tls_t *
pfs_tls_create()
{
	pfs_tls_t *tls;

	tls = (pfs_tls_t *)pfs_mem_malloc(sizeof(*tls), M_TLS);
	PFS_ASSERT(tls != NULL);

	memset(tls, 0, sizeof(*tls));
	tls->tls_tx = NULL;
	tls->tls_req_ttl = 0;
	tls->tls_bdi = NULL;
	tls->tls_meta_locked = false;

	tls->tls_stat_ver = 0;
	tls->tls_stat_api_type = MNT_STAT_BASE;
	tls->tls_stat_file_type = FILE_PFS_INITED;
	pfs_mntstat_nthreads_change(1);

	for (int i = 0; i < PFS_MAX_NCHD; i++) {
		tls->tls_ioqueue[i] = NULL;
	}
	return tls;
}

static void
pfs_tls_destroy(void *data)
{
	pfs_tls_t *tls = (pfs_tls_t *)data;
	pfs_ioq_t *ioq;

	if (tls == NULL)
		return;
	/*
	 * NOTE: never call get_current_tls() in this func!
	 * or we will get a new tls, rather than the "tls" refered to
	 */
	PFS_ASSERT(tls->tls_tx == NULL);
	for (int i = 0; i < PFS_MAX_NCHD; i++) {
		ioq = tls->tls_ioqueue[i];
		if (ioq) {
			ioq->ioq_destroy(ioq);
			tls->tls_ioqueue[i] = NULL;
		}
	}
	pfs_mem_free(tls, M_TLS);
	pfs_mntstat_nthreads_change(-1);
}

void __attribute__((constructor))
init_pfs_tls()
{
	int err;

	/*
	 * Create the tls key even before entering into main, to
	 * provide context for each comming thread.
	 */
	err = pthread_key_create(&pfs_tls_key, pfs_tls_destroy);
	PFS_VERIFY(err == 0);
}

void
pfs_tls_fini()
{
	pthread_key_delete(pfs_tls_key);
}

pfs_tls_t *
pfs_current_tls()
{
	int err;
	pfs_tls_t *tls;

	tls = (pfs_tls_t *)pthread_getspecific(pfs_tls_key);
	if (tls == NULL) {
		tls = pfs_tls_create();
		err = pthread_setspecific(pfs_tls_key, tls);
		PFS_VERIFY(err == 0);
	}
	return tls;
}

pfs_ioq_t *
pfs_tls_get_ioq(int devi, uint64_t epoch)
{
	pfs_tls_t *tls = pfs_current_tls();
	pfs_ioq_t *ioq;
	PFS_VERIFY(tls != NULL);
	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	/*
	 * the expiring of ioq indicates the device is umounted,
	 * reset it before returning to IO thread
	 */
	ioq = tls->tls_ioqueue[devi];
	if (ioq != NULL && ioq->ioq_epoch != epoch) {
		ioq->ioq_destroy(ioq);
		tls->tls_ioqueue[devi] = NULL;
	}
	return tls->tls_ioqueue[devi];
}

void
pfs_tls_set_ioq(int devi, pfs_ioq_t *ioq)
{
	pfs_tls_t *tls = pfs_current_tls();
	PFS_VERIFY(tls != NULL);
	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	/* overwrite is not allowed */
	PFS_ASSERT(tls->tls_ioqueue[devi] == NULL && ioq != NULL);
	tls->tls_ioqueue[devi] = ioq;
}
