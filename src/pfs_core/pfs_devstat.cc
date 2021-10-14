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

#include <stddef.h>
#include "pfs_admin.h"
#include "pfs_devio.h"
#include "pfs_devstat.h"

extern uint64_t			pfs_devs_epoch;
extern pfs_dev_t		*pfs_devs[PFS_MAX_NCHD];

struct devstat_snap {
	struct timeval	s_snaptime;
	uint64_t	s_ndev;
	uint64_t	s_epoch;

	char		s_cluster[PFS_MAX_CLUSTERLEN];
	char		s_devname[PFS_MAX_PBDLEN];
	int		s_type;
	int		s_flags;
	char		s_iostat[offsetof(pfs_devstat_t, ds_iostat_end) -
				 offsetof(pfs_devstat_t, ds_iostat_start)];
};

void
pfs_devstat_init(pfs_devstat_t *ds)
{
	memset(ds, 0, sizeof(*ds));
	rwlock_init(&ds->ds_rwlock, NULL);
}

void
pfs_devstat_uninit(pfs_devstat_t *ds)
{
	PFS_ASSERT(ds->ds_start_count == ds->ds_end_count);
	rwlock_destroy(&ds->ds_rwlock);
}

void
pfs_devstat_io_start(pfs_devstat_t *ds, const pfs_devio_t *io)
{
	PFS_ASSERT(ds == &io->io_dev->d_ds);
	if (!(io->io_flags & IO_STAT))
		return;

	rwlock_wrlock(&ds->ds_rwlock);
	if (ds->ds_start_count == ds->ds_end_count)
		ds->ds_busy_from = io->io_start_ts;
	ds->ds_start_count++;
	rwlock_unlock(&ds->ds_rwlock);
}

void
pfs_devstat_io_end(pfs_devstat_t *ds, const pfs_devio_t *io)
{
	int		op = io->io_op;
	int		err;
	struct timeval	now, delta;

	PFS_ASSERT(ds == &io->io_dev->d_ds);
	if (!(io->io_flags & IO_STAT))
		return;

	/* setup end timestamp */
	err = gettimeofday(&now, NULL);
	PFS_VERIFY(err == 0);

	rwlock_wrlock(&ds->ds_rwlock);
	/* if succeed, update statistics */
	if (io->io_error == 0) {
		ds->ds_bytes[op] += io->io_len;
		ds->ds_ops[op]++;
		timersub(&now, &io->io_start_ts, &delta);
		timeradd(&ds->ds_duration[op], &delta,
		    &ds->ds_duration[op]);
	}

	/* accumulate total busy time */
	timersub(&now, &ds->ds_busy_from, &delta);
	timeradd(&ds->ds_busy_time, &delta, &ds->ds_busy_time);
	ds->ds_busy_from = now;

	ds->ds_end_count++;
	// count - ops == failed_io_cnt
	rwlock_unlock(&ds->ds_rwlock);
}

#if 0
static void
print_devstat(devstat_snap *snap)
{
	pfs_devstat_t	stat;
	memcpy(&stat.ds_start_count, snap->s_iostat, sizeof(snap->s_iostat));

	pfs_itrace("print_devstat:\n");
	pfs_itrace("\tsnaptime: %ld.%ld\nndev: %lu\nglobal epoch: %lu\n",
	    snap->s_snaptime.tv_sec, snap->s_snaptime.tv_usec,
	    snap->s_ndev, snap->s_epoch);

	pfs_itrace("\tcluster: %s\n\tpbdname: %s\n\ttype: %d\n\tflags: %d\n",
	    snap->s_cluster, snap->s_devname, snap->s_type, snap->s_flags);

	pfs_itrace("\tstart_count: %lu\n\tend_count: %lu\n",
	    stat.ds_start_count, stat.ds_end_count);
	pfs_itrace("\tbusy_time: %ld.%ld\n",
	    stat.ds_busy_time.tv_sec, stat.ds_busy_time.tv_usec);
	pfs_itrace("\tbytes: R %lu, W %lu, T %lu\n",
	    stat.ds_bytes[PFSDEV_REQ_RD], stat.ds_bytes[PFSDEV_REQ_WR], stat.ds_bytes[PFSDEV_REQ_TRIM]);
	pfs_itrace("\tops: R %lu, W %lu, T %lu\n",
	    stat.ds_ops[PFSDEV_REQ_RD], stat.ds_ops[PFSDEV_REQ_WR], stat.ds_ops[PFSDEV_REQ_TRIM]);
	pfs_itrace("\tduration: R %ld.%ld, W %ld.%ld, T %ld.%ld\n",
	    stat.ds_duration[PFSDEV_REQ_RD].tv_sec, stat.ds_duration[PFSDEV_REQ_RD].tv_usec,
	    stat.ds_duration[PFSDEV_REQ_WR].tv_sec, stat.ds_duration[PFSDEV_REQ_WR].tv_usec,
	    stat.ds_duration[PFSDEV_REQ_TRIM].tv_sec, stat.ds_duration[PFSDEV_REQ_TRIM].tv_usec);
}
#endif

int
pfs_devstat_snap(int devi, admin_buf_t *ab)
{
	pfs_dev_t		*dev = pfs_devs[devi];
	int			err, n;
	struct devstat_snap	*snap;
	pfs_devstat_t		*ds;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD && dev != NULL);
	ds = &dev->d_ds;

	/* 1. reserve buffer */
	snap = (struct devstat_snap *)pfs_adminbuf_reserve(ab, sizeof(*snap));
	if (snap == NULL)
		ERR_RETVAL(ENOBUFS);

	/* 2. set snapshot header info */
	err = gettimeofday(&snap->s_snaptime, NULL);
	PFS_VERIFY(err == 0);
	snap->s_ndev = 1;
	snap->s_epoch = pfs_devs_epoch;

	/* 3. copy statistics */
	n = strncpy_safe(snap->s_cluster, dev->d_cluster, sizeof(snap->s_cluster));
	PFS_VERIFY(n > 0);
	n = strncpy_safe(snap->s_devname, dev->d_devname, sizeof(snap->s_devname));
	PFS_VERIFY(n > 0);
	snap->s_type = dev->d_type;
	snap->s_flags = dev->d_flags;

	rwlock_rdlock(&ds->ds_rwlock);
	memcpy(snap->s_iostat, (char *)&ds->ds_iostat_start,
	    sizeof(snap->s_iostat));
	rwlock_unlock(&ds->ds_rwlock);

	pfs_adminbuf_consume(ab, sizeof(*snap));
	return 0;
}
