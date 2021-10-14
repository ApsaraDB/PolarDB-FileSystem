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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pfs_admin.h"
#include "pfs_devio.h"
#include "pfs_devstat.h"
#include "pfs_impl.h"
#include "pfs_mount.h"
#include "pfs_tls.h"
#include "pfs_trace.h"
#include "pfs_stat.h"
#include "pfs_config.h"

uint64_t		pfs_devs_epoch;
pfs_dev_t		*pfs_devs[PFS_MAX_NCHD];
pthread_mutex_t		pfs_devs_mtx;

/* disable iostat by default */
static int64_t		devstat_enable = PFS_OPT_DISABLE;
PFS_OPTION_REG(devstat_enable, pfs_check_ival_switch);

extern char pfs_trace_pbdname[PFS_MAX_PBDLEN];
extern struct pfs_devops pfs_polardev_ops;
//extern struct pfs_devops pfs_pangudev_ops;
extern struct pfs_devops pfs_diskdev_ops;

static struct pfs_devops *pfs_dev_ops[] = {
#ifndef PFS_DISK_IO_ONLY
	&pfs_polardev_ops,
#endif
	//&pfs_pangudev_ops,
	&pfs_diskdev_ops,
	NULL,
};

static void 	pfs_io_destroy(pfs_devio_t *io);

static inline int
pfs_dev_submit_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{
	return dev->d_ops->dop_submit_io(dev, ioq, io);
}

static inline pfs_devio_t *
pfs_dev_wait_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{
	return dev->d_ops->dop_wait_io(dev, ioq, io);
}

static inline pfs_ioq_t *
pfs_dev_create_ioq(pfs_dev_t *dev)
{
	return dev->d_ops->dop_create_ioq(dev);
}

static inline bool
pfs_dev_need_throttle(pfs_dev_t *dev, pfs_ioq_t *ioq)
{
	return dev->d_ops->dop_need_throttle(dev, ioq);
}

static inline int
pfs_dev_open(pfs_dev_t *dev)
{
	return dev->d_ops->dop_open(dev);
}

static inline int
pfs_dev_reopen(pfs_dev_t *dev, int flags)
{
	return dev->d_ops->dop_reopen(dev);
}

static inline int
pfs_dev_close(pfs_dev_t *dev)
{
	return dev->d_ops->dop_close(dev);
}

static inline int
pfs_dev_info(pfs_dev_t *dev, pbdinfo_t *pi)
{
	return dev->d_ops->dop_info(dev, pi);
}

static inline int
pfs_dev_reload(pfs_dev_t *dev)
{
	return dev->d_ops->dop_reload(dev);
}

void __attribute__((constructor))
init_pfs_dev_mtx()
{
	mutex_init(&pfs_devs_mtx);
}


/*
 * pfs_devtype_t
 *
 * Get type of device, by inspecting cluster & devname(pbdname)
 * 	1. PBD (cluster=="polarstore", devname=="1-1")
 * 	2. pangu uri (cluster=="river...", devname=="...")
 */
pfs_devtype_t
pfsdev_type(const char *cluster, const char *devname)
{
	int cnt = 0;

	if (strlen(cluster) >= PFS_MAX_CLUSTERLEN ||
	    strlen(devname) >= PFS_MAX_PBDLEN) {
		pfs_etrace("cluster or pbdname is too long\n");
		return PFS_DEV_INVALID;
	}

	// in case 'devname' is pbdpath with leading '/'
	if (devname[0] == '/')
		return PFS_DEV_INVALID;
	/* local disk */
	if (strcmp(cluster, CL_DISK) == 0)
		return PFS_DEV_DISK;
#ifndef PFS_DISK_IO_ONLY
	/* polarstore PBD */
	if (strcmp(cluster, CL_POLAR) == 0 && isdigit(devname[0]))
		return PFS_DEV_POLAR;

	/* pangu uri */
	for (int i = 0; devname[i] != '\0'; i++)
		if (devname[i] == '-')
			cnt++;
	if (strncmp(cluster, CL_PANGU, strlen(CL_PANGU)) == 0
	    && strncmp(devname, "pangu-", 6) == 0
	    && cnt == 3)
		return PFS_DEV_PANGU;
#endif
	pfs_etrace("invalid cluster-pbdname combination {%s, %s}\n",
	    cluster, devname);
	return PFS_DEV_INVALID;
}

static int
pfs_dev_alloc_id(pfs_dev_t *dev)
{
	int id;

	mutex_lock(&pfs_devs_mtx);
	for (id = 0; id < PFS_MAX_NCHD; ++id) {
		if (pfs_devs[id] == NULL) {
			pfs_devs[id] = dev;
			break;
		}
	}
	mutex_unlock(&pfs_devs_mtx);

	return (id >= PFS_MAX_NCHD) ? -1 : id;
}

static void
pfs_dev_free_id(pfs_dev_t *dev)
{
	int id = dev->d_id;
	PFS_ASSERT(0 <= id && id < PFS_MAX_NCHD);

	mutex_lock(&pfs_devs_mtx);
	PFS_ASSERT(pfs_devs[id] == dev);
	pfs_devs[id] = NULL;
	mutex_unlock(&pfs_devs_mtx);
}

static pfs_dev_t *
pfs_dev_create(const char *cluster, const char *devname, int flags)
{
	size_t		devsize;
	int		devmtag;
	int		err;
	pfs_devtype_t	dtype;
	pfs_dev_t	*dev;
	pfs_devops_t	*dop;

	dtype = pfsdev_type(cluster, devname);
	if (dtype == PFS_DEV_INVALID) {
		pfs_etrace("cluster %s, devname %s: unknown type\n",
		    cluster, devname);
		return NULL;
	}

	for (int i = 0; (dop = pfs_dev_ops[i]) != NULL; i++) {
		if (dop->dop_type == dtype)
			break;
	}
	if (dop == NULL) {
		pfs_etrace("cluster %s, devname %s: cant find device type %d\n",
		    cluster, devname, dtype);
		return NULL;
	}
	devsize = dop->dop_size;
	devmtag = dop->dop_memtag;

	dev = (pfs_dev_t *)pfs_mem_malloc(devsize, devmtag);
	if (dev == NULL) {
		pfs_etrace("cluster %s, devname %s: no memory\n",
		    cluster, devname);
		return NULL;
	}
	err = strncpy_safe(dev->d_cluster, cluster, PFS_MAX_CLUSTERLEN);
	if (err < 0) {
		pfs_etrace("cluster name too long: %s\n", cluster);
		pfs_mem_free(dev, devmtag);
		return NULL;
	}
	err = strncpy_safe(dev->d_devname, devname, PFS_MAX_PBDLEN);
	if (err < 0) {
		pfs_etrace("device name too long: %s\n", devname);
		pfs_mem_free(dev, devmtag);
		return NULL;
	}
	dev->d_type = dtype;
	dev->d_ops = dop;
	dev->d_flags = flags;
	dev->d_id = pfs_dev_alloc_id(dev);
	if (dev->d_id < 0) {
		pfs_etrace("cluster %s, devname %s: dev id used up\n",
		    cluster, devname);
		pfs_mem_free(dev, devmtag);
		return NULL;
	}
	/* epoch increment only when device open */
	dev->d_epoch = __sync_add_and_fetch(&pfs_devs_epoch, 1);
	pfs_devstat_init(&dev->d_ds);
	return dev;
}

static void
pfs_dev_destroy(pfs_dev_t *dev)
{
	pfs_devstat_uninit(&dev->d_ds);
	pfs_dev_free_id(dev);
	dev->d_id = -1;
	pfs_mem_free(dev, dev->d_ops->dop_memtag);
}

static void
pfs_io_start(pfs_devio_t *io)
{
	int stat = -1;
	int err;

	err = gettimeofday(&io->io_start_ts, NULL);
	PFS_VERIFY(err == 0);

	pfs_devstat_io_start(&io->io_dev->d_ds, io);

	switch (io->io_op) {
	case PFSDEV_REQ_RD:	stat = STAT_PFS_DEV_READ_BW; break;
	case PFSDEV_REQ_WR: 	stat = STAT_PFS_DEV_WRITE_BW; break;
	case PFSDEV_REQ_TRIM:	stat = -1; break;
	default: PFS_ASSERT("io_start bad op" == NULL); break;
	}
	if (stat < 0)
		return;
	PFS_STAT_BANDWIDTH(stat, io->io_len);
}

static void
pfs_io_end(pfs_devio_t *io)
{
	int stat = -1;

	pfs_devstat_io_end(&io->io_dev->d_ds, io);

	switch (io->io_op) {
	case PFSDEV_REQ_RD:	stat = STAT_PFS_DEV_READ_DONE; break;
	case PFSDEV_REQ_WR: 	stat = STAT_PFS_DEV_WRITE_DONE; break;
	case PFSDEV_REQ_TRIM: 	stat = STAT_PFS_DEV_TRIM_DONE; break;
	default: PFS_ASSERT("io_end bad op" == NULL); break;
	}
	PFS_STAT_LATENCY_VALUE((StatType)stat, &io->io_start_ts);
	(void)stat;	/* suppress compiler error when trace is disabled */

	switch (io->io_op) {
		case PFSDEV_REQ_RD:	stat = MNT_STAT_DEV_READ; break;
		case PFSDEV_REQ_WR: 	stat = MNT_STAT_DEV_WRITE; break;
		case PFSDEV_REQ_TRIM: 	stat = MNT_STAT_DEV_TRIM; break;
		default: PFS_ASSERT("io_end bad op" == NULL); break;
	}

	MNT_STAT_END_VALUE_BANDWIDTH(stat, &io->io_start_ts, io->io_len);
}

static pfs_devio_t *
pfs_io_wait(pfs_devio_t *io, pfs_dev_t *dev)
{
	pfs_devio_t	*nio;
	pfs_ioq_t	*ioq;

	ioq = pfs_tls_get_ioq(dev->d_id, dev->d_epoch);
	PFS_ASSERT(ioq != NULL);
	PFS_ASSERT(io == NULL || io->io_queue == ioq);

	nio = pfs_dev_wait_io(dev, ioq, io);
	PFS_ASSERT(io == NULL || nio == io);
	if (nio == NULL)
		return NULL;
	if (nio->io_error < 0)
		pfs_etrace("io failed! error: %d, pbdname: %s, op: %d, "
		    "buf: %#x, len: %lu, bda: %lu, flags: %d\n",
		    nio->io_error, nio->io_dev->d_devname, nio->io_op,
		    nio->io_buf, nio->io_len, nio->io_bda, nio->io_flags);

	pfs_io_end(nio);
	return nio;
}

static int
pfs_io_submit(pfs_devio_t *io)
{
	pfs_dev_t	*dev = io->io_dev;
	int		err = 0;
	bool		waitio = false;
	pfs_ioq_t	*ioq;
	pfs_devio_t	*nio;

	ioq = pfs_tls_get_ioq(dev->d_id, dev->d_epoch);
	if (ioq == NULL) {
		ioq = pfs_dev_create_ioq(dev);
		if (ioq == NULL)
			ERR_RETVAL(ENOMEM);
		ioq->ioq_devid = dev->d_id;
		ioq->ioq_epoch = dev->d_epoch;
		pfs_tls_set_ioq(dev->d_id, ioq);
	}
	io->io_queue = ioq;

	do {
		err = 0;
		if (pfs_dev_need_throttle(dev, ioq) || waitio) {
			MNT_STAT_BEGIN();
			nio = pfs_io_wait(NULL, dev);
			if (waitio)
				MNT_STAT_END(MNT_STAT_DEV_NOBUF);
			else
				MNT_STAT_END(MNT_STAT_DEV_THROTTLE);
			PFS_VERIFY(nio != NULL);
			err = nio->io_error;
			pfs_io_destroy(nio);
			waitio = false;
		}
		if (err < 0)
			break;

		err = pfs_dev_submit_io(dev, ioq, io);
		if (err == -ENOBUFS)
			waitio = true;
	} while (waitio);
	if (err < 0)
		return err;

	pfs_io_start(io);
	return 0;
}

static pfs_devio_t *
pfs_io_create(pfs_dev_t *dev, int op, void *buf, size_t len, uint64_t bda,
    int flags)
{
	pfs_devio_t *io;

	io = (pfs_devio_t *)pfs_mem_malloc(sizeof(*io), M_DEV_IO);
	PFS_VERIFY(io != NULL);

	memset(io, 0, sizeof(*io));
	io->io_dev = dev;
	io->io_buf = buf;
	io->io_len = len;
	io->io_bda = bda;
	io->io_op = op;
	io->io_flags = flags;
	io->io_error = PFSDEV_IO_DFTERR;
	io->io_private = NULL;
	io->io_queue = NULL;

	if (devstat_enable == PFS_OPT_ENABLE)
		io->io_flags |= IO_STAT;

	return io;
}

static void
pfs_io_destroy(pfs_devio_t *io)
{
	PFS_ASSERT(io->io_private == NULL);	/* no held private info */
	PFS_ASSERT(io->io_queue != NULL);	/* each io must be submitted */

	io->io_queue = NULL;
	pfs_mem_free(io, M_DEV_IO);
}

int
pfsdev_open(const char *cluster, const char *devname, int flags)
{
	int		err;
	pfs_dev_t	*dev;

	pfs_itrace("open device cluster %s, devname %s, flags %#x\n",
	    cluster, devname, flags);

	dev = pfs_dev_create(cluster, devname, flags);
	if (dev == NULL)
		ERR_RETVAL(EINVAL);

	err = pfs_dev_open(dev);
	if (err < 0) {
		pfs_dev_destroy(dev);
		dev = NULL;
		return err;
	}
	return dev->d_id;
}

int
pfsdev_close(int devi)
{
	int		err;
	pfs_dev_t	*dev;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);

	err = pfs_dev_close(dev);
	if (err < 0) {
		pfs_etrace("dev close ret %d\n", err);
		PFS_VERIFY("dev close failed" == NULL);
	}
	pfs_dev_destroy(dev);
	dev = NULL;
	return 0;
}

int
pfsdev_info(int devi, pbdinfo_t *pi)
{
	pfs_dev_t *dev;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);

	return pfs_dev_info(dev, pi);
}

int
pfsdev_reload(int devi)
{
	pfs_dev_t	*dev;
	int		err;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);

	err = pfs_dev_reload(dev);
	if (err < 0)
		pfs_etrace("dev reload failed, ret: %d\n", err);
	return err;
}

static int
pfsdev_do_io(pfs_dev_t *dev, pfs_devio_t *io)
{
	int flags = io->io_flags;
	pfs_devio_t *nio;
	int err;

	err = pfs_io_submit(io);
	if (err)
		pfs_io_destroy(io);
	else if (flags & IO_NOWAIT)
		err = 0;
	else {
		nio = pfs_io_wait(io, dev);
		PFS_ASSERT(nio == io);
		err = io->io_error;
		pfs_io_destroy(io);
	}
	return err;
}

int
pfsdev_trim(int devi, uint64_t bda)
{
	pfs_dev_t *dev;
	pfs_devio_t *io;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL && dev_writable(dev));
	PFS_ASSERT((bda % PFS_BLOCK_SIZE) == 0);

	io = pfs_io_create(dev, PFSDEV_REQ_TRIM, NULL, PFSDEV_TRIMSIZE, bda,
	    IO_WAIT);
	PFS_VERIFY(io != NULL);

	return pfsdev_do_io(dev, io);
}

int
pfsdev_pread_flags(int devi, void *buf, size_t len, uint64_t bda, int flags)
{
	pfs_dev_t *dev;
	pfs_devio_t *io;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);
	PFS_ASSERT((bda % PBD_SECTOR_SIZE) == 0);
	PFS_ASSERT(len > 0 && (len % PBD_SECTOR_SIZE) == 0);

	io = pfs_io_create(dev, PFSDEV_REQ_RD, buf, len, bda, flags);
	PFS_VERIFY(io != NULL);

	return pfsdev_do_io(dev, io);
}

int
pfsdev_pwrite_flags(int devi, void *buf, size_t len, uint64_t bda, int flags)
{
	pfs_dev_t *dev;
	pfs_devio_t *io;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL && dev_writable(dev));
	PFS_ASSERT((bda % PBD_SECTOR_SIZE) == 0);
	PFS_ASSERT(len > 0 && (len % PBD_SECTOR_SIZE) == 0);

	io = pfs_io_create(dev, PFSDEV_REQ_WR, buf, len, bda, flags);
	PFS_VERIFY(io != NULL);

	return pfsdev_do_io(dev, io);
}

int
pfsdev_wait_io(int devi)
{
	pfs_dev_t	*dev;
	int		err, err1;
	pfs_devio_t	*io;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);

	err = 0;
	while ((io = pfs_io_wait(NULL, dev)) != NULL) {
		err1 = io->io_error;
		pfs_io_destroy(io);
		ERR_UPDATE(err, err1);
	}
	return err;
}

int
pfsdev_reopen(int devi, const char *cluster, const char *devname, int flags)
{
	pfs_dev_t *dev;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];

	if(cluster)
		PFS_ASSERT(strcmp(dev->d_cluster, cluster) == 0);
	PFS_ASSERT(strcmp(dev->d_devname, devname) == 0);
	dev->d_flags = flags;
	return pfs_dev_reopen(dev, flags);
}

const char *
pfsdev_trace_pbdname(const char *cluster, const char *pbdname)
{
	int n;
	char comp[3][PFS_MAX_PBDLEN];

	switch (pfsdev_type(cluster, pbdname)) {
	case PFS_DEV_DISK:
		return MAGIC_PBDNAME;
#ifndef PFS_DISK_IO_ONLY
	case PFS_DEV_POLAR:
		return pbdname;
	case PFS_DEV_PANGU:
		n = sscanf(pbdname, "pangu-%[^-]-%[^-]-%[^-]",
			comp[0], comp[1], comp[2]);
		PFS_VERIFY(n == 3);	// XXX: namei should guarantee it ok
		n = snprintf(pfs_trace_pbdname, sizeof(pfs_trace_pbdname),
			"%s-1", comp[1]);
		PFS_VERIFY(n < PFS_MAX_PBDLEN);
		pfs_itrace("pangu device %s uses %s as its pbdname for"
		    " tracing\n", pbdname, pfs_trace_pbdname);
		return pfs_trace_pbdname;
#endif
	default:
		return NULL;
	}
}
