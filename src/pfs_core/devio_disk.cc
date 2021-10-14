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

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <linux/fs.h>

#include "pfs_trace.h"
#include "pfs_devio.h"
#include "pfs_memory.h"
#include "pfs_option.h"

#define DISK_NR_EVENTS		(16)

enum {
	DISKTRIM_ENABLE		= 1,
	DISKTRIM_DISABLE	= 2,
};

static int64_t diskdev_trim_enable = DISKTRIM_DISABLE;
PFS_OPTION_REG(diskdev_trim_enable, pfs_check_ival_normal);

typedef struct pfs_diskdev {
	pfs_dev_t	dk_base;
	int		dk_fd;
	int		dk_oflags;
	size_t		dk_sectsz;
} pfs_diskdev_t;

typedef struct pfs_diskioq {
	pfs_ioq_t		dkq_ioq;
#define	dkq_destroy		dkq_ioq.ioq_destroy
	/* hold unsubmit io for batch submit */
	int			dkq_pending_count;
	TAILQ_HEAD(, pfs_devio)	dkq_pending_queue;

	/* hold inflight io */
	int			dkq_inflight_count;
	TAILQ_HEAD(, pfs_devio) dkq_inflight_queue;
	io_context_t		dkq_aioctx;	// TODO
} pfs_diskioq_t;

static int64_t disk_iodepth = 65536;
PFS_OPTION_REG(disk_iodepth, pfs_check_ival_normal);

static int64_t disk_batch_submit_thold = 64;
PFS_OPTION_REG(disk_batch_submit_thold, pfs_check_ival_normal);

static int64_t disk_wait_min_nr = 1;
PFS_OPTION_REG(disk_wait_min_nr, pfs_check_ival_normal);

static int64_t disk_wait_timeout_us = 200;
PFS_OPTION_REG(disk_wait_timeout_us, pfs_check_ival_normal);

static void
pfs_diskdev_destroy_ioq(pfs_ioq_t *ioq)
{
	pfs_diskioq_t *dkioq = (pfs_diskioq_t *)ioq;
	int err;

	PFS_ASSERT(dkioq->dkq_pending_count == 0);
	PFS_ASSERT(TAILQ_EMPTY(&dkioq->dkq_pending_queue));
	PFS_ASSERT(dkioq->dkq_inflight_count == 0);
	PFS_ASSERT(TAILQ_EMPTY(&dkioq->dkq_inflight_queue));

	err = io_destroy(dkioq->dkq_aioctx);
	if (err < 0)
		pfs_etrace("failed to destroy aio context: %d\n", err);

	pfs_mem_free(dkioq, M_DISK_IOQ);
}

static pfs_ioq_t *
pfs_diskdev_create_ioq(pfs_dev_t *dev)
{
	pfs_diskioq_t *dkioq;
	int err;

	dkioq = (pfs_diskioq_t *)pfs_mem_malloc(sizeof(*dkioq), M_DISK_IOQ);
	if (dkioq == NULL) {
		pfs_etrace("create diks ioq data failed: ENOMEM\n");
		return NULL;
	}
	memset(dkioq, 0, sizeof(*dkioq));
	dkioq->dkq_destroy = pfs_diskdev_destroy_ioq;
	dkioq->dkq_pending_count = 0;
	TAILQ_INIT(&dkioq->dkq_pending_queue);
	dkioq->dkq_inflight_count = 0;
	TAILQ_INIT(&dkioq->dkq_inflight_queue);

	memset(&dkioq->dkq_aioctx, 0, sizeof(dkioq->dkq_aioctx));
	err = io_setup(DISK_NR_EVENTS, &dkioq->dkq_aioctx);
	if (err < 0) {
		pfs_mem_free(dkioq, M_DISK_IOQ);
		pfs_etrace("failed to setup aio context: %d\n", err);
		return NULL;
	}

	return (pfs_ioq_t *)dkioq;
}

static bool
pfs_diskdev_need_throttle(pfs_dev_t *dev, pfs_ioq_t *ioq)
{
	pfs_diskioq_t *dkioq = (pfs_diskioq_t *)ioq;
	return (dkioq->dkq_pending_count + dkioq->dkq_inflight_count >= disk_iodepth);
}

static void
pfs_replace_mapper_path(char *path)
{
	static const char *mapper_str = "mapper_";
	char *find = strstr(path, mapper_str);
	if (find) {
	    *(find + 6) = '/';
	}
        pfs_itrace("disk dev path: %s\n", path);
}


static int
pfs_diskdev_open(pfs_dev_t *dev)
{
	pfs_diskdev_t *dkdev = (pfs_diskdev_t *) dev;
	char path[PATH_MAX];
	int fd, flags, err, sectsz;

	dkdev->dk_fd = -1;
	if (snprintf(path, sizeof(path), "/dev/%s", dev->d_devname) >=
	    (int)sizeof(path))
		ERR_RETVAL(ENAMETOOLONG);


	/*
	 * If path contains 'mapper_', need to replace it with 'mapper/'
	 */
	pfs_replace_mapper_path(path);
	/*
	 * RW should guarantee the data is written to disk,
	 * while RO should bypass page cache.
	 */
	flags = dev_writable(dev) ? O_RDWR|O_DIRECT : O_RDONLY|O_DIRECT;
	pfs_itrace("open local disk: open(%s, %#x)\n", path, flags);
	fd = open(path, flags);
	if (fd < 0) {
		pfs_etrace("cant open %s: %s\n", path, strerror(errno));
		return -errno;
	}

	err = ioctl(fd, BLKSSZGET, &sectsz);
	if (err < 0) {
		pfs_etrace("cant ioctl BLKSSZGET%d: %s\n", fd, strerror(errno));
		close(fd);
		return -errno;
	}

	dkdev->dk_fd = fd;
	dkdev->dk_oflags = flags;
	dkdev->dk_sectsz = (size_t)sectsz;
	return 0;
}
static int
pfs_diskdev_reopen(pfs_dev_t *dev)
{
        pfs_itrace("dsikdev reopen, now flags:%d", dev->d_flags);
	pfs_diskdev_t *dkdev = (pfs_diskdev_t *) dev;
	char path[PATH_MAX];
	int fd, flags, err, sectsz;

	if (snprintf(path, sizeof(path), "/dev/%s", dev->d_devname) >=
	    (int)sizeof(path))
		ERR_RETVAL(ENAMETOOLONG);

	/*
	 * If path contains 'mapper_', need to replace it with 'mapper/'
	 */
	pfs_replace_mapper_path(path);
	/*
	 * RW should guarantee the data is written to disk,
	 * while RO should bypass page cache.
	 */
	flags = dev_writable(dev) ? O_RDWR|O_DIRECT : O_RDONLY|O_DIRECT;
	pfs_itrace("open local disk: open(%s, %#x)\n", path, flags);
	if (dkdev->dk_fd >= 0)
		close(dkdev->dk_fd);
	fd = open(path, flags);
	if (fd < 0) {
		pfs_etrace("cant open %s: %s\n", path, strerror(errno));
		return -errno;
	}

	err = ioctl(fd, BLKSSZGET, &sectsz);
	if (err < 0) {
		pfs_etrace("cant ioctl BLKSSZGET%d: %s\n", fd, strerror(errno));
		close(fd);
		return -errno;
	}

	dkdev->dk_fd = fd;
	dkdev->dk_oflags = flags;
	dkdev->dk_sectsz = (size_t)sectsz;
	return 0;
}

static int
pfs_diskdev_close(pfs_dev_t *dev)
{
	pfs_diskdev_t *dkdev = (pfs_diskdev_t *)dev;
	int err;

	PFS_ASSERT(dkdev->dk_fd >= 0);
	err = close(dkdev->dk_fd);
	dkdev->dk_fd = -1;

	return err;
}

static int
pfs_diskdev_info(pfs_dev_t *dev, struct pbdinfo *pi)
{
	pfs_diskdev_t *dkdev = (pfs_diskdev_t *)dev;
	size_t size;
	int err, readonly;

	err = ioctl(dkdev->dk_fd, BLKGETSIZE, &size);
	if (err < 0) {
		pfs_etrace("cant ioctl BLKGETSIZE %d: %s\n", dkdev->dk_fd, strerror(errno));
		return -errno;
	}
	pfs_itrace("ioctl status %d\n", err);
	err = ioctl(dkdev->dk_fd, BLKROGET, &readonly);
	if (err < 0) {
		pfs_etrace("cant ioctl BLKROGET %d: %s\n", dkdev->dk_fd, strerror(errno));
		return -errno;
	}

	size *= 512;	// hard-coded in kernel, not influenced by logical sector size
	pi->pi_pbdno = 0;
	pi->pi_unitsize = (4UL << 20);
	pi->pi_chunksize = (10ULL << 30);
	pi->pi_disksize = (size / pi->pi_chunksize) * pi->pi_chunksize;
	pi->pi_rwtype = readonly ? 0 : 1;

	pfs_itrace("pfs_diskdev_info get pi_pbdno %u, pi_rwtype %d, pi_unitsize %llu, "
	    "pi_chunksize %llu, pi_disksize %llu\n", pi->pi_pbdno, pi->pi_rwtype,
	    pi->pi_unitsize, pi->pi_chunksize, pi->pi_disksize);
	pfs_itrace("pfs_diskdev_info waste size: %llu\n", size - pi->pi_disksize);
	return err;
}

static int
pfs_diskdev_reload(pfs_dev_t *dev)
{
	return 0;
}

static inline bool
pfs_diskdev_dio_aligned(pfs_diskdev_t *dkdev, uint64_t val)
{
	return (val & (dkdev->dk_sectsz-1)) == 0;
}

static inline bool
pfs_diskdev_need_align(pfs_diskdev_t *dkdev, uint64_t val)
{
	return (dkdev->dk_oflags & O_DIRECT) && !pfs_diskdev_dio_aligned(dkdev, val);
}

static void
pfs_diskdev_enq_io(pfs_diskioq_t *dkioq, pfs_devio_t *io)
{
	TAILQ_INSERT_TAIL(&dkioq->dkq_pending_queue, io, io_next);
	dkioq->dkq_pending_count++;
}

static void
pfs_diskdev_deq_io(pfs_diskioq_t *dkioq, pfs_devio_t *io)
{
	TAILQ_REMOVE(&dkioq->dkq_pending_queue, io, io_next);
	dkioq->dkq_pending_count--;
}

static void
pfs_diskdev_io_done(pfs_devio_t *io, struct iocb *iocb, long res, long res2)
{
	int err;

	PFS_ASSERT(io->io_error == PFSDEV_IO_DFTERR);
	err = 0;
	if (res != (long)io->io_len || res2 != 0) {
		// res2 is always set 0 in kernel
		pfs_etrace("disk io %p op %d len %lu returns res %ld res2 %ld\n",
				io, io->io_op, io->io_len, res, res2);
		err = -EIO;
	}

	if (iocb->u.c.buf != io->io_buf) {
		if (err == 0 && io->io_op == PFSDEV_REQ_RD)
			memcpy(io->io_buf, iocb->u.c.buf, (size_t)res);
		pfs_mem_free(iocb->u.c.buf, M_DISK_DIOBUF);
		iocb->u.c.buf = NULL;
	}

	io->io_error = err;
}

static void
pfs_diskdev_iocb_done(io_context_t ctx, struct iocb *iocb, long res, long res2)
{
	pfs_devio_t *io = container_of(iocb, pfs_devio_t, io_iocb);

	pfs_diskdev_io_done(io, iocb, res, res2);
}

static int
pfs_diskdev_io_prep_pread(pfs_diskdev_t *dkdev, pfs_devio_t *io, struct iocb *iocb)
{
	void *diobuf;
	int err;

	if (pfs_diskdev_need_align(dkdev, (uint64_t)io->io_buf)) {
		diobuf = NULL;
		err = pfs_mem_memalign((void **)&diobuf, dkdev->dk_sectsz,
		    io->io_len, M_DISK_DIOBUF);
		if (err) {
			pfs_etrace("failed to memalign diobuf: %s\n", strerror(err));
			return -err;
		}

		PFS_ASSERT(pfs_diskdev_dio_aligned(dkdev, (uint64_t)diobuf));
		PFS_ASSERT(pfs_diskdev_dio_aligned(dkdev, io->io_bda));
		PFS_ASSERT(pfs_diskdev_dio_aligned(dkdev, io->io_len));
	} else {
		diobuf = io->io_buf;
	}

	PFS_ASSERT(io->io_len <= PFS_FRAG_SIZE);

	io_prep_pread(iocb, dkdev->dk_fd, diobuf, io->io_len, io->io_bda);
	return 0;
}

static int
pfs_diskdev_io_prep_pwrite(pfs_diskdev_t *dkdev, pfs_devio_t *io, struct iocb *iocb)
{
	void *diobuf;
	int err;

	if (pfs_diskdev_need_align(dkdev, (uint64_t)io->io_buf)) {
		diobuf = NULL;
		err = pfs_mem_memalign((void **)&diobuf, dkdev->dk_sectsz,
		    io->io_len, M_DISK_DIOBUF);
		if (err) {
			pfs_etrace("failed to memalign diobuf: %s\n", strerror(err));
			return -err;
		}
		memcpy(diobuf, io->io_buf, io->io_len);

		PFS_ASSERT(pfs_diskdev_dio_aligned(dkdev, (uint64_t)diobuf));
		PFS_ASSERT(pfs_diskdev_dio_aligned(dkdev, io->io_bda));
		PFS_ASSERT(pfs_diskdev_dio_aligned(dkdev, io->io_len));
	} else {
		diobuf = io->io_buf;
	}

	PFS_ASSERT(io->io_len <= PFS_FRAG_SIZE);

	io_prep_pwrite(iocb, dkdev->dk_fd, diobuf, io->io_len, io->io_bda);
	return 0;
}

static int
pfs_diskdev_io_trim(pfs_diskdev_t *dkdev, pfs_devio_t *io)
{
	int err;
	uint64_t range[2];

	if (diskdev_trim_enable == DISKTRIM_DISABLE)
		return 0;

	PFS_ASSERT(pfs_diskdev_dio_aligned(dkdev, io->io_bda));
	range[0] = io->io_bda;
	range[1] = io->io_len;

#ifndef	BLKDISCARD	/* trim on ESSD */
#define	BLKDISCARD	_IO(0x12,119)
#endif
	err = ioctl(dkdev->dk_fd, BLKDISCARD, &range);
	if (err < 0)
		pfs_etrace("ioctl(BLKDISCARD, offset %lu, len %lu) failed,"
		    "err %d, errno %d\n", range[0], range[1], err, errno);
	return err;
}

static void
pfs_diskdev_try_flush(pfs_diskdev_t *dkdev, pfs_diskioq_t *dkioq, bool force)
{
	int i, ret;
	pfs_devio_t *io;
	struct iocb *iocbs[DISK_NR_EVENTS];
	int iocbc = 0, smin;

	if (TAILQ_EMPTY(&dkioq->dkq_pending_queue))
		return;

	if (dkioq->dkq_pending_count < disk_batch_submit_thold && !force)
		return;

	smin = MIN(DISK_NR_EVENTS, disk_batch_submit_thold);
	TAILQ_FOREACH(io, &dkioq->dkq_pending_queue, io_next) {
		if (iocbc >= smin)
			break;
		iocbs[iocbc++] = &io->io_iocb;
	}

	ret = io_submit(dkioq->dkq_aioctx, iocbc, iocbs);
	if (ret < 0 && ret != -EAGAIN) {
		pfs_etrace("failed to submit: %d\n", ret);
		return;
	}
	for (i = 0; i < ret; i++) {
		io = TAILQ_FIRST(&dkioq->dkq_pending_queue);
		PFS_ASSERT(&io->io_iocb == iocbs[i]);
		pfs_diskdev_deq_io(dkioq, io);
		TAILQ_INSERT_TAIL(&dkioq->dkq_inflight_queue, io, io_next);
		dkioq->dkq_inflight_count++;
	}
}

static void
pfs_diskdev_try_wait(pfs_diskdev_t *dkdev, pfs_diskioq_t *dkioq)
{
	struct io_event ev[DISK_NR_EVENTS];
	struct timespec timeout;
	int rv, nr_min, nr_max;

	/* try_flush() may fail, leading no IO req moved to inflight queue */
	if (TAILQ_EMPTY(&dkioq->dkq_inflight_queue))
		return;

	nr_max = DISK_NR_EVENTS;
	nr_min = MIN(dkioq->dkq_inflight_count, disk_wait_min_nr);
	nr_min = MIN(nr_min, nr_max);
	timeout.tv_sec = 0;
	timeout.tv_nsec = disk_wait_timeout_us * NSEC_PER_USEC;
	rv = io_getevents(dkioq->dkq_aioctx, nr_min, nr_max, ev, &timeout);
	if (rv < 0) {
		pfs_etrace("failed to getevents: %d\n", rv);
		return;
	}

	for (int i = 0; i < rv; i++) {
		pfs_diskdev_iocb_done(dkioq->dkq_aioctx, ev[i].obj,
			ev[i].res, ev[i].res2);
	}
}

static int
pfs_diskdev_submit_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{
	pfs_diskdev_t *dkdev = (pfs_diskdev_t *)dev;
	pfs_diskioq_t *dkioq = (pfs_diskioq_t *)ioq;
	struct iocb *iocb;
	int err;

	/* XXX trim is not async */
	if (io->io_op == PFSDEV_REQ_TRIM) {
		io->io_error = pfs_diskdev_io_trim(dkdev, io);
		TAILQ_INSERT_TAIL(&dkioq->dkq_inflight_queue, io, io_next);
		dkioq->dkq_inflight_count++;
		return 0;
	}

	err = 0;
	iocb = &io->io_iocb;
	memset(iocb, 0, sizeof(*iocb));
	switch (io->io_op) {
	case PFSDEV_REQ_RD:
		err = pfs_diskdev_io_prep_pread(dkdev, io, iocb);
		break;
	case PFSDEV_REQ_WR:
		err = pfs_diskdev_io_prep_pwrite(dkdev, io, iocb);
		break;
	default:
		pfs_etrace("invalid io task! op: %d, bufp: %p, len: %zu, bda%lu\n",
		    io->io_op, io->io_buf, io->io_len, io->io_bda);
		PFS_ASSERT("unsupported io type" == NULL);
	}
	if (err < 0) {
		pfs_etrace("failed to prep iocb\n");
		return err;
	}

	io->io_error = PFSDEV_IO_DFTERR;
	pfs_diskdev_enq_io(dkioq, io);
	pfs_diskdev_try_flush(dkdev, dkioq, false);
	return 0;
}

static pfs_devio_t *
pfs_diskdev_wait_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{
	pfs_diskdev_t *dkdev = (pfs_diskdev_t *)dev;
	pfs_diskioq_t *dkioq = (pfs_diskioq_t *)ioq;
	pfs_devio_t *nio;

	if (TAILQ_EMPTY(&dkioq->dkq_pending_queue) &&
	    TAILQ_EMPTY(&dkioq->dkq_inflight_queue))
		return NULL;

	for (;;) {
		TAILQ_FOREACH(nio, &dkioq->dkq_inflight_queue, io_next) {
			if (nio->io_error == PFSDEV_IO_DFTERR)
				continue;
			if (io == NULL || nio == io)
				break;
		}

		if (nio == NULL) {
			pfs_diskdev_try_flush(dkdev, dkioq, true);
			pfs_diskdev_try_wait(dkdev, dkioq);
			continue;
		}

		TAILQ_REMOVE(&dkioq->dkq_inflight_queue, nio, io_next);
		--dkioq->dkq_inflight_count;
		return nio;
	}
	return NULL;
}

/* register device operations */
struct pfs_devops pfs_diskdev_ops = {
	.dop_name		= "disk",
	.dop_type		= PFS_DEV_DISK,
	.dop_size		= sizeof(pfs_diskdev_t),
	.dop_memtag		= M_DISK_DEV,
	.dop_open		= pfs_diskdev_open,
        .dop_reopen		= pfs_diskdev_reopen,
	.dop_close		= pfs_diskdev_close,
	.dop_info		= pfs_diskdev_info,
	.dop_reload		= pfs_diskdev_reload,
	.dop_create_ioq		= pfs_diskdev_create_ioq,
	.dop_need_throttle	= pfs_diskdev_need_throttle,
	.dop_submit_io 		= pfs_diskdev_submit_io,
	.dop_wait_io 		= pfs_diskdev_wait_io,
};
