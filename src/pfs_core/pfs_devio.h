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

#ifndef _PFS_DEVIO_H_
#define _PFS_DEVIO_H_

#include <sys/queue.h>
#include <libaio.h>

#include <stdint.h>

#include "pfs_devstat.h"
#include "pfs_impl.h"

#define CL_POLAR	"polarstore"
#define CL_PANGU	"river"
#define CL_DISK		"disk"
#ifndef PFS_DISK_IO_ONLY
#define CL_DEFAULT	CL_POLAR
#else
#define CL_DEFAULT	CL_DISK
#endif

#define MAGIC_PBDNAME	"0-0"

#define PFSDEV_IOSIZE		(16 << 10)
#define PFSDEV_TRIMSIZE		( 4 << 20)
#define PFSDEV_IO_NMAX		8
#define PFSDEV_IO_DFTERR	((int32_t)0xe55e5505)

#define	DEVFLG_RD		0x0001
#define	DEVFLG_WR		0x0002
#define	DEVFLG_RDWR		(DEVFLG_RD | DEVFLG_WR)
#define	DEVFLG_REQ_SAFE		0x0010


/* logical device(PBD) info */
typedef struct pbdinfo {
	uint32_t	pi_pbdno;	/* not used now */
	int8_t		pi_rwtype;	/* <0: invalid, 0: read, 1: write */
	uint64_t	pi_unitsize;
	uint64_t	pi_chunksize;
	uint64_t	pi_disksize;
} pbdinfo_t;

/* supported devices */
typedef enum pfs_devtype {
	PFS_DEV_INVALID	= 0,
#ifndef PFS_DISK_IO_ONLY
	PFS_DEV_POLAR,
	PFS_DEV_PANGU,
#endif
	PFS_DEV_DISK,
	PFS_DEV_MAX,
} pfs_devtype_t;

enum {
	IO_WAIT		= 0x0000,
	IO_NOWAIT	= 0x0001,
	IO_STAT		= 0x0010,
};

typedef struct pfs_dev pfs_dev_t;
typedef struct pfs_devio pfs_devio_t;
typedef struct pfs_ioq pfs_ioq_t;

/* io task */
typedef struct pfs_devio {
	TAILQ_ENTRY(pfs_devio) io_next;
	pfs_dev_t 	*io_dev;
	pfs_ioq_t	*io_queue;
	void		*io_buf;
	uint64_t	io_len;
	uint64_t	io_bda;
	int		io_op;
	int32_t		io_error;
	int		io_flags;
	struct timeval	io_start_ts;
	void		*io_private;
	struct iocb	io_iocb;
} pfs_devio_t;

/* per thread io queue */
typedef struct pfs_ioq {
	int		ioq_devid;
	uint64_t	ioq_epoch;	/* check whether expired */
	void		(*ioq_destroy)(pfs_ioq_t *);
} pfs_ioq_t;

/* device meta & operation */
typedef struct pfs_devops {
	const char	*dop_name;
	pfs_devtype_t	dop_type;
	size_t		dop_size;
	int		dop_memtag;
	int		(*dop_open)(pfs_dev_t *dev);
	int		(*dop_reopen)(pfs_dev_t *dev);
	int		(*dop_close)(pfs_dev_t *dev);
	int		(*dop_info)(pfs_dev_t *dev, pbdinfo_t *pi);
	int		(*dop_reload)(pfs_dev_t *dev);
	pfs_ioq_t *	(*dop_create_ioq)(pfs_dev_t *dev);
	bool		(*dop_need_throttle)(pfs_dev_t *dev, pfs_ioq_t *ioq);
	int		(*dop_submit_io)(pfs_dev_t *dev, pfs_ioq_t *ioq,
			    pfs_devio_t *io);
	pfs_devio_t *	(*dop_wait_io)(pfs_dev_t *dev, pfs_ioq_t *ioq,
			    pfs_devio_t *io);
} pfs_devops_t;

/* pfs device */
typedef struct pfs_dev {
	int		d_id;		/* index in devices array */
	uint64_t	d_epoch;	/* mounted devices epoch */
	pfs_devtype_t	d_type;		/* dev meta */
	pfs_devops_t	*d_ops;		/* dev operation impl */
	int		d_flags;	/* dev rw permission & require_safe */
	char		d_cluster[PFS_MAX_CLUSTERLEN];
	char		d_devname[PFS_MAX_PBDLEN];	/* alias pbdname */

	pfs_devstat_t	d_ds;		/* statistics */
} pfs_dev_t;

/* device operation API */
pfs_devtype_t pfsdev_type(const char *cluster, const char *devname);
int	pfsdev_open(const char *cluster, const char *devname, int flags);
int	pfsdev_reopen(int devi, const char *cluster, const char *devname,
	    int flags);
int	pfsdev_close(int devi);
int	pfsdev_info(int devi, pbdinfo_t *pi);
int	pfsdev_reload(int devi);
int	pfsdev_trim(int devi, uint64_t bda);
int	pfsdev_pread_flags(int devi, void *buf, size_t len, uint64_t bda,
	    int flags);
int	pfsdev_pwrite_flags(int devi, void *buf, size_t len, uint64_t bda,
	    int flags);
int	pfsdev_wait_io(int devi);

const char *pfsdev_trace_pbdname(const char *cluster, const char *pbdname);

static inline int
pfsdev_pread(int devi, void *buf, size_t len, uint64_t bda)
{
	return pfsdev_pread_flags(devi, buf, len, bda, IO_WAIT);
}

static inline int
pfsdev_pwrite(int devi, void *buf, size_t len, uint64_t bda)
{
	return pfsdev_pwrite_flags(devi, buf, len, bda, IO_WAIT);
}

/* write permission checker (read permission is granted by default) */
static inline bool
dev_writable(pfs_dev_t *dev)
{
	return (dev->d_flags & DEVFLG_WR) != 0;
}

#endif	/* _PFS_DEVIO_H_ */
