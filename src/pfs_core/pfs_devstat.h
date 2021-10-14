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

#ifndef _PFS_DEVSTAT_H_
#define _PFS_DEVSTAT_H_

#include "pfs_impl.h"
#ifndef PFS_DISK_IO_ONLY
#include "pfs_iochnl.h"
#else
enum {
    PFSDEV_REQ_NOP      = 0,
    PFSDEV_REQ_INFO     = 1,
    PFSDEV_REQ_RD       = 2,
    PFSDEV_REQ_WR       = 3,
    PFSDEV_REQ_TRIM     = 4,

    PFSDEV_REQ_MAX,
};
#endif

typedef struct pfs_devio pfs_devio_t;
typedef struct admin_buf admin_buf_t;

/* device statistics */
typedef struct pfs_devstat {
	pthread_rwlock_t ds_rwlock;
	/* statistics */
#define	ds_iostat_start	ds_start_count
	uint64_t	ds_start_count;
	uint64_t	ds_end_count;
	struct timeval	ds_busy_time;
	uint64_t	ds_bytes[PFSDEV_REQ_MAX];
	uint64_t	ds_ops[PFSDEV_REQ_MAX];
	struct timeval	ds_duration[PFSDEV_REQ_MAX];
#define	ds_iostat_end	ds_busy_from
	struct timeval	ds_busy_from;
} pfs_devstat_t;

void pfs_devstat_init(pfs_devstat_t *ds);
void pfs_devstat_uninit(pfs_devstat_t *ds);
void pfs_devstat_io_start(pfs_devstat_t *ds, const pfs_devio_t *io);
void pfs_devstat_io_end(pfs_devstat_t *ds, const pfs_devio_t *io);
int pfs_devstat_snap(int devi, admin_buf_t *ab);

#endif	/* _PFS_DEVSTAT_H_ */
