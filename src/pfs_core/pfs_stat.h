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

#ifndef PFS_MOUNTSTAT_H
#define PFS_MOUNTSTAT_H

#include <stdint.h>
#include "pfs_stat_file_type.h"

enum {
	MNT_STAT_BASE = -1,
	MNT_STAT_FILE_OPEN,
	MNT_STAT_FILE_OPEN_CREAT,
	MNT_STAT_FILE_READ,
	MNT_STAT_FILE_WRITE,
	MNT_STAT_FILE_LSEEK,
	MNT_STAT_FILE_FSTAT,
	MNT_STAT_FILE_TRUNCATE,
	MNT_STAT_FILE_FALLOCATE,
	MNT_STAT_FILE_UNLINK,

	MNT_STAT_DIR_DU,
	MNT_STAT_DIR_RENAME,
	MNT_STAT_DIR_REMOVE,
	MNT_STAT_DIR_OPENDIR,
	MNT_STAT_DIR_READDIR,

	MNT_STAT_SYNC_MOUNT,
	MNT_STAT_SYNC_INODE_RELOAD,
	MNT_STAT_SYNC_INODE_WAIT,

	MNT_STAT_JOURNAL_POLL,
	MNT_STAT_JOURNAL_REPLAY,
	MNT_STAT_JOURNAL_TRIM,
	MNT_STAT_JOURNAL_WRITE,

	MNT_STAT_CONTAINER_INODE_GET,
	MNT_STAT_CONTAINER_INODE_PUT,

	MNT_STAT_DEV_SLEEP,
	MNT_STAT_DEV_NOBUF,
	MNT_STAT_DEV_THROTTLE,
	MNT_STAT_DEV_READ,
	MNT_STAT_DEV_WRITE,
	MNT_STAT_DEV_TRIM,

	MNT_STAT_META_RDLOCK,
	MNT_STAT_META_WRLOCK,

	MNT_STAT_TYPE_COUNT
};

enum {
	MNT_STAT_API_NONE = -1,
	MNT_STAT_BACK_READ,
	MNT_STAT_BACK_WRITE,
	MNT_STAT_API_READ,
	MNT_STAT_API_WRITE,
	MNT_STAT_API_PREAD,
	MNT_STAT_API_PWRITE,
	MNT_STAT_TX_WRITE,

	MNT_STAT_API_OPEN,
	MNT_STAT_API_OPEN_CREAT,
	MNT_STAT_API_LSEEK,
	MNT_STAT_API_FSTAT,
	MNT_STAT_API_FTRUNCATE,
	MNT_STAT_API_FALLOCATE,
	MNT_STAT_API_UNLINK,
	MNT_STAT_API_STAT,
	MNT_STAT_API_TRUNCATE,
	MNT_STAT_API_CREAT,
	MNT_STAT_API_FSYNC,
	MNT_STAT_API_FDATASYNC,

	MNT_STAT_INODE_WAIT,

	MNT_STAT_FILE_SPEC_TYPE_COUNT
};

enum {
	MNT_STAT_TH_NCOUNT,
	MNT_STAT_TH_ACTIVE,

	MNT_STAT_TH_TYPE_COUNT
};

struct timeval;
typedef struct admin_buf admin_buf_t;

void pfs_mntstat_init();
void pfs_mntstat_prepare(struct timeval* stat_begin, int api_type);
void pfs_mntstat_set_file_type(int file_type);
void pfs_mntstat_store(struct timeval* stat_begin, struct timeval* stat_end,
    int stat_type, bool file_type_spec, uint32_t size);
void pfs_mntstat_reinit(struct timeval* stat_time);
void pfs_mntstat_sync(struct timeval* stat_time);
void pfs_mntstat_clear();

void pfs_mntstat_nthreads_change(int delta);

int pfs_mntstat_snap(admin_buf_t *ab, int64_t begin_time,
    int64_t time_range, char* file_type_pattern, int file_type_pattern_len);
int pfs_mntstat_sample(char* sample_pattern, int sample_pattern_len);

#define MNT_STAT_CLEAR() pfs_mntstat_clear()

#define MNT_STAT_BEGIN() \
	struct timeval	__stat_begin; \
	pfs_mntstat_prepare(&__stat_begin, MNT_STAT_API_NONE)

#define MNT_STAT_END(type) \
	pfs_mntstat_store(&__stat_begin, NULL, type, false, 0)

#define MNT_STAT_API_BEGIN(type) \
	struct timeval	__stat_begin; \
	pfs_mntstat_prepare(&__stat_begin, type)

#define MNT_STAT_API_END(type) do { \
	pfs_mntstat_store(&__stat_begin, NULL, type, true, 0); \
	MNT_STAT_CLEAR(); \
} while(0)

#define MNT_STAT_END_BANDWIDTH(type, size) \
	pfs_mntstat_store(&__stat_begin, NULL, type, true, (uint32_t)size)

#define MNT_STAT_API_END_BANDWIDTH(type, size) do { \
	MNT_STAT_END_BANDWIDTH(type, size); \
	MNT_STAT_CLEAR(); \
} while(0)

#define MNT_STAT_END_VALUE(type, stat_begin) \
	pfs_mntstat_store(stat_begin, NULL, type, false, 0)

#define MNT_STAT_END_VALUE_BANDWIDTH(type, stat_begin, size) \
	pfs_mntstat_store(stat_begin, NULL, type, false, (uint32_t)size)

#endif //POLARDB_PFS_MOUNTSTAT_H
