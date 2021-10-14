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

#ifndef _PFSD_API_H_
#define _PFSD_API_H_

#include "pfsd_common.h"

typedef struct pfs_mount pfs_mount_t;
typedef struct pfs_inode pfs_inode_t;

/* return ino */
int64_t	pfsd_creat_svr(const char *pbdpath, mode_t , uint64_t *btime,
	    int32_t *file_type);
int64_t	pfsd_open_svr(const char *pbdpath, int flags, mode_t,
	    uint64_t *btime, int32_t *file_type);

ssize_t	pfsd_pread_svr(pfs_mount_t *mnt, pfs_inode_t *inode, void *buf,
	    size_t len, off_t off, uint64_t btime);
ssize_t	pfsd_pwrite_svr(pfs_mount_t *mnt, pfs_inode_t *inode, int flags,
	    const void *buf, size_t len, off_t off, ssize_t *file_size, uint64_t btime);

int	pfsd_truncate_svr(const char *pbdpath, off_t len);
int	pfsd_ftruncate_svr(pfs_mount_t *mnt, pfs_inode_t *in, off_t len, uint64_t btime);

int	pfsd_unlink_svr(const char *pbdpath);

int	pfsd_stat_svr(const char *pbdpath, struct stat *buf);
int	pfsd_fstat_svr(pfs_mount_t *mnt, pfs_inode_t *in, struct stat *buf, uint64_t btime);

int	pfsd_fallocate_svr(pfs_mount_t *mnt, pfs_inode_t *in, off_t offset,
	    off_t len, int mode, uint64_t btime);
int	pfsd_chdir_svr(const char *pbdpath);

int	pfsd_opendir_svr(const char *pbdpath, int64_t *deno, int64_t *first_ino);
int	pfsd_readdir_svr(pfs_mount_t *mnt, int64_t dino, int64_t ino,
	    uint64_t offset, struct dirent *entry, int64_t *next_ino);

off_t	pfsd_lseek_end_svr(pfs_mount_t *mnt, pfs_inode_t *in, off_t off, uint64_t btime);

#endif

