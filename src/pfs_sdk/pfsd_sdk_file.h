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

#ifndef _PFSD_SDK_FILE_H_
#define _PFSD_SDK_FILE_H_

#include "pfs_impl.h"

#include <sys/types.h>
#include <pthread.h>

#include "pfsd_proto.h"

#ifdef __cplusplus
extern "C" {
#endif


bool pfsd_writable(int mnt_flags);

typedef struct pfsd_file {
    pthread_rwlock_t f_rwlock;
    int     f_fd;
    int     f_flags;
    off_t   f_offset;

    int64_t f_inode;
    int32_t f_refcnt; /* incr when be reading/writing */
    pfsd_chnl_payload_common_t f_common_pl;
} pfsd_file_t;

void pfsd_sdk_file_init();

/* for sdk internal */
pfsd_file_t *
	pfsd_alloc_file();
void	pfsd_free_file(pfsd_file_t*);
int	pfsd_alloc_fd(pfsd_file_t*);
pfsd_file_t *
	pfsd_get_file(int fd, bool writelock);
void	pfsd_put_file(pfsd_file_t *file);
int	pfsd_close_file(pfsd_file_t *file);
void	pfsd_file_cleanup();

/* dir */
bool	pfsd_chdir_begin();
bool	pfsd_chdir_end();
int	pfsd_dir_xsetwd(const char *path, size_t len);
int	pfsd_dir_xgetwd(char *buf, size_t len);

/* name and cwd */
const char *
	pfsd_name_init(const char *pbdpath, char *abspbdpath, size_t size);
int	pfsd_normalize_path(char *pbdpath);

#ifdef __cplusplus
}
#endif

#endif

