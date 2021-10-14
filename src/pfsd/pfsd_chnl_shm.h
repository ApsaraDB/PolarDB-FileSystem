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

#ifndef PFSD_CHNL_SHM_H_
#define PFSD_CHNL_SHM_H_

#include <stdint.h>
#include <stdbool.h>
#include <semaphore.h>
#include <unistd.h>

#include "pfsd_chnl.h"
#include "pfsd_common.h"

#define CHNL_SHM_VER 2
#define CHNL_SHM_CONNECT_POLL_UNIT 100 // 0.1ms


#define PBD_MAX_NAME_LEN 64

// located at first [0, 4KB)
typedef struct pidfile_sync_data {
	uint32_t ver;
	char cluster[PBD_MAX_NAME_LEN];
	char pbdname[PBD_MAX_NAME_LEN];
	int32_t host_id;
	int32_t flags;
	uint32_t shm_mnt_epoch;
}__attribute__((aligned(4096))) pidfile_sync_data_t;

// located at first [4KB, 8KB)
typedef struct pidfile_ack_data {
	int32_t err;
	uint32_t ver;
	char err_msg[64];
	struct {
		int32_t shm_connect_id;
		char shm_fname[PFSD_SHM_MAX][FILE_MAX_FNAME];
		int32_t mntid;
		uint32_t shm_mnt_epoch;
		int32_t flags;
		int32_t err_remount;
	}v1;
}__attribute__((aligned(4096))) pidfile_ack_data_t;

typedef struct pidfile_data {
	pidfile_sync_data_t sync_data;
	pidfile_ack_data_t  ack_data;
}__attribute__((aligned(4096))) pidfile_data_t;

typedef struct chnl_ctx_shm {
	int	 ctx_pidfile_fd;
	char	ctx_pidfile_dir[PFSD_MAX_SVR_ADDR_SIZE]; /* pidfile dir which be watched by inotify */
	char	ctx_pidfile_addr[PFSD_MAX_SVR_ADDR_SIZE];/* pidfile with absolute path */
	bool	ctx_is_svr;
	union {
		/* For client if ctx_is_svr is false */
		struct {
			int32_t shm_connect_id;
			char *shm_ptr[PFSD_SHM_MAX];
			int64_t shm_len[PFSD_SHM_MAX];
			int32_t mntid;
			pidfile_data_t shm_pidfile_data;
		} clt;
		/* For server if ctx_is_svr is true */
		struct {
			sem_t shm_listen_thread_latch;
			int shm_inotify_fd;
			char shm_fname[PFSD_SHM_MAX][FILE_MAX_FNAME]; /* shm path for communication */
		} svr;
	};
} chnl_ctx_shm_t;

void pfsd_chnl_shm_client_init();

#endif //PFSD_CHNL_SHM_H_
