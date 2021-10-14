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

#ifndef PFSD_CHNL_H_
#define PFSD_CHNL_H_

#include <stdlib.h>
#include <stdint.h>

#define PFSD_MAX_SVR_ADDR_SIZE	4096
#define PFSD_CONNECT_TIMEOUT_US	(3 * 1000000)
#define CHNL_MAX_CONN		16

typedef struct pfsd_connect_entry pfsd_connect_entry_t;

enum pfsd_chnl_req_type {
	CHNL_MOUNT		= 0,

	//like growfs, remount
	CHNL_MOUNT_UPDATE	= 1,

	//like stat
	CHNL_READ_META		= 2,
	//like pread(it may also read meta)
	CHNL_READ_DATA		= 3,
	CHNL_READ_DATA_AIO	= 4,
	//like ftruncate
	CHNL_WRITE_META		= 5,
	//like pwrite(it may also read/write meta)
	CHNL_WRITE_DATA		= 6,
	CHNL_WRITE_DATA_AIO	= 7,

	CHNL_ABORT		= 8,
};

int32_t pfsd_chnl_connect(const char *svr_addr, const char *cluster,
    int timeout_ms, const char *pbdname, int host_id, int flags);

int32_t pfsd_chnl_reconnect(int32_t conn_id, const char *cluster,
    int timeout_ms, const char *pbdname, int host_id, int flags);

int pfsd_chnl_buffer_alloc(int32_t connect_id, int64_t max_req_len,
    void **req_buffer, int64_t max_rsp_len, void **rsp_buffer, void **io_buffer,
    long *buffer_meta);

int64_t pfsd_chnl_send_recv(int32_t connect_id, void *req_buffer,
    int64_t req_len, void *rsp_buffer, int64_t max_rsp_len, void *io_buffer,
    long buffer_meta, int timout_us);

void pfsd_chnl_buffer_free(int32_t connect_id, void *req_buf, void *rsp_buf,
    void *io_buf, long buffer_meta);

void pfsd_chnl_update_meta(int32_t connect_id, long meta);

int pfsd_chnl_get_logic_id(int32_t connect_id);

int pfsd_chnl_abort(int32_t connect_id, pid_t pid);

int pfsd_chnl_close(int32_t connect_id, bool force);

int pfsd_chnl_listen(const char *svr_addr, const char *pbdname, int nworkers,
    void *arg1, void *arg2);

/* server side */
int32_t pfsd_chnl_accept_begin(void *ctx, void *op, int32_t conn_id_hint);

void pfsd_chnl_accept_begin_rollback(int32_t conn_id);

/* server side */
void pfsd_chnl_accept_end(int32_t conn_id, int mnt_id);

/* server side */
int32_t pfsd_chnl_close_begin(int32_t connect_id);

/* server side */
void pfsd_chnl_close_end();

bool pfsd_is_valid_connid(int32_t cid);

bool pfsd_is_conn_closed(int32_t connect_id);

#endif //PFSD_CHNL_H_

