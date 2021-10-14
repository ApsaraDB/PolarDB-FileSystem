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

#ifndef PFSD_CHNL_IMPL_H_
#define PFSD_CHNL_IMPL_H_

#include <stdint.h>
#include <stdbool.h>

int32_t pfsd_chnl_get_channel_id();

typedef struct pfsd_chnl_op {
	const char *chnl_type_name;
	void* (*chnl_ctx_create)(const char *svr_addr, bool is_svr);
	void (*chnl_ctx_destroy)(void *chnl_ctx);

	//return connection_id if succeed.
	int32_t (*chnl_connect)(void *chnl_ctx, const char *cluster,
		const char *pbdname, int host_id, int flags, int timout_us,
		bool reconn);

	int (*chnl_prepare)(const char *pbdname, int nworkers, void *arg);
	int (*chnl_recover)(void *ctx, void *op, const char *svr_addr, 
		int workers, void *arg);
	int (*chnl_listen)(void *chnl_ctx, void *chnl_op, const char *svr_addr,
		void *arg1, void *arg2);
	int64_t (*chnl_send_req_sync)(void *chnl_ctx, int64_t max_req_len,
		void *req_buffer, int64_t max_rsp_len, void *rsp_buffer,
		void *io_buffer, long buffer_meta);
	int64_t (*chnl_recv_rsp_sync)(void *chnl_ctx, int64_t max_req_len,
		void *req_buffer, int64_t max_rsp_len, void *rsp_buffer, 
		void *io_buffer, long buffer_meta);

	int (*chnl_alloc)(void *chnl_ctx, int64_t max_req_len, void **req_buffer,
		int64_t max_rsp_len, void **rsp_buffer, void **io_buffer,
		long *buffer_meta);
	void (*chnl_free)(void *chnl_ctx, void *req_buffer,  void *rsp_buffer,
		void *io_buffer, long buffer_meta);
	void (*chnl_update_meta)(void *chnl_ctx, long meta);
	int (*chnl_abort)(void *chnl_ctx, int32_t pid);
	int (*chnl_close)(void *chnl_ctx, bool forced);
} pfsd_chnl_op_t;

typedef struct pfsd_connect_entry {
	int32_t connect_id;
	int32_t connect_refcnt;
	int connect_mntid;
	struct pfsd_chnl_op* connect_op;
	void* connect_data;
} pfsd_connect_entry_t;

void pfsd_chnl_ctx_create(const char *name, void **ctx, pfsd_chnl_op_t **op);

#define PFSD_REGISTER_ASSIGN(name, type) .name = name##type,
#define PFSD_CHNL_REGISTER(type, name) \
	static pfsd_chnl_op_t pfsd_chnl##type##_obj = { \
		.chnl_type_name = #name, \
		PFSD_REGISTER_ASSIGN(chnl_ctx_create, type) \
		PFSD_REGISTER_ASSIGN(chnl_ctx_destroy, type) \
		PFSD_REGISTER_ASSIGN(chnl_connect, type) \
		PFSD_REGISTER_ASSIGN(chnl_prepare, type) \
		PFSD_REGISTER_ASSIGN(chnl_recover, type) \
		PFSD_REGISTER_ASSIGN(chnl_listen, type) \
		PFSD_REGISTER_ASSIGN(chnl_send_req_sync, type) \
		PFSD_REGISTER_ASSIGN(chnl_recv_rsp_sync, type) \
		PFSD_REGISTER_ASSIGN(chnl_alloc, type) \
		PFSD_REGISTER_ASSIGN(chnl_free, type) \
		PFSD_REGISTER_ASSIGN(chnl_update_meta, type) \
		PFSD_REGISTER_ASSIGN(chnl_abort, type) \
		PFSD_REGISTER_ASSIGN(chnl_close, type) \
	}; \
	pfsd_chnl_op_t* pfsd_chnl##type##_pointer \
		__attribute__((used)) __attribute__((section("_pfsd_chnl"))) = \
		&pfsd_chnl##type##_obj

#endif //PFSD_CHNL_IMPL_H_
