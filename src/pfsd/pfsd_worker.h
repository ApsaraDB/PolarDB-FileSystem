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

#ifndef _PFSD_WORKER_H_
#define _PFSD_WORKER_H_

#include <pthread.h>
#include "pfsd_proto.h"
#include "pfsd_common.h"

struct pfsd_iochannel;

extern volatile bool g_stop;

/*A worker thread is dedicated to a shm */
typedef struct worker {
	pthread_t w_tid;
	int w_idx;
	int w_nch;
	struct pfsd_iochannel *w_channels[PFSD_SHM_MAX  *PFSD_WORKER_MAX];
	sem_t w_sem; /*for sync start thread */
	pfsd_cpu_record_t *w_cr; /*if it set affinity */
} worker_t;

extern worker_t *g_workers;
extern int g_nworkers;

worker_t *pfsd_create_workers(int nworkers);
void pfsd_destroy_workers(worker_t **workers);

void *pfsd_worker_routine(void *arg);

extern pfsd_cpu_record_t *g_cpufile;
extern int g_ncpu;
/*Exec in main thread when start, find available core for worker threads */
void *pfsd_worker_affinity_prepare(int nworkers);
bool pfsd_worker_bind_cpuset(worker_t *worker);
bool pfsd_is_busy_cpu(int cpuid, int ncpu);

int pfsd_worker_handle_request(pfsd_iochannel *ch, int index);

void pfsd_worker_handle_growfs(pfsd_iochannel *ch, int index, const growfs_request_t *req, growfs_response_t *rsp);
void pfsd_worker_handle_rename(pfsd_iochannel *ch, int index, const rename_request_t *req, rename_response_t *rsp);
void pfsd_worker_handle_open(pfsd_iochannel *ch, int index, const open_request_t *req, open_response_t *rsp);
void pfsd_worker_handle_read(pfsd_iochannel *ch, int index, const read_request_t *req, read_response_t *rsp);
void pfsd_worker_handle_write(pfsd_iochannel *ch, int index, const write_request_t *req, write_response_t *rsp);
void pfsd_worker_handle_truncate(pfsd_iochannel *ch, int index, const truncate_request_t *req, truncate_response_t *rsp);
void pfsd_worker_handle_ftruncate(pfsd_iochannel *ch, int index, const ftruncate_request_t *req, ftruncate_response_t *rsp);
void pfsd_worker_handle_unlink(pfsd_iochannel *ch, int index, const unlink_request_t *req, unlink_response_t *rsp);
void pfsd_worker_handle_stat(pfsd_iochannel *ch, int index, const stat_request_t *req, stat_response_t *rsp);
void pfsd_worker_handle_fstat(pfsd_iochannel *ch, int index, const fstat_request_t *req, fstat_response_t *rsp);
void pfsd_worker_handle_fallocate(pfsd_iochannel *ch, int index, const fallocate_request_t *req, fallocate_response_t *rsp);
void pfsd_worker_handle_chdir(pfsd_iochannel *ch, int index, const chdir_request_t *req, chdir_response_t *rsp);
void pfsd_worker_handle_mkdir(pfsd_iochannel *ch, int index, const mkdir_request_t *req, mkdir_response_t *rsp);
void pfsd_worker_handle_rmdir(pfsd_iochannel *ch, int index, const rmdir_request_t *req, rmdir_response_t *rsp);
void pfsd_worker_handle_opendir(pfsd_iochannel *ch, int index, const opendir_request_t *req, opendir_response_t *rsp);
void pfsd_worker_handle_readdir(pfsd_iochannel *ch, int index, const readdir_request_t *req, readdir_response_t *rsp);
void pfsd_worker_handle_access(pfsd_iochannel *ch, int index, const access_request_t *req, access_response_t *rsp);
void pfsd_worker_handle_lseek(pfsd_iochannel *ch, int index, const lseek_request_t *req, lseek_response_t *rsp);

/*for debug : return current processing request's pid  */
pid_t pfsd_worker_current_processing_pid();

#endif

