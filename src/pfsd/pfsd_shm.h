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

#ifndef	_PFSD_SHM_H_
#define _PFSD_SHM_H_

#include <pthread.h>
#include <stdint.h>
#include "pfsd_common.h"
#include "pfsd_proto.h"

#define PFSD_SHM_VERSION (0x02)

/* Requests in channel, must be 64 */
#define PFSD_SHM_MAX_REQUESTS (64)

/* A channel in shm, visited by multiple processes */
typedef struct pfsd_iochannel {
    uint32_t ch_epoch;
    uint32_t ch_magic;

    /* channel index */
    int ch_index;
    /* buf size */
    size_t ch_unitsize;
    /* max_requests, no bigger than PFSD_SHM_MAX_REQUESTS  */
    int ch_max_req;

    char ch_padding[512];

    /* mutex used only by pfsd */
    //pthread_mutex_t ch_req_lock;
    volatile uint64_t ch_free_bitmap __attribute__((aligned(64)));
    pfsd_request_t ch_requests[PFSD_SHM_MAX_REQUESTS];
    /* It's protected by ch_free_bitmap, along with ch_requests */
    pfsd_response_t ch_responses[PFSD_SHM_MAX_REQUESTS];

    /* It's protected by ch_free_bitmap, along with ch_requests
     * aligned by 4KB is appropriate for disk io.  */
    unsigned char ch_buf[] __attribute__((aligned(4096))); /* ch_max_req * ch_unitsize */
} pfsd_iochannel_t;

/* A shm is visited by multiple processes */
typedef struct pfsd_shm {
    uint32_t sh_magic;
    uint32_t sh_version;
    uint32_t sh_epoch;
    int sh_size;
    size_t sh_unitsize;
    int sh_nch;
    int sh_index;

} __attribute__((aligned(4096))) pfsd_shm_t;

typedef char _check_shm_header_[sizeof(pfsd_shm_t) == 4096 ? 1 : -1];

extern size_t g_shm_unit_size[PFSD_SHM_MAX];
extern pfsd_shm_t* g_shm[PFSD_SHM_MAX];
extern char g_shm_fname[PFSD_SHM_MAX][512];

static inline
size_t pfsd_channel_size(int nreq,  uint32_t unit_size) {
    return sizeof(pfsd_iochannel_t) + nreq * unit_size;
}

static inline
size_t pfsd_shm_size(int nch, int nreq, uint32_t unit_size) {
    return sizeof(pfsd_shm_t) + nch * pfsd_channel_size(nreq, unit_size);
}

static inline
pfsd_shm_t *pfsd_channel_shm(pfsd_iochannel_t *ch) {
    return (pfsd_shm_t *)((char *)ch - sizeof(pfsd_shm_t) - 
        ch->ch_index * pfsd_channel_size(ch->ch_max_req, ch->ch_unitsize));
}

int pfsd_shm_init(const char *shm_dir, const char *pbdname, size_t nch);
int pfsd_shm_destroy(pfsd_shm_t *shm);

/* shm attach, for pfsd shm tools */
int pfsd_shm_attach(const char *shm_dir, const char *pbd, int wr_attach);
void pfsd_print_shm(pfsd_shm_t *shm);
void pfsd_print_channel(pfsd_shm_t *shm, int ch_index);
void pfsd_print_all_channels(pfsd_shm_t *shm);

/* DB process got a request to fill in */
pfsd_request_t *pfsd_shm_get_request(pfsd_iochannel_t *ch, int connid);

/* DB process give request back to shm.
 * The arg req must be returned by pfsd_shm_get_request.
 */
int pfsd_shm_put_request(pfsd_iochannel_t *ch, pfsd_request_t *req);

/* DB process send request to pfs_daemon.
 * The arg req must be returned by pfsd_shm_get_request.
 */
void pfsd_shm_send_request(pfsd_iochannel_t* ch, pfsd_request_t *req);

/* pfsd fetch request to process */
pfsd_request_t *pfsd_shm_fetch_request(pfsd_iochannel_t *ch);

/* When pfsd worker done request, dequeue it and notify DB process */
void pfsd_shm_done_request(pfsd_iochannel_t *shm, int req_index);

/* pfsd recycle requests up to limit */
void pfsd_shm_recycle_request(pfsd_iochannel_t *ch);

/* client side call this */
int pfsd_shm_cli_abort_request(pfsd_shm_t *shm, int conn_id, pid_t pid);
/* server side call this */
int pfsd_shm_svr_abort_request(pfsd_shm_t *shm, int conn_id, bool force);

int pfsd_shm_abort_request(pfsd_shm_t *shm, int conn_id, pid_t pid, bool force, bool is_svr);


void pfsd_wait_io(pfsd_request_t *req, sem_t *sem);

int pfsd_sdk_alloc_request(int32_t connid, size_t iosize, pfsd_shm_t *shm[], int nshm,
                           pfsd_iochannel_t **och, pfsd_request_t **oreq);
#endif

