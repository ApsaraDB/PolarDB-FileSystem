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

#ifndef _TRACE_PFS_CTX_H_
#define _TRACE_PFS_CTX_H_

#include <sys/time.h>
#include "trace_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define  PFS_TRACE_STATCAP 256
int     _pfs_trace_ctx_init(unsigned int svrid, const char *pbdname);
void    _pfs_trace_ctx_stop();
void    pfs_trace_log_func(TraceLogLevel lv, const char *fmt, ...);

#if     defined(PFS_TRACE_ENABLE)

#define pfs_trace_ctx_init(server_id, pbdname)      \
        _pfs_trace_ctx_init(server_id, pbdname)

#define pfs_trace_ctx_stop()                        \
        _pfs_trace_ctx_stop()

#define PFS_STAT_BANDWIDTH(type, value)     \
        polar_stat(0, 0, STAT_TYPE_HIST, STAT_OP_UPDATE_BW, type, value);

#define PFS_INC_COUNTER(type)              \
        polar_stat(0, 0, STAT_TYPE_CNT, STAT_OP_UPDATE_CNT, type, 1);

#define PFS_STAT_LATENCY_ENTRY(type)        \
        struct timeval __trace_ts__;        \
        gettimeofday(&__trace_ts__, NULL);

#define PFS_STAT_LATENCY(type)              \
        polar_stat_latency(0, 0, type, &__trace_ts__);

#define PFS_STAT_LATENCY_VALUE(type, pvalue)      \
        polar_stat_latency(0, 0, type, pvalue);

#else

#define pfs_trace_ctx_init(server_id, pbdname)  do{ } while(0)
#define pfs_trace_ctx_stop() do{ } while(0)

#define PFS_STAT_BANDWIDTH(type, value)     do{ } while(0)
#define PFS_INC_COUNTER(type)               do{ } while(0)
#define PFS_STAT_LATENCY_ENTRY(type)        do{ } while(0)
#define PFS_STAT_LATENCY(type)              do{ } while(0)
#define PFS_STAT_LATENCY_VALUE(type, pvalue) do{ } while(0)
#endif

#if     defined(PFS_TRACEPOINT_ENABLE)
// pfs trace
extern  uint32_t g_trace_server_id;
#define PFS_SetTraceid(req)                                     \
do {                                                            \
    static uint32_t id = 0;                                     \
    ATOMIC_FETCH_AND_ADD(&id, 1);                               \
    struct timeval ts;                                          \
    gettimeofday(&ts, NULL);                                    \
    req->trace_ts           = ts.tv_sec * 1000000 + ts.tv_usec; \
    req->trace_spanid       = 0;                                \
    req->trace_server_id    = g_trace_server_id;                \
    req->trace_main_id      = id;                               \
    req->trace_pfs_sub_id   = 0;                                \
    trace_set_type(req->trace_flags, TRACE_TYPE_PLS);           \
    if(SAMPLE_POINT(req->trace_main_id))                        \
        req->trace_flags   |= TRACE_TP_FLAG;                    \
    fprintf(stderr, "[PFS_TRACE_LOG] trace main id %u\n", req->trace_main_id);  \
} while(0)

#else

#define PFS_SetTraceid(req)     do{ } while(0)

#endif


#ifdef __cplusplus
}
#endif

#endif
