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

#ifndef _TRACE_COMMON_H_
#define _TRACE_COMMON_H_

#include <stdio.h>
#include <stdint.h>

#define TRACE_NAME              "polartrace"
#define TRACE_SETTING_NAME      "setting"
#define TRACE_BUFFER_NAME       "buffer"
#define TRACE_STAT_NAME         "stats"
#define TRACE_MONITOR_NAME      "monitor"
#define TRACE_PROBE_NAME        "probe"

#define TRACE_BASE_NAME         "/dev/shm"
#define TRACE_RUN_PATH          "/var/run"
#define TRACE_REGISTRY_NAME     "registry"
#define TRACE_UNIX_SOCK         "polartrace.sock"
#define MAX_TRACE_POINT_COUNT   64
#define TRACE_UNIX_NAME_MAX_LEN 108
#define TRACE_WATCHER_COUNT     128
#define TRACE_TIMER_COUNT       128
#define MAX_STAT_COUNT          128
#define MAX_STAT_NAME_LEN       32

#define OFFSET_APP_TYPE         24
#define STAT_TYPE_MASK          ((1 << OFFSET_APP_TYPE) - 1)
#define TypeToIndex(type)       (type & STAT_TYPE_MASK)
#define TypeToAppType(type)     (TraceAppType)(type >> OFFSET_APP_TYPE)
#define AppTypeToStatBase(type) (STAT_TYPE_BASE)(type << OFFSET_APP_TYPE)

#define ValueAligned4K(value)   ((value & 0xfff) == 0)

#define BSR_TRACE_CAP           1
#define TRACE_MAX_PATH_LEN      512
#define HISTGRAM_TYPE_CNT       8
#define HISTGRAM_RANGE_CNT      32

#define TRACE_ARR_LEN(arr)      ((sizeof(arr))/(sizeof(arr[0])))

#define DATA_SEC_ATTR(sector)                               \
    __attribute__((section(#sector)))

#define DATA_SEC_DECL(type, sector)                         \
    extern type *__start_##sector[], *__stop_##sector[];

#define DATA_SEC_FOREACH(var, sector)                       \
    for(var = __start_##sector; var < __stop_##sector; var++)

#define ATOMIC_FETCH_AND_ADD(a, b)                          \
        __sync_fetch_and_add(a, b)

#define ATOMIC_TEST_AND_SET(a, b)                           \
        __sync_lock_test_and_set(a, b)

#define ATOMIC_LOAD(a, b, memorder)                         \
        __atomic_load(a, b, memorder)

#define ATOMIC_STORE(a, b, memorder)                        \
        __atomic_store(a, b, memorder)

#define ATOMIC_FETCH_ADD(a, b, memorder)                    \
        __atomic_fetch_add(a, b, memorder)

enum TraceAppType {
    TRACE_APP_BSR = 1,
    TRACE_APP_PLS = 2,
    TRACE_APP_PFS = 3,
    TRACE_MAX_APP_TYPE,
};

struct StatTag {
    uint32_t server_id;
    uint32_t pbdno;
    uint32_t pbdver;
    uint32_t chunk_id;
    uint32_t disk_id;
};

#define FUNCADDR() \
    ({\
        uint64_t ___p___; \
        asm ("leaq (%%rip), %%rax\n\t movq %%rax, %0\n\t": "=r"(___p___)::"rax");\
        ___p___; \
    })

const static struct StatTag common_tag = {0, 0, 0, 0, 0};

enum TraceLogLevel {
    TRACE_DEBUG = 0,
    TRACE_INFO,
    TRACE_ERROR
};

enum TraceAggreType {
    AGGRE_TYPE_COUNTER      = 10000,
    AGGRE_TYPE_BANDWIDTH    = 10001,
    AGGRE_TYPE_LAT_ENTRY    = 10002,
    AGGRE_TYPE_LAT_DONE     = 10003,
};

enum TRACE_OP {
    NOTIFY_OP               = 1,
    REGISTRY_OP,
    ONLINE_CONFIG_OP,
};

enum NotifyType {
    TRACEPOINT_NOTIFY       = 1,
    STAT_NOTIFY,
    MONITOR_NOTIFY,
    PROBE_NOTIFY,
    EASYSTAT_NOTIFY,
    SNAPSHOT_NOTIFY,
    HEARTBEAT_NOTIFY,
    QUERY_NOTIFY,
    MAX_NOTIFY_TYPE,
};

static inline const char *trace_type2name(TraceAppType type) {
    switch(type) {
        case TRACE_APP_BSR:
            return "bsr";
        case TRACE_APP_PLS:
            return "pls";
        case TRACE_APP_PFS:
            return "pfs";
        default:
            return NULL;
    }
    return NULL;
}

#ifndef TRACE_ASSERT_RETNONE
#define TRACE_ASSERT_RETNONE(cond) if ( !(cond) ) { return; }
#endif

#ifndef TRACE_ASSERT_RETVAL
#define TRACE_ASSERT_RETVAL(cond, val) if ( !(cond) ) { return (val); }
#endif


#endif

