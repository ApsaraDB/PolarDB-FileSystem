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

#ifndef _PFSD_ZLOG_H_
#define _PFSD_ZLOG_H_

#include <zlog.h>

#define CHKSVR_LOG_LEVEL_DEBUG  20
#define CHKSVR_LOG_LEVEL_INFO   40
#define CHKSVR_LOG_LEVEL_NOTICE 60
#define CHKSVR_LOG_LEVEL_WARN   80
#define CHKSVR_LOG_LEVEL_ERROR  100
#define CHKSVR_LOG_LEVEL_FATAL  120

#ifndef CHKSVR_LOG_LEVEL
    #define CHKSVR_LOG_LEVEL CHKSVR_LOG_LEVEL_INFO
#endif

#if CHKSVR_LOG_LEVEL == CHKSVR_LOG_LEVEL_DEBUG
#define pfsd_debug(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_DEBUG, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_info(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_INFO, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_notice(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_NOTICE, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_warn(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_WARN, __VA_ARGS__);  \
    errno = saved_err; \
} while(0)

#define pfsd_error(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_ERROR, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_fatal(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_FATAL, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#elif CHKSVR_LOG_LEVEL == CHKSVR_LOG_LEVEL_INFO
#define pfsd_debug(...) do {} while (0)
#define pfsd_info(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_INFO, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_notice(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_NOTICE, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_warn(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_WARN, __VA_ARGS__);  \
    errno = saved_err; \
} while(0)

#define pfsd_error(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_ERROR, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_fatal(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_FATAL, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#elif CHKSVR_LOG_LEVEL == CHKSVR_LOG_LEVEL_NOTICE
#define pfsd_debug(...) do {} while (0)
#define pfsd_info(...)  do {} while (0)
#define pfsd_notice(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_NOTICE, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_warn(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_WARN, __VA_ARGS__);  \
    errno = saved_err; \
} while(0)

#define pfsd_error(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_ERROR, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_fatal(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_FATAL, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#elif CHKSVR_LOG_LEVEL == CHKSVR_LOG_LEVEL_WARN
#define pfsd_debug(...)  do {} while (0)
#define pfsd_info(...)   do {} while (0)
#define pfsd_notice(...) do {} while (0)
#define pfsd_warn(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_WARN, __VA_ARGS__);  \
    errno = saved_err; \
} while(0)

#define pfsd_error(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_ERROR, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_fatal(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_FATAL, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#elif CHKSVR_LOG_LEVEL == CHKSVR_LOG_LEVEL_ERROR
#define pfsd_debug(...)  do {} while (0)
#define pfsd_info(...)   do {} while (0)
#define pfsd_notice(...) do {} while (0)
#define pfsd_warn(...)   do {} while (0)
#define pfsd_error(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_ERROR, __VA_ARGS__); \
    errno = saved_err; \
} while(0)

#define pfsd_fatal(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_FATAL, __VA_ARGS__); \
    errno = saved_err; \
} while(0)
#elif CHKSVR_LOG_LEVEL == CHKSVR_LOG_LEVEL_FATAL
#define pfsd_debug(...)  do {} while (0)
#define pfsd_info(...)   do {} while (0)
#define pfsd_notice(...) do {} while (0)
#define pfsd_warn(...)   do {} while (0)
#define pfsd_error(...)  do {} while (0)
#define pfsd_fatal(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_FATAL, __VA_ARGS__); \
    errno = saved_err; \
} while(0)
#else
#define pfsd_debug(...)  do {} while (0)
#define pfsd_info(...)   do {} while (0)
#define pfsd_notice(...) do {} while (0)
#define pfsd_warn(...)   do {} while (0)
#define pfsd_error(...)  do {} while (0)
#define pfsd_fatal(...)  do {} while (0)
#endif

/* cs_log is always write log no metter debug or release */
#define pfsd_log(...) do { \
    int saved_err = errno; \
    dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, \
          __LINE__, ZLOG_LEVEL_INFO, __VA_ARGS__) ; \
    errno = saved_err; \
} while(0)

static inline int LogInit(const char *conf, char *cat) {
    return dzlog_init(conf, cat);
}

static inline void LogFini() {
    zlog_fini();
}

extern zlog_category_t *original_zlog_cat;

static inline void wrapper_zlog(const char *buf) {
    zlog(original_zlog_cat, "", 0, "", 0, __LINE__, ZLOG_LEVEL_INFO, "%s", buf);
}

#endif

