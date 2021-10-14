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

#ifndef	_PFS_TRACE_H_
#define	_PFS_TRACE_H_

#include <stdarg.h>

#include "trace_pfs_ctx.h"
#include "pfs_util.h"

enum {
	PFS_TRACE_OFF	= 0,
	PFS_TRACE_ERROR	= 1,
	PFS_TRACE_WARN	= 2,
	PFS_TRACE_INFO	= 3,
	PFS_TRACE_DBG	= 4,
	PFS_TRACE_DEBUG	= PFS_TRACE_DBG,
	PFS_TRACE_VERB	= 5,
};

void	pfs_vtrace(int level, const char *fmt, ...);

extern int64_t trace_plevel;

#define pfs_trace(level, force, fmt,...) \
do { \
	if (level <= trace_plevel || force) \
		pfs_vtrace(level, fmt, ##__VA_ARGS__); \
} while(0)

#define pfs_itrace(fmt,...) \
do { \
	if (PFS_TRACE_INFO <= trace_plevel) \
		pfs_vtrace(PFS_TRACE_INFO, fmt, ##__VA_ARGS__); \
} while(0)

#define pfs_etrace(fmt,...) \
do { \
	if (PFS_TRACE_ERROR <= trace_plevel) \
		pfs_vtrace(PFS_TRACE_ERROR, fmt, ##__VA_ARGS__); \
} while(0)

#define pfs_dbgtrace(fmt,...) \
do { \
	if (PFS_TRACE_DBG <= trace_plevel) \
		pfs_vtrace(PFS_TRACE_DBG, fmt, ##__VA_ARGS__); \
} while(0)

typedef struct tracectl {
	const char 	*tc_file;
	const char 	*tc_func;
	int 		tc_line;
	int 		tc_level;
	int		tc_enable;
	const char	*tc_format;
} tracectl_t;

#define	pfs_verbtrace(fmt, ...)	do {					\
	static tracectl_t _tc = { 					\
		__FILE__, __func__, __LINE__, 				\
		PFS_TRACE_DBG, 						\
		false, 							\
		fmt,							\
       	}; 								\
	static tracectl_t *_ptr DATA_SET_ATTR(_tracectl) = &_tc;	\
									\
	if (_tc.tc_enable)						\
		pfs_trace(_tc.tc_level, true, fmt, ##__VA_ARGS__);	\
} while (0)

typedef	struct msg_header	msg_header_t;
typedef	struct msg_trace	msg_trace_t;

int	pfs_trace_handle(int sock, msg_header_t *mh, msg_trace_t *tr);
void 	pfs_trace_redirect(const char *pbdname, int hostid);

typedef void pfs_log_func_t(const char *buf);
extern pfs_log_func_t *pfs_log_functor;

#endif
