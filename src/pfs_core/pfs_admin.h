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

#ifndef _PFS_ADMIN_H_
#define _PFS_ADMIN_H_

#include <sys/socket.h>
#include <sys/types.h>

#include "pfs_impl.h"
#include "pfs_option.h"

enum {
	ADM_NONE		= 0,
	ADM_TRACE		= 7,	/* trace manipulation */
	ADM_ERRINJECT		= 8,	/* inject error */
	ADM_COMMAND		= 9,
	ADM_OPTION		= 10,
};

enum {
	TRACE_LIST_REQ		= 1,
	TRACE_LIST_RPL		= 2,

	TRACE_SET_REQ		= 3,
	TRACE_SET_RPL		= 4,

	OPTION_LIST_REQ		= 5,
	OPTION_LIST_RPL		= 6,

	OPTION_SET_REQ		= 7,
	OPTION_SET_RPL		= 8,

	OPTION_RELOAD_REQ = 9,
	OPTION_RELOAD_RPL = 10,
};

enum {
	EINJECT_REQ		= 1,
	EINJECT_RPL		= 2,
};

enum {
	CMD_READ_REQ		= 1,
	CMD_READ_RPL		= 2,

	CMD_DU_REQ		= 3,
	CMD_DU_RPL		= 4,

	CMD_STAT_REQ		= 5,
	CMD_STAT_RPL		= 6,

	CMD_LSOF_REQ		= 7,
	CMD_LSOF_RPL		= 8,

	CMD_MEMSTAT_REQ		= 9,
	CMD_MEMSTAT_RPL		= 10,

	CMD_INFO_REQ		= 11,
	CMD_INFO_RPL		= 12,

	CMD_DEVSTAT_REQ		= 13,
	CMD_DEVSTAT_RPL		= 14,

	CMD_CACHESTAT_REQ	= 15,
	CMD_CACHESTAT_RPL	= 16,

	CMD_MOUNTSTAT_REQ	= 17,
	CMD_MOUNTSTAT_RPL	= 18,

	CMD_NAMECACHE_STAT_REQ = 19,
	CMD_NAMECACHE_STAT_RPL = 20,

	CMD_NAMECACHE_BINSTAT_REQ = 21,
	CMD_NAMECACHE_BINSTAT_RPL = 22
};

typedef struct msg_header {
	int16_t		mh_type;
	int16_t		mh_op;
	int32_t		mh_error;
	int64_t		mh_datalen;
} msg_header_t;

typedef struct msg_trace {
	char		tr_file[PFS_MAX_PATHLEN];
	int32_t		tr_line;
	int32_t		tr_level;
	int32_t		tr_enable;
} msg_trace_t;

typedef struct msg_option {
	char		o_name[PFS_MAX_OPTLEN];
	int64_t		o_value;
} msg_option_t;

struct cmd_read {
	char		rd_file[PFS_MAX_PATHLEN];
	int64_t		rd_off;
	int64_t		rd_len;
} __attribute__((packed));

struct cmd_du {
	char		du_file[PFS_MAX_PATHLEN];
	int		du_depth;
	int		du_all;
} __attribute__((packed));

struct cmd_memstat {
        int             mt_type;
} __attribute__((packed));

struct cmd_lsof {
	int		lsof_fd;
} __attribute__((packed));

struct cmd_info {
	char		info_pbdname[PFS_MAX_PBDLEN];
	int		info_depth;
} __attribute__((packed));

struct cmd_devstat {
	char		ds_pbdname[PFS_MAX_PBDLEN];
} __attribute__((packed));

struct cmd_cachestat {
	char		bs_pbdname[PFS_MAX_PBDLEN];
} __attribute__((packed));

#define FILE_TYPE_PATTERN_MAXLEN 256
struct cmd_mountstat {
	char		ms_pbdname[PFS_MAX_PBDLEN];
	int64_t		ms_begin_time;
	int64_t		ms_time_range;
	char		ms_file_type_pattern[FILE_TYPE_PATTERN_MAXLEN];
	char		ms_sample_pattern[FILE_TYPE_PATTERN_MAXLEN];
} __attribute__((packed));

struct cmd_namecachestat {
	int			type;
} __attribute__((packed));

struct cmd_namecachebinstat {
	int			unused;
} __attribute__((packed));

typedef union msg_command {
	struct cmd_read	mc_rd;
	struct cmd_du	mc_du;
	struct cmd_lsof	mc_lsof;
	struct cmd_memstat mc_memstat;
	struct cmd_info	mc_info;
	struct cmd_devstat mc_devstat;
	struct cmd_cachestat mc_cachestat;
	struct cmd_mountstat mc_mountstat;
	struct cmd_namecachestat mc_namecachestat;
	struct cmd_namecachebinstat mc_namecachebinstat;
} msg_command_t;

typedef struct admin_info 	admin_info_t;
typedef	struct admin_buf 	admin_buf_t;

admin_info_t *	pfs_admin_init(const char *pbdname);
int 		pfs_admin_fini(admin_info_t *ai, const char *pbdname);
int		pfs_admin_reply(int sock, int type, int op, int error, admin_buf_t *ab);
int 		uds_recv(int sock, void *buf, int len, int flags);
int 		uds_send(int sock, void *buf, int len, int flags);

admin_buf_t *	pfs_adminbuf_create(int sock, int type, int op, int size);
void		pfs_adminbuf_destroy(admin_buf_t *ab, int error);
int		pfs_adminbuf_printf(admin_buf_t *ab, const char *fmt, ...);
pfs_printer_t *	pfs_adminbuf_printer(admin_buf_t *ab);
void * 		pfs_adminbuf_reserve(admin_buf_t *ab, int size);
void 		pfs_adminbuf_consume(admin_buf_t *ab, int size);


#endif /* _PFS_ADMIN_H_ */
