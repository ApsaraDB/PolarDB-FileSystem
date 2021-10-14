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

#ifndef _PFSD_PROTO_H_
#define _PFSD_PROTO_H_

#include <semaphore.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stddef.h>

#include "pfs_impl.h"

enum {
	PFSD_REQUEST_MOUNT = 0, /* Deprecated */
	PFSD_REQUEST_OPEN,
	PFSD_REQUEST_READ,
	PFSD_REQUEST_WRITE,
	PFSD_REQUEST_FTRUNCATE,
	PFSD_REQUEST_TRUNCATE,
	PFSD_REQUEST_UNLINK,
	PFSD_REQUEST_FSTAT,
	PFSD_REQUEST_STAT,
	PFSD_REQUEST_FALLOCATE,
	PFSD_REQUEST_CHDIR,
	PFSD_REQUEST_MKDIR,
	PFSD_REQUEST_RMDIR,
	PFSD_REQUEST_OPENDIR,
	PFSD_REQUEST_READDIR,
	PFSD_REQUEST_ACCESS,
	PFSD_REQUEST_RENAME,
	PFSD_REQUEST_LSEEK,
	PFSD_REQUEST_GROWFS,

	PFSD_RESPONSE_MOUNT = 1000, /* Deprecated */
	PFSD_RESPONSE_OPEN,
	PFSD_RESPONSE_READ,
	PFSD_RESPONSE_WRITE,
	PFSD_RESPONSE_FTRUNCATE,
	PFSD_RESPONSE_TRUNCATE,
	PFSD_RESPONSE_UNLINK,
	PFSD_RESPONSE_FSTAT,
	PFSD_RESPONSE_STAT,
	PFSD_RESPONSE_FALLOCATE,
	PFSD_RESPONSE_CHDIR,
	PFSD_RESPONSE_MKDIR,
	PFSD_RESPONSE_RMDIR,
	PFSD_RESPONSE_OPENDIR,
	PFSD_RESPONSE_READDIR,
	PFSD_RESPONSE_ACCESS,
	PFSD_RESPONSE_RENAME,
	PFSD_RESPONSE_LSEEK,
	PFSD_RESPONSE_GROWFS,
};

inline
const char* pfsd_req_type_string(int type)
{
#define ENUM_TYPE_STR(type) \
		case type: \
			return #type;

	switch (type) {
		ENUM_TYPE_STR(PFSD_REQUEST_MOUNT)
		ENUM_TYPE_STR(PFSD_REQUEST_OPEN)
		ENUM_TYPE_STR(PFSD_REQUEST_READ)
		ENUM_TYPE_STR(PFSD_REQUEST_WRITE)
		ENUM_TYPE_STR(PFSD_REQUEST_FTRUNCATE)
		ENUM_TYPE_STR(PFSD_REQUEST_TRUNCATE)
		ENUM_TYPE_STR(PFSD_REQUEST_UNLINK)
		ENUM_TYPE_STR(PFSD_REQUEST_FSTAT)
		ENUM_TYPE_STR(PFSD_REQUEST_STAT)
		ENUM_TYPE_STR(PFSD_REQUEST_FALLOCATE)
		ENUM_TYPE_STR(PFSD_REQUEST_CHDIR)
		ENUM_TYPE_STR(PFSD_REQUEST_MKDIR)
		ENUM_TYPE_STR(PFSD_REQUEST_RMDIR)
		ENUM_TYPE_STR(PFSD_REQUEST_OPENDIR)
		ENUM_TYPE_STR(PFSD_REQUEST_READDIR)
		ENUM_TYPE_STR(PFSD_REQUEST_ACCESS)
		ENUM_TYPE_STR(PFSD_REQUEST_RENAME)
		ENUM_TYPE_STR(PFSD_REQUEST_LSEEK)
	}

	return "Unknow request";
}

typedef enum pfsd_req_shm_state {
	/**
	 * Init state
	 */
	REQ_FREE = 0,

	/**
	 * Now filling request
	 */
	REQ_ALLOC,

	/**
	 * Request filling finished. Now it is waiting reply filling.
	 */
	REQ_WAIT_REPLY,

	/**
	 * Request is processing now.
	 */
	REQ_IN_PROGRESS,

	/**
	 * Reply filling finished. Now it is waiting channel released
	 */
	REQ_WAIT_RELEASE,

	/**
	 * The requester will not need the reply. Replier can set it to CHNL_FREE
	 */
	REQ_ZOMBIE,

	/**
	 * The replier can not generate reply due to restart. requester can set it
	 * to CHNL_FREE.
	 */
} pfsd_req_shm_state_t;

inline
const char* pfsd_req_state_string(int8_t state)
{
	switch (state) {
		case REQ_FREE:
			return "REQ_FREE";

		case REQ_ALLOC:
			return "REQ_ALLOC";

		case REQ_WAIT_REPLY:
			return "REQ_WAIT_REPLY";

		case REQ_IN_PROGRESS:
			return "REQ_IN_PROGRESS";

		case REQ_WAIT_RELEASE:
			return "REQ_WAIT_RELEASE";

		default:
			break;
	}

	return "UNKNOWN REQ_STATE";
}

typedef struct pfsd_chnl_payload_common {
	uint64_t pl_btime;
	int32_t  pl_file_type;
	int32_t  pl_padding;
} pfsd_chnl_payload_common_t;

#define REQUEST_HEADER_PADDING (256)

#define PFSD_REQUEST_INFO \
union { \
	volatile int64_t val __attribute__ ((aligned(64))); \
	struct { \
		int16_t connid; \
		int8_t state; \
		uint8_t _header_padding; \
		int32_t owner; \
	}; \
}

typedef PFSD_REQUEST_INFO pfsd_request_info_t;

#define COMMON_REQUEST_HEADER \
	union { \
		struct { \
			PFSD_REQUEST_INFO; \
			int mntid; /* mnt index in pfsd */ \
			int type; \
			pfsd_chnl_payload_common_t common_pl_req; \
		};\
		char _request_header_padding[REQUEST_HEADER_PADDING]; \
	};

#define RESPONSE_HEADER_PADDING (128)

#define COMMON_RESPONSE_HEADER \
	union { \
		struct{ \
			int type; \
			int error; /* errno */ \
			pfsd_chnl_payload_common_t common_pl_rsp; \
		}; \
		char _response_header_padding[RESPONSE_HEADER_PADDING]; \
	};

#define REQUEST_ALIGN (1024)
/* For reserved */
typedef struct {
	char padding[REQUEST_ALIGN];
} pfsd_request_holder_t;

#define RESPONSE_ALIGN (512)
/* For reserved */
typedef struct {
	char padding[RESPONSE_ALIGN];
} pfsd_response_holder_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	char g_pbd[PFS_MAX_PBDLEN];
} growfs_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int err;
} growfs_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	int o_flags;
	mode_t o_mode;
} open_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int64_t o_ino;
	off_t o_off;
} open_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	int64_t r_ino;
	size_t r_len;
	off_t r_off;
} read_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int64_t r_ino;
	ssize_t r_len;
} read_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	int64_t w_ino;
	off_t w_off;
	size_t w_len;
	int w_flags;
} write_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int64_t w_ino;
	ssize_t w_len;
	ssize_t w_file_size;
} write_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	int64_t f_ino;
	off_t f_off;
	ssize_t f_len;
	int f_mode;
} fallocate_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int64_t f_ino;
	int f_res;
} fallocate_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	off_t t_len;
} truncate_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int t_res;
} truncate_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	int64_t f_ino;
	off_t f_len;
} ftruncate_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int f_res;
} ftruncate_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

} unlink_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int u_res;
} unlink_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

} stat_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	struct stat s_st;
	int s_res;
} stat_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	int64_t f_ino;
} fstat_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	struct stat f_st;
	int f_res;
} fstat_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;
} chdir_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int c_res;
} chdir_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	mode_t m_mode;
} mkdir_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int m_res;
} mkdir_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

} rmdir_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int r_res;
} rmdir_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	mode_t a_mode;
} access_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int a_res;
} access_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

} rename_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int r_res;
} rename_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	int64_t l_ino;
	off_t l_offset;
	int l_whence;
} lseek_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	off_t l_offset;
} lseek_response_t;


/* For dirent buffer */
#define PFSD_DIRENT_BUFFER_SIZE (20 * 1024UL)

typedef struct __dirstream {
	struct dirent d_sysde; /* should be the first member, depended on by pfs_readidr */
	int64_t d_ino;	  /* dir ino */

	uint64_t d_next_offset;
	int64_t d_next_ino;

	/* For dirent buffer */
	uint64_t d_data_offset;
	uint64_t d_data_size;
	char d_data[PFSD_DIRENT_BUFFER_SIZE];
} DIR;

typedef struct {
	COMMON_REQUEST_HEADER;

} opendir_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int o_res;
	int64_t o_dino;
	int64_t o_first_ino;
} opendir_response_t;

typedef struct {
	COMMON_REQUEST_HEADER;

	int64_t r_dino;
	int64_t r_ino;
	uint64_t r_offset;
} readdir_request_t;

typedef struct {
	COMMON_RESPONSE_HEADER;

	int r_res;
	int64_t r_ino;
	uint64_t r_offset;
	uint64_t r_data_size;
} readdir_response_t;

typedef struct pfsd_request {
	uint32_t shm_epoch;
	union {
		/* for convenience, same as COMMON_REQUEST_HEADER */
		struct {
			COMMON_REQUEST_HEADER;
		};

		growfs_request_t g_req;
		open_request_t o_req;
		read_request_t r_req;
		write_request_t w_req;
		ftruncate_request_t ft_req;
		truncate_request_t t_req;
		unlink_request_t un_req;
		fstat_request_t f_req;
		stat_request_t s_req;
		fallocate_request_t fa_req;
		chdir_request_t cd_req;
		mkdir_request_t mk_req;
		rmdir_request_t rm_req;
		opendir_request_t od_req;
		readdir_request_t rd_req;
		rename_request_t re_req;
		lseek_request_t l_req;
		access_request_t a_req;

		pfsd_request_holder_t holder;
	};
} pfsd_request_t;

inline int64_t pfsd_request_set_connid(int64_t val, int16_t connid) {
	((pfsd_request_info_t*)(&val))->connid = connid;
	return val;
}

inline int64_t pfsd_request_set_state(int64_t val, int8_t state) {
	((pfsd_request_info_t*)(&val))->state = state;
	return val;
}

inline int64_t pfsd_request_set_pid(int64_t val, int32_t pid) {
	((pfsd_request_info_t*)(&val))->owner = pid;
	return val;
}

inline int8_t pfsd_request_get_state(int64_t val) {
	return ((pfsd_request_info_t*)(&val))->state;
}

/* compile sanity check */
typedef char _check_request_[(sizeof(pfsd_request_t) <= 
    offsetof(pfsd_request_t, holder) + sizeof(pfsd_request_holder_t)) ? 1 : -1];

inline int pfsd_request_type(const pfsd_request_t* req) {
	return req->g_req.type;
}

typedef struct {
	sem_t r_sem;
	union {
		/* for convenience, same as COMMON_RESPONSE_HEADER */
		struct {
			COMMON_RESPONSE_HEADER
		};

		growfs_response_t g_rsp;
		open_response_t o_rsp;
		read_response_t r_rsp;
		write_response_t w_rsp;
		ftruncate_response_t ft_rsp;
		truncate_response_t t_rsp;
		unlink_response_t un_rsp;
		fstat_response_t f_rsp;
		stat_response_t s_rsp;
		fallocate_response_t fa_rsp;
		chdir_response_t cd_rsp;
		mkdir_response_t mk_rsp;
		rmdir_response_t rm_rsp;
		opendir_response_t od_rsp;
		readdir_response_t rd_rsp;
		rename_response_t re_rsp;
		lseek_response_t l_rsp;
		access_response_t a_rsp;

		pfsd_response_holder_t holder;
	};
} pfsd_response_t;

/* compile sanity check */
typedef char _check_response_[(sizeof(pfsd_response_t) <= 
    offsetof(pfsd_response_t, holder) + sizeof(pfsd_response_holder_t)) ? 1 : -1];


inline void pfsd_request_print(const pfsd_request_t* r, unsigned char* buf)
{
	fprintf(stdout, "\tReq owner %d type %s state %s connid %d epoch %u\n",
					r->owner,
					pfsd_req_type_string(r->type),
					pfsd_req_state_string(r->state),
					(int)r->connid,
					r->shm_epoch);

	switch (r->type) {
		case PFSD_REQUEST_OPEN:
			fprintf(stdout, "\t\t[o_flags %d, file %s]\n",
							r->o_req.o_flags, buf);
			break;

		case PFSD_REQUEST_READ:
			fprintf(stdout, "\t\t[r_ino %ld, off_t %lu,r_len %ld]\n",
							r->r_req.r_ino,
							r->r_req.r_off,
							r->r_req.r_len);
			break;

		case PFSD_REQUEST_WRITE:
			fprintf(stdout, "\t\t[w_ino %ld,off_t %lu,w_len %ld,w_flags %d]\n",
							r->w_req.w_ino,
							r->w_req.w_off,
							r->w_req.w_len,
							r->w_req.w_flags);
			break;

		case PFSD_REQUEST_FTRUNCATE:
			fprintf(stdout, "\t\t[f_ino %ld, f_len %lu]\n",
							r->ft_req.f_ino,
							r->ft_req.f_len);
			break;

		case PFSD_REQUEST_TRUNCATE:
			fprintf(stdout, "\t\t[t_len %lu, file %s]\n",
							r->t_req.t_len, buf);
			break;

		case PFSD_REQUEST_UNLINK:
			fprintf(stdout, "\t\t[file %s]\n", buf);
			break;

		case PFSD_REQUEST_FSTAT:
			fprintf(stdout, "\t\t[f_ino %ld]\n", r->f_req.f_ino);
			break;

		case PFSD_REQUEST_STAT:
			fprintf(stdout, "\t\t[file %s]\n", buf);
			break;

		case PFSD_REQUEST_FALLOCATE:
			fprintf(stdout, "\t\t[f_ino %ld, f_off %lu, f_len %ld, f_mode %d]\n",
							r->fa_req.f_ino,
							r->fa_req.f_off,
							r->fa_req.f_len,
							r->fa_req.f_mode);
			break;

		case PFSD_REQUEST_CHDIR:
		case PFSD_REQUEST_MKDIR:
		case PFSD_REQUEST_RMDIR:
		case PFSD_REQUEST_ACCESS:
		case PFSD_REQUEST_OPENDIR:
			fprintf(stdout, "\t\t[file %s]\n", buf);
			break;

		case PFSD_REQUEST_READDIR:
			fprintf(stdout, "\t\t[r_dino %ld, r_ino %ld, r_off %lu]\n",
							r->rd_req.r_dino,
							r->rd_req.r_ino,
							r->rd_req.r_offset);
			break;

		case PFSD_REQUEST_RENAME:
			fprintf(stdout, "\t\t[file1 %s, file2 %s]\n", buf, buf + PFS_MAX_PATHLEN);
			break;

		case PFSD_REQUEST_LSEEK:
			fprintf(stdout, "\t\t[l_ino %ld, l_off %lu, l_whence %d]\n",
							r->l_req.l_ino,
							r->l_req.l_offset,
							r->l_req.l_whence);
			break;

		default:
			fprintf(stdout, "\t\t[UNKNOW REQUEST TYPE]\n");
			break;
	}
}

#endif

