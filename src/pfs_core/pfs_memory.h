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

#ifndef	_PFS_MEMORY_H_
#define	_PFS_MEMORY_H_

enum {
	M_NONE = 0,
	M_SECTOR,
	M_FRAG,
	M_TX,
	M_TXOP,
	M_TXCB,
	M_REQWAIT,
	M_DBLKV,
	M_CHUNKV,
	M_CHDESC,
	M_TLS,
	M_INODE,
	M_DIR,
	M_FILE,
	M_FILEHOLE,
	M_CHUNK,
	M_MOUNT,
	M_OBJBUFV,
	M_METASET,
	M_ANODEV,
	M_PAXOS_SECTOR,
	M_ADMINFO,
	M_ADMBUF,
	M_CMDINFO,
	M_SECTHDR,
	M_SECTBUF,
	M_OIDV,
	M_IO_TMPBUF,
	M_ZERO_BUF,
	M_DEV_IO,
	M_POLAR_DEV,
	M_POLAR_IOQ,
	M_PANGU_DEV,
	M_PANGU_IOQ,
	M_PANGU_TASK,
	M_DISK_DEV,
	M_DISK_IOQ,
	M_DISK_DIOBUF,
	M_DENO_VECT,
	M_CHUNK_META,
	M_CHUNK_READSTREAM,
	M_CHUNK_WRITESTREAM,
	M_CHUNK_METABUF,
	M_CHUNK_CRCBUF,
	M_CHUNK_BLOCKUSED,
	M_NAMECACHE,
	M_OIDV_HOLEOFF,
	M_DXENT,
	M_INSTK_VEC,
	M_CONFIG,
	M_CONFIG_SECT,
	M_CONFIG_KV,
	M_FDTBL_PTR,
	M_INODE_BLK_TABLE,

	M_NTYPE
};

typedef struct admin_buf admin_buf_t;

void * 	pfs_mem_malloc(size_t size, int type);
void 	pfs_mem_free(void *ptr, int type);
void * 	pfs_mem_realloc(void *ptr, size_t newsize, int type);
int 	pfs_mem_memalign(void **pp, size_t alignment, size_t size, int type);
int	pfs_mem_stat(admin_buf_t *dbuf);

#endif	/* _PFS_MEMORY_H_ */
