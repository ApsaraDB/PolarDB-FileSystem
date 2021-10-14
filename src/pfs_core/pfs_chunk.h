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

#ifndef	_PFS_CHUNK_H_
#define	_PFS_CHUNK_H_

#include "pfs_api.h"
#include "pfs_impl.h"

typedef struct pfs_chunkstream_desc {
	uint32_t	csd_nchunk;	/* formatted chunk number of PBD */
	char		csd_pbdname[PFS_MAX_PBDLEN];
	char 		csd_cluster[PFS_MAX_CLUSTERLEN];
	int		csd_ioch_desc;
	int		csd_meta_fd;
	int		csd_flags;
	uint64_t	csd_pfs_run_ver;
} pfs_chunkstream_desc_t;

typedef struct pfs_chunkstream {
	pfs_chunkstream_desc_t	*cs_desc;
	int 			cs_ckid;
	uint64_t		cs_time_us;
} pfs_chunkstream_t;

extern "C" {
pfs_chunkstream_desc_t *
	pfs_chunkstream_init(const char *cluster, const char *pbdname, int flags); 
pfs_chunkstream_t *
	pfs_chunkstream_open(const pfs_chunkstream_desc_t *desc, int chunkid);
int64_t	pfs_chunkstream_read(pfs_chunkstream_t *stream, char *buf, size_t len);
int64_t	pfs_chunkstream_write(pfs_chunkstream_t *stream, const char *buf,
	    size_t len);
int	pfs_chunkstream_close(pfs_chunkstream_t *stream);
int	pfs_chunkstream_fini(pfs_chunkstream_desc_t *desc); 
int	pfs_chunkstream_eof(pfs_chunkstream_t *stream);
void	pfs_chunkstream_get_nchunk(const pfs_chunkstream_desc_t *desc, 
	    int *nchunk);
}


int	pfs_chunk_backup_init(pfs_chunkstream_desc_t *desc);
int	pfs_chunk_restore_init(pfs_chunkstream_desc_t *desc); 
pfs_chunkstream_t *
	pfs_chunk_readstream_open(const pfs_chunkstream_desc_t *desc,
	    int chunkid);
pfs_chunkstream_t *
	pfs_chunk_writestream_open(const pfs_chunkstream_desc_t *desc,
	    int chunkid);
int64_t	pfs_chunk_readstream(pfs_chunkstream_t *cs, char *buf, size_t len);
int64_t pfs_chunk_writestream(pfs_chunkstream_t *cs, const char *buf, size_t len);
void	pfs_chunk_readstream_close(pfs_chunkstream_t *cs);
void	pfs_chunk_writesteam_close(pfs_chunkstream_t *cs);
void	pfs_chunk_fini(pfs_chunkstream_desc_t *desc);
int	pfs_chunk_readstream_isfinish(pfs_chunkstream_t *cs);
int	pfs_chunk_writestream_isfinish(pfs_chunkstream_t *cs);


#endif
