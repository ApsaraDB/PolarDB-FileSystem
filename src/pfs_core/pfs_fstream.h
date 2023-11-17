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

#ifndef	_PFS_FSTREAM_H_
#define	_PFS_FSTREAM_H_

#include <sys/types.h>
#include <stdint.h>

typedef struct pfs_mount	pfs_mount_t;

typedef struct pfs_fstrm {
	int		f_fileno;
	int		f_flags;

	pthread_mutex_t	f_mtx;
	struct pfs_fstrm *f_next;

	int		f_rw;		/* currently reading or writing */
	char		*f_base;
	size_t		f_bufsz;
	char		*f_cur;
	char		*f_end;		/* end of valid data */
} pfs_fstrm_t;

int	pfs_fstrm_open(const char *pbdpath, const char *mode,
	    pfs_fstrm_t **fpp);
int	pfs_fstrm_xclose(pfs_fstrm_t *fp);
int	pfs_fstrm_xread(pfs_fstrm_t *fp, void *buf, size_t size, size_t nmemb,
	    size_t *nitem);
int	pfs_fstrm_xwrite(pfs_fstrm_t *fp, const void *buf, size_t size, size_t nmemb,
	    size_t *nitem);
int	pfs_fstrm_xflush(pfs_fstrm_t *fp);
off_t	pfs_fstrm_xseekoff(pfs_fstrm_t *fp, off_t offset, int whence, bool reseterr, bool reseteof);
int	pfs_fstrm_xfileno(pfs_fstrm_t *fp, int *fileno);
int	pfs_fstrm_xeof(pfs_fstrm_t *fp, bool *iseof);
int	pfs_fstrm_xerror(pfs_fstrm_t *fp, bool *haserr);
int	pfs_fstrm_xclearerr(pfs_fstrm_t *fp);

#endif
