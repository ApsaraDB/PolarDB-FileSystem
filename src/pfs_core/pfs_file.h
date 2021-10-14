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

#ifndef _PFS_FILEOPS_H_
#define _PFS_FILEOPS_H_

#include <stdint.h>
#include <sys/queue.h>
#include <stddef.h>
#include <unistd.h>
#include <pthread.h>

#include "pfs_impl.h"
#include "pfs_tx.h"

typedef struct pfs_inode pfs_inode_t;
typedef struct nameinfo	nameinfo_t;

#define	OFFSET_FILE_POS		(-1)	/* offset is current file position */
#define	OFFSET_FILE_SIZE	(-2)	/* offset is file size */

extern int64_t file_shrink_size;

/*
 * I: file lock f_rwlock
 */
typedef struct pfs_file {
	pthread_rwlock_t f_rwlock;	/* (I) */
	int		f_fd;		/* file description */
	int		f_mntid;
	int		f_flags;
	off_t		f_offset;	/* next expected read/write offset,
					   atomic add\sub */
	uint64_t	f_btime;
	pfs_inode_t	*f_inode;
	int32_t		f_refcnt;	/* readers and writers count, only
					   changed when holding fdtbl lock */
	int		f_type;
} pfs_file_t;

/* file lock flag when pfs_file_get */
#define	RDLOCK_FLAG	0x01	/* Result in file read lock */
#define	WRLOCK_FLAG	0x02	/* Result in file write lock */

#define	FILE_RDLOCK(file)	rwlock_rdlock(&(file)->f_rwlock)
#define	FILE_WRLOCK(file)	rwlock_wrlock(&(file)->f_rwlock)
#define	FILE_UNLOCK(file)	rwlock_unlock(&(file)->f_rwlock)

#define INNER_FILE_BTIME		0

#define FALLOC_PFSFL_FIXED_OFFSET	0x0100	/* lower bits defined in falloc.h */

pfs_file_t *
	pfs_file_get(int fd, int lockflag);
void	pfs_file_put(pfs_file_t *file);
int	pfs_file_open(pfs_mount_t *mnt, nameinfo_t *ni, int oflags, pfs_file_t **filep);
int 	pfs_file_open_impl(pfs_mount_t *mnt, pfs_ino_t ino, int flags,
	    pfs_file_t **filep, uint64_t btime);
int	pfs_file_close(pfs_file_t *file);
int	pfs_file_close_locked(pfs_file_t *file);
int	pfs_file_xstat(pfs_file_t *file, struct stat *st);
ssize_t	pfs_file_xpread(pfs_file_t *file, void *buf, size_t len, off_t offset);
ssize_t	pfs_file_xpwrite(pfs_file_t *file, const void *buf, size_t len,
	    off_t offset);
int	pfs_file_xftruncate(pfs_file_t *file, off_t len);
int	pfs_file_xfallocate(pfs_file_t *file, off_t offset, size_t len, int mode);
off_t	pfs_file_xlseek(pfs_file_t *file, off_t offset, int whence);
int	pfs_file_xmap(pfs_file_t *file, fmap_entry_t *fmapv, int count);
ssize_t	pfs_file_size(pfs_file_t *file, uint64_t btime);
ssize_t pfs_file_pread(pfs_file_t *file, void *buf, size_t len, off_t offset);
ssize_t pfs_file_pwrite(pfs_file_t *file, const void *buf, size_t len, off_t offset);
int	pfs_file_release(pfs_mount_t *mnt, pfs_ino_t ino, uint64_t btime);
int	pfs_file_xsetxattr(pfs_file_t *file, const char *name, const void *value, size_t size);

typedef	struct admin_buf	admin_buf_t;
int 	pfs_fdtbl_dump(admin_buf_t *ab);
void	pfs_fdtbl_init();

/*
 * Helper inline functions to calculate block id and offset.
 */
static inline pfs_blkid_t
fblkid(off_t off, size_t blksize)
{
	PFS_ASSERT((blksize & (blksize -1)) == 0); /* power of 2 */
	PFS_ASSERT(off >= 0);
	return (pfs_blkid_t)(off / blksize);
}

static inline off_t
fblkoff(off_t off, size_t blksize)
{
	PFS_ASSERT((blksize & (blksize -1)) == 0); /* power of 2 */
	PFS_ASSERT(off >= 0);
	return (off_t)(off & (blksize - 1));
}

#endif
