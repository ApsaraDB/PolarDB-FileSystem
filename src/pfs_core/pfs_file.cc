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

#include <sys/param.h>
#include <sys/stat.h>
#include <linux/falloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "pfs_admin.h"
#include "pfs_impl.h"
#include "pfs_dir.h"
#include "pfs_file.h"
#include "pfs_mount.h"
#include "pfs_inode.h"
#include "pfs_blkio.h"
#include "pfs_version.h"
#include "pfs_stat.h"

/*-
 * FILE IO
 * -------
 *
 * File is to manage data on PBD. The management info is called meta
 * data. For any data IO operation that may modify meta data, a tx is
 * used to collect modify operations and is then submitted to the log
 * thread for logging. Tx logging may conflict with other tx from
 * other hosts, in that case it is failed. Only if the tx logging is
 * succeeded then actual data IO is allowed. All PFS instances must
 * follow this rule, and this rule keeps the integrity and consistency
 * of meta data among multiple host environment. Note that data
 * consistency is left to the upper layer. PFS can't keep instances on
 * different hosts from writing to the same already allocated blocks.
 *
 * As an example, let's look at the case of writing new data into a
 * file on host A. First, new data blocks for the writing are
 * allocated and recorded in a tx X1 and then X1 is submitted to the
 * log thread. The logging of X1 succeeds if there is no tx from other
 * hosts. After X1 is logged, the data write begins. If later a new
 * similar write tx X2 on host B is submitted. Its log thread finds
 * the new block allocation of X1, and the X1 is recreated and
 * replayed on host B. X2 will abort and start a brand new allocation
 * again. After X2 is submitted for logging and succeeds, the data
 * write can then begin.
 *
 * Besides data IO, there are two additional problems to be considered
 * at the file level: file/inode reference counting and locking order
 * of file, inode and meta data.
 *
 * REFERENCE COUNT
 * ---------------
 *
 * We have to reference count file and inode, because an inode can be
 * refered by more than one file and a file can be refered by more
 * than one fd, as depicted below. Reference counting is the common
 * technique to safely destroy an object refered by more than one
 * users.
 *
 * The reference count of a file or an inode is protected by the lock
 * of its set, fd table and mount inode list respectively. Whileas an
 * individual element may come and go, the set is always existent and
 * so is its protecting lock. An always existent set lock make it
 * easier to reference count an object.
 *
 *  thr1     thr2       thr3             thr4
 *   |         |          |               |
 *  fd1       fd1        fd2             fd3        <= file level: fd,
 *    \        /          |               |            file and inode
 *      file 1          file 2          file 3
 *        \                /              |
 *         \              /               V
 *          -> inode 1  <-              inode2
 *               |                        |
 *               V                        V
 *          phy inode 1                phy inode 2  <= meta data level
 *
 * LOCKING ORDER
 * -------------
 *
 * The other problem is locking order. We abide with the locking order
 * below:
 *      ->  lock fdtbl, increment file refcnt, unlock fdtbl
 *      ->  lock file,
 *          enter tx
 *
 *          ->  lock inode,
 *          ->  LOCK meta data, and access/modify meta data in memroy
 *          <-  unlock inode
 *
 *          submit tx
 *          tx is waken up
 *          abort tx and uodo meta data if necessary
 *          <- UNLOCK meta data
 *
 *          run callback
 *          ->  lock inode
 *          <-  unlock inode
 *
 *      <-  unlock file,
 *      -> lock fdtbl, decrement file refcnt, unlock fdtbl
 *
 * The special point is that we hold the meta data lock until tx is
 * done, either successfully or failed. For read type tx, the hold is
 * short and that is not a problem, since read tx only accesses memory
 * and doesn't need IO. For write type tx, the lock is held for the
 * whole log IO and it is a long time. But we have to hold the lock
 * during IO, because logging tx may fail and in that case we need to
 * undo tx modification. If the meta lock is released while logging IO,
 * there is no way keep meta data integrity.
 *
 * During the meta data lock hold, inode lock is released, hoping to
 * run file level code of read type concurrently. For write type file
 * level code, they will block, either waiting for meta data lock or
 * waiting for inode block alloction/free. Note that after inode lock
 * release, we MUST not acquire the inode lock again; otherwise lock
 * loop may occur and deadlock may follow. To obey with this rule, we
 * atomically set the 'stale' field in inodes if we need to undo in
 * memory inode modification, when aborting or replaying a tx. The
 * file level code will check if the in memory inode is stale when
 * doing IO. If so, the inode will be reloaded, in the locking order:
 * file -> inode -> meta data.
 *
 * FILE HOLE
 * ---------------
 *
 * File hole is the non-written area in the range of file size and
 * data read from holes are expected zeroed. File's minimum allocated
 * unit is block, so there are two cases of file holes:
 * 1) unallocated block: current file block is never written, and no
 *    block are allocated.
 * 2) allocated and partial written block: block is allocated but only
 *    part of block is written.
 * libpfs can recognize case 1 through file's block map directly. But for
 * case 2 libpfs needs more detailed block information. Then block hole
 * is introduced to tell which part of current block is never written.
 * Its invariant is that it is always at the right of block.
 *
 * For example, when a block is allocated, its block hole is [0, 4M).
 * After writing some data into [0, 2M), block hole becomes [2M, 4M).
 * While the whole block is written, its block hole is [4M, 4M). If
 * someone writes data into [1M, 2M) after allocating a new block,
 * the range of [0, 1M) is filled with zero by libpfs itself.
 *
 */

#define MAX_NFD_LIMIT 2048000L
#define MAX_SHRINK_SIZE 10737418240L

static bool
pfs_check_ival_max_nfd(void *data)
{
	int64_t integer_val = *(int64_t*)data;
	if (integer_val <= 0 || integer_val >= MAX_NFD_LIMIT)
		return false;
	return true;
}

static bool
pfs_check_ival_shrink_size(void *data)
{
	int64_t integer_val = *(int64_t*)data;
	if (integer_val <= 0 || integer_val > MAX_SHRINK_SIZE)
		return false;
	return true;
}

/*
 * pbd base info option config
 * must init by restart
 */
static int64_t file_max_nfd = 204800;
PFS_OPTION_REG(file_max_nfd, pfs_check_ival_max_nfd);

static pfs_file_t	**fdtbl;
static int		fdtbl_nopen;
static int		fdtbl_free_last;
static int		pfs_max_nfd;
pthread_mutex_t		fdtbl_mtx;

int64_t file_shrink_size = (10L << 30);
PFS_OPTION_REG(file_shrink_size, pfs_check_ival_shrink_size);

/**
 * We create a forward linked list to save the closed fd.
 *
 * We tag the fdtbl[fd] is free by encoding fdtbl[fd] % 2 == 1, due to valid
 * file pointers are aligned to sizeof(void*) so their lowest bit must be
 * zero. And the rest bit of fdtbl[fd] is used to save the previous closed fd.
 *
 * We use the linked list as a stack: we push closed fd at its
 * head (stored in varilable "fdtbl_free_last") and pop free fd at the head
 * as well.
 *
 * So now free fd positions set in fdtble now is divided into two parts: one
 * part is at [x, file_max_nfd) with zero value stored in fdtble where x is the
 * largest never allocated fd; the other is a linked list storing all the
 * closed fd using "2y+1" encoding with its head position at fdtbl_free_last.
 *
 * A fdtbl elements values example after some open/close operations:
 *
 * |file*|file*|4*2+1|file_max_nfd*2+1|3*2+1|file*|0|0|0|.........|0|
 *              ^                                                  ^
 *              |                                                  |
 *       fdtbl_free_last                                     file_max_nfd
 *
 * We alloc 6 fds first. The values change order is:
 * 1. fdtbl[0] = file*
 * 2. fdtbl[1] = file*
 * 3. fdtbl[2] = file*
 * 4. fdtbl[3] = file*
 * 5. fdtbl[4] = file*
 * 6. fdtbl[5] = file*
 *
 * Now we close fd 3, 4, 2. The values change order is:
 * 1. fdtbl[3] = fdtbl_free_last * 2 + 1 = 2*file_max_nfd+1
 *    fdtbl_free_last = 3, --fdtbl_nopen
 * 2. fdtbl[4] = fdtbl_free_last * 2 + 1 = 7 fdtbl_free_last = 4, --fdtbl_nopen
 * 3. fdtbl[2] = fdtbl_free_last * 2 + 1 = 9 fdtbl_free_last = 2, --fdtbl_nopen
 */

static inline void
fd_set_init()
{
	PFS_ASSERT((fdtbl_free_last == 0) && (pfs_max_nfd == 0));
	/* max nfd must exactly control by config */
	pfs_max_nfd = file_max_nfd;
	fdtbl_free_last = pfs_max_nfd;
	fdtbl = (pfs_file_t**)pfs_mem_malloc(pfs_max_nfd * sizeof(pfs_file_t*), M_FDTBL_PTR);
	PFS_VERIFY(fdtbl != NULL);
}

static inline int
fd_get(pfs_file_t *file)
{
	int fd = -1;
	if (fdtbl == NULL)
		fd_set_init();

	if (fdtbl_free_last == pfs_max_nfd) {
		if (fdtbl_nopen < pfs_max_nfd) {
			/*
			 * Pop from array
			 */
			fd = fdtbl_nopen;
			++fdtbl_nopen;
			fdtbl[fd] = file;
		}
	} else {
		/*
		 * Pop from the linked list with its head position at
		 * fdtbl_free_last.
		 *
		 * After the last element is popped, then
		 * fdtbl_free_last == pfs_max_nfd.
		 */
		fd = fdtbl_free_last;
		fdtbl_free_last = (int)(((intptr_t)fdtbl[fdtbl_free_last]) / 2);
		++fdtbl_nopen;
		fdtbl[fd] = file;
	}
	return fd;
}

static inline void
fd_put(int fd)
{
	PFS_ASSERT(fdtbl != NULL);
	/*
	 * Push into the linked list with its head position changed to
	 * the input fd.
	 */
	fdtbl[fd] = (pfs_file_t*)(intptr_t)(fdtbl_free_last * 2 + 1);
	fdtbl_free_last = fd;
	--fdtbl_nopen;
}

static inline pfs_file_t*
fd_to_file(int fd)
{
	PFS_ASSERT(fdtbl != NULL);
	if (((intptr_t)fdtbl[fd]) % 2 == 1)
		return NULL;
	return fdtbl[fd];
}

static int
fd_alloc(pfs_file_t *file)
{
	int fd = -1;
	mutex_lock(&fdtbl_mtx);
	fd = fd_get(file);
	//We guarantee fd and file is consistent after releasing fdtbl_mtx.
	file->f_fd = fd;
	mutex_unlock(&fdtbl_mtx);
	return fd;
}

static void
pfs_file_destroy(pfs_file_t *file)
{
	if (file->f_inode) {
		pfs_inode_put(file->f_inode);
		file->f_inode = NULL;
	}

	rwlock_destroy(&file->f_rwlock);
	pfs_mem_free(file, M_FILE);
}

static int
fd_free(pfs_file_t *file, bool file_is_locked)
{
	int fd = file->f_fd;
	bool need_free = false;

	/*
	 * File refcnt can only change when holding fdtbl lock.
	 */
	mutex_lock(&fdtbl_mtx);
	PFS_ASSERT(fdtbl != NULL);
	PFS_ASSERT(0 <= fd && fd < pfs_max_nfd);
	PFS_ASSERT(fdtbl[fd] == file);
	if (fdtbl[fd]->f_refcnt <= 1) {
		fd_put(fd);
		need_free = true;
	}
	mutex_unlock(&fdtbl_mtx);

	if (need_free) {
		if (file_is_locked)
			FILE_UNLOCK(file);
		pfs_file_destroy(file);
		return 0;
	}
	ERR_RETVAL(EAGAIN);
}

pfs_file_t *
pfs_file_get(int fd, int lockflag)
{
	pfs_file_t *file = NULL;

	mutex_lock(&fdtbl_mtx);
	if (0 <= fd && fd < pfs_max_nfd)
		file = fd_to_file(fd);
	if (file)
		file->f_refcnt++;
	mutex_unlock(&fdtbl_mtx);

	if (file) {
		pfs_mntstat_set_file_type(file->f_type);
		if (lockflag == WRLOCK_FLAG)
			FILE_WRLOCK(file);
		else
			FILE_RDLOCK(file);
	}
	return file;
}

void
pfs_file_put(pfs_file_t *file)
{
	if (file == NULL)
		return;	/* the file may have been destroyed */

	FILE_UNLOCK(file);

	mutex_lock(&fdtbl_mtx);
	file->f_refcnt--;
	mutex_unlock(&fdtbl_mtx);
}

static ssize_t
pfs_file_truncate(pfs_inode_t *in, off_t len, uint64_t btime)
{
	pfs_mount_t	*mnt = in->in_mnt;
	uint64_t	blksize = mnt->mnt_blksize;
	int64_t		shrinksize = file_shrink_size;	/* file_shrink_size isn't thread-safe */
	ssize_t		fsize;
	pfs_blkid_t	lastblkid;
	int		err;
	pfs_blkno_t	dblkno;
	off_t		blkoff, dbhoff;

	err = pfs_inode_sync_first(in, PFS_INODET_FILE, btime, false);
	if (err < 0)
		return err;

	fsize = pfs_inode_size(in);
	/*
	 * If truncated size is larger than 'file_shrink_size',
	 * then shrink file size by 'file_shrink_size'.
	 * The caller will retry until file size is equal
	 * to len.
	 */
	if (shrinksize > 0 && fsize - len > shrinksize)
		len = fsize - shrinksize;

	if (len == 0) {
		/*
		 * There is no valid offset and thus block id for the
		 * the range [0, len). Contrive the last block id as -1,
		 * so that lastblkid + 1 can still be valid.
		 */
		lastblkid = -1;
	} else {
		lastblkid = fblkid((off_t)len - 1, blksize);
		pfs_inode_map(in, lastblkid, &dblkno, &dbhoff);
		if (dblkno > 0 && len < fsize) {
			blkoff = fblkoff((off_t)len, blksize);
			/*
			 * Check if dblk hole offset can be slided to
			 * the left side. If len is block aligned, that
			 * is blkoff == 0, its block id is different
			 * from lastblkid and the hole for lastblkid's
			 * dblk needs no expansion.
			 *
			 * Here we do not change the hole of blocks within the
			 * file size
			 */
			if (blkoff > 0 && blkoff < dbhoff &&
			    pfs_version_has_features(mnt, PFS_FEATURE_BLKHOLE)) {
				err = pfs_inode_phy_check(in);
				if (err < 0)
					return err;
				pfs_inode_expand_dblk_hole(in, lastblkid,
				    blkoff, blksize - blkoff);
			}
		}
	}
	/*
	 * Delete blocks within the range of [lastblkid+1, ~).
	 * It is OK to have a dry run of pfs_inode_del_from().
	 */
	/*
	 * FIXME: At this time, mem-inode is dirty. If del_from() failed and
	 * return, phyin may not been recorded in tx, thus unable to invalidate
	 * inode. However, the current implementation eliminates the possibility.
	 */
	err = pfs_inode_del_from(in, lastblkid + 1);
	if (err < 0)
		return err;
	if (len != fsize) {
		err = pfs_inode_change(in, len - fsize, false);
		if (err < 0)
			return err;
	}
	return len;
}

int
pfs_file_open_impl(pfs_mount_t *mnt, pfs_ino_t ino, int flags,
    pfs_file_t **filep, uint64_t btime)
{
	int		fd, err;
	pfs_file_t	*file = NULL;
	pfs_inode_t	*in = NULL;

	fd = -1;	/* initialize for error out */
	file = NULL;
	in = NULL;

	file = (pfs_file_t *)pfs_mem_malloc(sizeof(pfs_file_t), M_FILE);
	if (file == NULL)
		ERR_RETVAL(ENOMEM);
	memset(file, 0, sizeof(*file));
	rwlock_init(&file->f_rwlock, NULL);
	file->f_refcnt = 0;
	file->f_offset = 0;
	file->f_btime = btime;
	file->f_flags = flags;

	/*
	 * If file is already opened, file->f_inode will point to that mem inode.
	 * Otherwise, create a new one.
	 */
	in = pfs_inode_get(mnt, ino);
	if (in == NULL)
		ERR_GOTO(ENOMEM, out);
	pfs_inode_lock(in);
	err = pfs_inode_sync_first(in, PFS_INODET_NONE, file->f_btime, false);
	pfs_inode_unlock(in);
	if (err < 0)
		goto out;
	file->f_inode = in;
	file->f_mntid = mnt->mnt_id;

	fd = fd_alloc(file);
	if (fd < 0)
		ERR_GOTO(EMFILE, out);

	if (filep) {
		*filep = file;
		if (ino == JOURNAL_FILE_MONO)
			file->f_type = FILE_PFS_JOUNAL;
		else if (ino == PAXOS_FILE_MONO)
			file->f_type = FILE_PFS_PAXOS;
	}

	return fd;

out:
	if (in) {
		pfs_inode_put(in);
		in = NULL;
	}
	if (file) {
		rwlock_destroy(&file->f_rwlock);
		pfs_mem_free(file, M_FILE);
		file = NULL;
	}
	return err;
}

int
pfs_file_open(pfs_mount_t *mnt, nameinfo_t *ni, int oflags, pfs_file_t **filep)
{
	int err;
	int file_type;
	MNT_STAT_BEGIN();
	file_type = pfs_get_file_type(ni->ni_path);
	pfs_mntstat_set_file_type(file_type);
	*filep = NULL;
	err = pfs_memdir_xlookup(mnt, ni, oflags);
#define FFLAGMASK        (O_APPEND)
	if (err < 0)
		goto out;
	err = pfs_file_open_impl(mnt, ni->ni_ino, oflags & FFLAGMASK,
	    filep, ni->ni_btime);
	if (*filep)
		(*filep)->f_type = file_type;

out:
	if (oflags & O_CREAT)
		MNT_STAT_END(MNT_STAT_FILE_OPEN_CREAT);
	else
		MNT_STAT_END(MNT_STAT_FILE_OPEN);
	return err;
}

static ssize_t
pfs_file_read(pfs_inode_t *in, void *buf, size_t len, off_t offset,
    bool locked, uint64_t btime)
{
	char		*data = (char *)buf;
	pfs_mount_t	*mnt = in->in_mnt;
	uint64_t	blksize = mnt->mnt_blksize;
	ssize_t		rlen, rsum, left;
	pfs_blkno_t	dblkno;
	pfs_blkid_t	blkid;
	off_t		blkoff, dbhoff;	/* dblk hole offset */
	size_t		fsize;
	int 		err;

	if (locked) {
		err = pfs_inode_sync_first(in, PFS_INODET_FILE, btime, false);
		if (err < 0)
			return err;
	}

	fsize = pfs_inode_size(in);
	/* Can't exceed file size */
	if (offset >= (off_t)fsize)
		len = 0;
	else if ((ssize_t)(offset + len) >= (ssize_t)fsize)
		len = fsize - offset;

	for (rsum = 0; rsum < (ssize_t)len; rsum += rlen, offset += rlen) {
		left = len - rsum;
		blkid = fblkid(offset, blksize);
		blkoff = fblkoff(offset, blksize);

		pfs_inode_map(in, blkid, &dblkno, &dbhoff);
		if (dblkno == 0 && offset + left > pfs_inode_size(in)) {
			/*
			 * There is no mapping for the file block. Blocks
			 * within file size should be either a written data
			 * block or an unwritten hole block. But now an invalid
			 * block mapping is found. It may be that other threads
			 * have truncated the file. Interesting to see.
			 *
			 * We should re-check fsize after we re-lock inode.
			 */
			pfs_etrace("blkid %llu mapps to %lld\n in read",
			    blkid, dblkno);
			ERR_RETVAL(EAGAIN);
		}
		if (locked)
			pfs_inode_unlock(in);

		if (dbhoff <= blkoff) {
			/*
			 * Hit on a hole range. Note the invariant that the
			 * hole must extend to the end of the block. So the
			 * max hole length that can be read is blksize - blkoff.
			 */
			PFS_ASSERT(dblkno == 0 ||
			    pfs_version_has_features(mnt, PFS_FEATURE_BLKHOLE));
			rlen = MIN(blksize - blkoff, left);
			memset(data+rsum, 0, rlen);
		} else {
			rlen = MIN(MIN(dbhoff, blksize) - blkoff, left);
			rlen = pfs_blkio_read(mnt, data+rsum, dblkno,
			    blkoff, rlen);
		}

		if (locked)
			pfs_inode_lock(in);
		if (rlen < 0)
			return rlen;
		//If we do not need further read then we do not need sync.
		if (locked && ((rsum + rlen) < (ssize_t)len)) {
			err = pfs_inode_sync(in, PFS_INODET_FILE, btime, false);
			if (err < 0)
				return err;
		}
	}

	return rsum;
}

/*
 * write operation can't hold any locks during doing I/O, but it may modify
 * block hole. To keep block hole atomic, write would record block hole's
 * change into block map and writemodify structures in current inode. At
 * the same time an access barrier is set into inode. Other threads which
 * want to access inode would be blocked by pfs_inode_sync().
 *
 * If error occurs during write, writemodify are freed and inode is marked
 * stale. After all data are already written into disk, current thread
 * transfers writemodify to tx and record it into journal. If process crashes,
 * write operation has no effect because of its change isn't written into
 * journal.
 */
static ssize_t
pfs_file_write(pfs_inode_t *in, const void *buf, size_t len, off_t *off,
    bool locked, uint64_t btime)
{
	char		*data = (char *)buf, *pdata;
	pfs_mount_t	*mnt = in->in_mnt;
	uint64_t	blksize = mnt->mnt_blksize;
	int		err = 0;
	ssize_t		wlen, wsum, left, fsize;
	pfs_blkno_t	dblkno;
	pfs_blkid_t	blkid;
	off_t		offset, blkoff, dbhoff, woff;

	if (locked) {
		err = pfs_inode_sync_first(in, PFS_INODET_FILE, btime, false);
		if (err)
			return err;
	}

	fsize = pfs_inode_size(in);
	offset = *off;
	if (offset == OFFSET_FILE_SIZE)
		offset = (off_t)fsize;
	err = 0;
	for (wsum = 0; wsum < (ssize_t)len; wsum += wlen, offset += wlen) {
		left = len - wsum;
		blkid = fblkid(offset, blksize);
		blkoff = fblkoff(offset, blksize);

		pfs_inode_map(in, blkid, &dblkno, &dbhoff);
		if (dblkno == 0) {
			/*
			 * There is no mapping for the file block. We
			 * have allocated blocks before write, but
			 * now cant find them, so there must be other
			 * threads deleting it. Interesting to see.
			 */
			pfs_etrace("blkid %llu mapps to %lld in write\n",
			    blkid, dblkno);
			ERR_RETVAL(EAGAIN);
		}

		if (dbhoff < blkoff) {
			/*
			 * The write hits in the middle of a hole and will
			 * split it. To maintain the invariant that a hole
			 * extends to the end of its block, the left part of
			 * the hole is filled first.
			 *
			 * Note that blkio_write fills the block with zeros
			 * if its data argument is NULL.
			 */
			woff = dbhoff;
			wlen = blkoff - dbhoff;
			pdata = NULL;
			dbhoff = blkoff;
			pfs_inode_writemodify_shrink_dblk_hole(in, blkid,
			    dbhoff, blksize - dbhoff);
		} else {
			woff = blkoff;
			wlen = MIN(blksize - blkoff, left);
			pdata = data + wsum;
			if (dbhoff < blkoff + wlen) {
				dbhoff = blkoff + wlen;
				pfs_inode_writemodify_shrink_dblk_hole(in, blkid,
				    dbhoff, blksize - dbhoff);
			}

			/*
			 * Only writing user data can change file size.
			 * Record the delta into writemodify to exclude others
			 * before releasing lock.
			 */
			if (offset + wlen > fsize) {
				pfs_inode_writemodify_increment_size(in,
				    offset + wlen - fsize);
			}
		}
		if (locked)
			pfs_inode_unlock(in);

		wlen = pfs_blkio_write(mnt, pdata, dblkno, woff, wlen);

		if (locked)
			pfs_inode_lock(in);

		if (wlen < 0)
			return wlen;
		/*
		 * Filling block hole shouldn't update offset.
		 */
		if (pdata == NULL)
			wlen = 0;
		if (locked) {
			err = pfs_inode_sync(in, PFS_INODET_FILE, btime, false);
			if (err)
				return err;
		}
	}
	*off = offset;
	return wsum;
}

static int
pfs_file_setxattr(pfs_inode_t *in, const char *name, const void *value,
    size_t size, uint64_t btime)
{
	int err;

	err = pfs_inode_sync_first(in, PFS_INODET_NONE, btime, false);
	if (err < 0)
		return err;

	err = pfs_inodephy_setxattr(in->in_mnt, in->in_ino, name, value, size);
	return err;
}

static int
pfs_file_stat(pfs_inode_t *in, struct stat *st, uint64_t btime)
{
	int err;

	err = pfs_inode_sync_first(in, PFS_INODET_NONE, btime, false);
	if (err < 0)
		return err;
	err = pfs_inode_stat(in, st);
	return err;
}

int
pfs_file_close(pfs_file_t *file)
{
	if (file == NULL)
		return 0;

	return fd_free(file, false);
}

int
pfs_file_close_locked(pfs_file_t *file)
{
	if (file == NULL)
		return 0;

	return fd_free(file, true);
}

static off_t
pfs_file_lseek(pfs_file_t *file, off_t offset, int whence)
{
	off_t old_offset, new_offset;

	switch (whence) {
	case SEEK_SET:
		old_offset = file->f_offset;
		new_offset = offset;
		goto check_file_offset;

	case SEEK_CUR:
		old_offset = file->f_offset;
		new_offset = old_offset + offset;
		break;

	case SEEK_END:
		old_offset = pfs_file_size(file, file->f_btime);
		if (old_offset < 0)
			return old_offset;
		new_offset = old_offset + offset;
		break;

	default:
		ERR_RETVAL(EINVAL);
	}

	if (offset > 0  && new_offset < old_offset)
		ERR_RETVAL(EOVERFLOW);

	/*
	 * when offset < 0 with SEEK_END, f_offset is less than filesize,
	 * new_offset maybe bigger than f_offset. So we compare new_offset and
	 * file size.
	 */
	if (offset < 0 && new_offset > old_offset)
		ERR_RETVAL(EOVERFLOW);

check_file_offset:
	if (new_offset < 0) {
		ERR_RETVAL(EINVAL);
	} else {
		file->f_offset = new_offset;
		return file->f_offset;
	}
}

static ssize_t
pfs_file_allocate(pfs_inode_t *in, off_t offset, size_t len, int mode,
    uint64_t btime)
{
	int		err;
	pfs_mount_t	*mnt = in->in_mnt;
	uint64_t	blksize = mnt->mnt_blksize;
	ssize_t		asum, left, alen;
	ssize_t		oldfsize, fsize;
	pfs_blkno_t	dblkno;
	off_t		dbhoff;
	pfs_blkid_t	blkid;

	err = pfs_inode_sync_first(in, PFS_INODET_FILE, btime, false);
	if (err < 0)
		return err;

	oldfsize = fsize = pfs_inode_size(in);
	if (offset == OFFSET_FILE_SIZE)
		offset = (off_t)fsize;
	for (asum = 0; asum < (ssize_t)len; asum += alen, offset += alen) {
		left = len - asum;

		blkid = fblkid(offset, blksize);
		pfs_inode_map(in, blkid, &dblkno, &dbhoff);
		if (dblkno == 0) {
			err = pfs_inode_add(in, blkid);
			if (err < 0)
				return err;

			/*
			 * Empty block hole to avoid frequently modifying the
			 * metadata of current file.
			 * Users must guarantee that file has been initialized
			 * by themselves before it is read at the same offset.
			 */
			if ((mode & FALLOC_FL_NO_HIDE_STALE) &&
			    pfs_version_has_features(mnt, PFS_FEATURE_BLKHOLE)) {
				/*
				 * pfs_inode_phy_get is not needed here because
				 * it is done in pfs_inode_add. But in fact
				 * FALLOC_FL_NO_HIDE_STALE can be applied for
				 * allocated blk~~
				 */
				pfs_inode_shrink_dblk_hole(in, blkid, blksize, 0);
			}
		}

		alen = MIN(blksize - fblkoff(offset, blksize), left);
		if (offset + alen > fsize)
			fsize = offset + alen;
	}
	if (!(mode & FALLOC_FL_KEEP_SIZE) && fsize > oldfsize) {
		err = pfs_inode_change(in, fsize - oldfsize, false);
		if (err < 0)
			return err;
	}
	return fsize;
}

ssize_t
pfs_file_size(pfs_file_t *file, uint64_t btime)
{
	pfs_inode_t *in = file->f_inode;
	ssize_t fsize;
	int err, ino;

	fsize = 0;
	pfs_inode_lock(in);
	if (pfs_inode_skip_sync(in)) {
		/*
		 * When we meet the condition, we return the file size
		 * of in->in_ino after pfs_file_size called with checking
		 * whether the file is removed.
		 */
		ino = in->in_ino;
		fsize = pfs_inodephy_size(in->in_mnt, ino);
		pfs_inode_unlock(in);
		return fsize;
	}
	err = pfs_inode_sync_first(in, PFS_INODET_FILE, btime, false);
	if (err == 0)
		fsize = pfs_inode_size(in);
	pfs_inode_unlock(in);
	return err < 0 ? err : fsize;
}

static int
pfs_file_map(pfs_inode_t *in, fmap_entry_t *fmapv, int count, uint64_t btime)
{
	pfs_mount_t *mnt = in->in_mnt;
	int err, i;
	ssize_t fsize;
	pfs_blkid_t blkid;
	pfs_blkno_t dblkno;
	off_t dbhoff;
	fmap_entry_t *fmap;

	err = pfs_inode_sync_first(in, PFS_INODET_FILE, btime, false);
	if (err < 0)
		return err;

	fsize = pfs_inode_size(in);
	for (i = 0; i < count; i++) {
		fmap = &fmapv[i];
		if (fmap->f_off < 0 || fmap->f_off >= fsize)
			ERR_RETVAL(EINVAL);
		blkid = fblkid(fmap->f_off, mnt->mnt_blksize);
		pfs_inode_map(in, blkid, &dblkno, &dbhoff);

		fmap->f_ckid = dblkno / PFS_NBT_PERCHUNK;
		fmap->f_blkno = dblkno;
		fmap->f_btno = blkno2btno(mnt, dblkno);
		fmap->f_bthoff = dbhoff;
	}

	return 0;
}

int
pfs_file_xftruncate(pfs_file_t *file, off_t len)
{
	pfs_inode_t *in = file->f_inode;
	pfs_mount_t *mnt = in->in_mnt;
	ssize_t fsize;
	int err = 0;

	PFS_ASSERT(len >= 0);
	MNT_STAT_BEGIN();
	/*
	 * pfs_file_truncate() may not truncate file size to len
	 * if truncated size is too large, so we should check whether
	 * it needs to retry.
	 */
	do {
		tls_write_begin(mnt);
		pfs_inode_lock(in);
		fsize = pfs_file_truncate(in, len, file->f_btime);
		err = fsize < 0 ? fsize : 0;
		pfs_inode_unlock(in);
		tls_write_end(err);
	} while (err == 0 && fsize != len);
	MNT_STAT_END(MNT_STAT_FILE_TRUNCATE);
	return err;
}

ssize_t
pfs_file_xpread(pfs_file_t *file, void *buf, size_t len, off_t off)
{
	pfs_inode_t *in = file->f_inode;
	pfs_mount_t *mnt = in->in_mnt;
	ssize_t rlen;
	int err;
	off_t off2;
	MNT_STAT_BEGIN();
	if (off == OFFSET_FILE_POS)
		off2 = file->f_offset;
	else
		off2 = off;
	PFS_ASSERT(off2 >= 0);

	rlen = -1;
	tls_read_begin(mnt);
	pfs_inode_lock(in);
	rlen = pfs_file_read(in, buf, len, off2, true, file->f_btime);
	err = rlen < 0 ? rlen : 0;
	pfs_inode_unlock(in);
	tls_read_end(err);

	if (err == 0 && off == -1)
		__sync_add_and_fetch(&file->f_offset, rlen);
	MNT_STAT_END(MNT_STAT_FILE_READ);
	return rlen;
}

ssize_t
pfs_file_xpwrite(pfs_file_t *file, const void *buf, size_t len, off_t off)
{
	pfs_inode_t *in = file->f_inode;
	pfs_mount_t *mnt = in->in_mnt;
	ssize_t wlen;
	int err, err1;
	off_t off2;

	if (len <= 0)
		return 0;

	MNT_STAT_BEGIN();
	if (file->f_flags & O_APPEND)
		off2 = OFFSET_FILE_SIZE;
	else if (off == OFFSET_FILE_POS)
		off2 = file->f_offset;
	else
		off2 = off;
	PFS_ASSERT(off2 >= 0 || off2 == OFFSET_FILE_SIZE);

	/*
	 * pwrite is not protected by a tx, since it modify file data,
	 * not meta data.
	 *
	 * XXX:
	 * we shouldn't protect with tls_read_begin/end, because it may
	 * hurt performance.
	 */
	// tls_read_begin(mnt);
	pfs_inode_lock(in);
	wlen = pfs_file_write(in, buf, len, &off2, true, file->f_btime);
	err = wlen < 0 ? wlen : 0;
	pfs_inode_unlock(in);
	// tls_read_end(mnt);

	/*
	 * File with O_APPEND flag can't tolerate ETIMEDOUT error,
	 * because new file size may be already written into journal
	 * even we get an ETIMEDOUT error. Then retrying append
	 * operations results in multiple writing.
	 */
	tls_write_begin_flags(mnt, file->f_flags & O_APPEND);
	pfs_inode_lock(in);
	/*
	 * Always transform writemodify to tx if it's not empty.
	 * So if err<0 or commit failed, the rollback of tx will
	 * restore metadata and the callback will clear sync events.
	 */
	err1 = pfs_inode_writemodify_commit(in);
	ERR_UPDATE(err, err1);
	pfs_inode_unlock(in);
	tls_write_end(err);

	if (err)
	       wlen = err;
	else if (off == OFFSET_FILE_POS)
		file->f_offset = off2;
	MNT_STAT_END(MNT_STAT_FILE_WRITE);
	return wlen;
}

int
pfs_file_xsetxattr(pfs_file_t *file, const char *name, const void *value,
    size_t size)
{
	pfs_inode_t *in = file->f_inode;
	pfs_mount_t *mnt = in->in_mnt;
	int err;

	tls_write_begin(mnt);
	pfs_inode_lock(in);
	err = pfs_file_setxattr(in, name, value, size, file->f_btime);
	pfs_inode_unlock(in);
	tls_write_end(err);
	return err;
}

int
pfs_file_xstat(pfs_file_t *file, struct stat *st)
{
	pfs_inode_t *in = file->f_inode;
	pfs_mount_t *mnt = in->in_mnt;
	int err;
	MNT_STAT_BEGIN();
	tls_read_begin(mnt);
	pfs_inode_lock(in);
	err = pfs_file_stat(in, st, file->f_btime);
	pfs_inode_unlock(in);
	tls_read_end(err);
	MNT_STAT_END(MNT_STAT_FILE_FSTAT);
	return err;
}

int
pfs_file_xfallocate(pfs_file_t *file, off_t offset, size_t len, int mode)
{
	pfs_inode_t *in = file->f_inode;
	pfs_mount_t *mnt = in->in_mnt;
	off_t off2;
	ssize_t newfsize;
	int err;
	MNT_STAT_BEGIN();
	/*
	 * Ignore file flags in FALLOC_PFSFL_FIXED_OFFSET mode.
	 * Otherwise blocks will be wrongly preallocated at the
	 * tail if file is opened with O_APPEND.
	 */
	if (mode & FALLOC_PFSFL_FIXED_OFFSET) {
		off2 = offset;
	} else {
		if (file->f_flags & O_APPEND)
			off2 = OFFSET_FILE_SIZE;
		else if (offset == OFFSET_FILE_POS)
			off2 = file->f_offset;
		else
			off2 = offset;
	}
	PFS_ASSERT(off2 >= 0 || off2 == OFFSET_FILE_SIZE);

	tls_write_begin(mnt);
	pfs_inode_lock(in);
	newfsize = pfs_file_allocate(in, off2, len, mode, file->f_btime);
	err = newfsize < 0 ? newfsize : 0;
	pfs_inode_unlock(in);
	tls_write_end(err);
	MNT_STAT_END(MNT_STAT_FILE_FALLOCATE);
	return err;
}

off_t
pfs_file_xlseek(pfs_file_t *file, off_t offset, int whence)
{
	pfs_mount_t *mnt = file->f_inode->in_mnt;
	int err;
	off_t curoff;
	bool need_sync = pfs_mount_needsync(mnt) && (whence == SEEK_END);
	MNT_STAT_BEGIN();
	curoff = -1;
	tls_read_begin_flags(mnt, need_sync);
	curoff = pfs_file_lseek(file, offset, whence);
	err = curoff < 0 ? curoff : 0;
	tls_read_end(err);
	MNT_STAT_END(MNT_STAT_FILE_LSEEK);
	return curoff;
}

/*
 * pfs_file_pread() and pfs_file_pwrite() are dedicated to log thread.
 * They have no inode lock, and actually should not have inode lock,
 * because that may cause deadlock, of which a possible scenario is
 * listed below:
 * - an IO thread holds metadata wrlock and send a log request to
 *   the log thread.
 * - admin thread is stating the .pfs-journal file, holding its inode
 *   lock and blocking on metadata rdlock.
 * - the log thread tries to get the inode lock of .pfs-journal.
 */
ssize_t
pfs_file_pread(pfs_file_t *file, void *buf, size_t len, off_t off)
{
	pfs_inode_t *in = file->f_inode;
	ssize_t n;
	MNT_STAT_BEGIN();
	pfs_tls_set_stat_file_type(file->f_type);
	n = pfs_file_read(in, buf, len, off, false, INNER_FILE_BTIME);
	MNT_STAT_END(MNT_STAT_FILE_READ);
	MNT_STAT_API_END_BANDWIDTH(MNT_STAT_API_PREAD, len);
	return n;
}

ssize_t
pfs_file_pwrite(pfs_file_t *file, const void *buf, size_t len, off_t off)
{
	pfs_inode_t *in = file->f_inode;
	ssize_t n;
	MNT_STAT_BEGIN();
	pfs_tls_set_stat_file_type(file->f_type);
	n = pfs_file_write(in, buf, len, &off, false, INNER_FILE_BTIME);
	MNT_STAT_END(MNT_STAT_FILE_WRITE);
	MNT_STAT_API_END_BANDWIDTH(MNT_STAT_API_PWRITE, len);
	return n;
}

int
pfs_file_release(pfs_mount_t *mnt, pfs_ino_t ino, uint64_t btime)
{
	int err;
	pfs_file_t *file = NULL;

	do {
		err = pfs_file_open_impl(mnt, ino, 0, &file, btime);
		if (err < 0)
			goto ignore_enoent;

		err = pfs_file_xftruncate(file, 0);
		if (err < 0)
			goto ignore_enoent;

		err = pfs_inode_release(mnt, ino, btime, file->f_inode);
	ignore_enoent:
		if (err == -ENOENT) {
			pfs_etrace("inode %ld, seems to be remotely removed "
			   "according to orphan inodes reclaiming!\n", ino);
			err = 0;
		}
		if (file)
			pfs_file_close(file);
	} while(err == -EAGAIN);

	return err;
}

int
pfs_file_xmap(pfs_file_t *file, fmap_entry_t *fmapv, int count)
{
	int err;
	pfs_inode_t *in = file->f_inode;
	pfs_mount_t *mnt = in->in_mnt;

	tls_read_begin(mnt);
	pfs_inode_lock(in);
	err = pfs_file_map(in, fmapv, count, file->f_btime);
	pfs_inode_unlock(in);
	tls_read_end(err);

	return err;
}

static void __attribute__((constructor))
init_pfs_fdtbl()
{
	mutex_init(&fdtbl_mtx);
}

static int
dump_file(admin_buf_t *ab, pfs_file_t *file)
{
	int err, n;
	char path[PATH_MAX];
	int64_t ino = file->f_inode->in_ino;
	pfs_mount_t *mnt = file->f_inode->in_mnt;

	tls_read_begin(mnt);
	err = pfs_dir_path(mnt, ino, path, sizeof(path), file->f_btime);
	tls_read_end(err);
	if (err == PFS_DE_UNLINKED || err == -ENOENT) {
		n = snprintf(path, sizeof(path), "(unlinked, ino: %ld)", ino);
		PFS_VERIFY(0 < n && n < (int)sizeof(path));
	}
	else if (err < 0) {
		return err;
	}

	pfs_adminbuf_printf(ab, "%6d %s\n", file->f_fd, path);
	return 0;
}

int
pfs_fdtbl_dump(admin_buf_t *ab)
{
	int i, n;
	pfs_file_t *file;

	mutex_lock(&fdtbl_mtx);
	for (i = 0, n = 0; i < pfs_max_nfd && n < fdtbl_nopen; i++) {
		file = fd_to_file(i);
		if (file == NULL)
			continue;
		n++;
		(void)dump_file(ab, file);
	}
	mutex_unlock(&fdtbl_mtx);

	return 0;
}
