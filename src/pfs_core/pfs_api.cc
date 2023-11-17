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
#include <linux/falloc.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include <fcntl.h>

#include "pfs_api.h"
#include "pfs_fstream.h"
#include "pfs_mount.h"
#include "pfs_file.h"
#include "pfs_dir.h"
#include "pfs_inode.h"
#include "pfs_impl.h"
#include "pfs_option.h"
#include "pfs_trace.h"
#include "pfs_stat.h"

/*-
 *  This file implements the API layer of the PFS, whose main
 *  component diagram is depicted below. API layer is responsible for
 *  the access to directories and files. Both directory and file
 *  employ inode to manage their contents: directory entries and block
 *  tags. Inode, diretnry and block tag are meta data. Meta data are
 *  accessed within a tx. A tx serializes the access to all meta data by
 *  a giant meta lock. Also if there is modification to meta data, the
 *  modification will be logged. The log is written to builtin file
 *  .pfs-journal, which is meta data sync channel among one leader
 *  node and multiple follower nodes.
 *
 *       +------------- api -----------+
 *       |                             |
 *       v                             v
 *      dir ---------> inode <------- file
 *        \               /          ^ |
 *         \             /          /  v
 *          +-> meta  <-+     +----+  dev
 *               |            |        |
 *               v            |        v
 *              tx tx         |    io channel
 *               | ^          +        |
 *               v |         /|        v
 *              log   ------+ |   POLAR SWITCH
 *               |            |
 *               v            /
 *             paxos  -------+
 *
 * File is responsible for data management. It interacts with dev layer,
 * a concepts similar to raw device in UN*X. A pfs dev communicates through
 * io channel with polar switch. Polar switch interprets the block device
 * address and send IO requets to chunk servers, where data is actually
 * stored or retrieved.
 *
 * File API functions can be divided into two categories: the ones
 * based on path names and the others based on fd.
 *
 * Typical implementation of API functions base @filepath is as follows:
 *      - call pfs_file_find to translate @filepath into ino.
 *      - call pfs_file_open with ino to get a file.
 *      - do the file operation.
 *      - call pfs_file_close to release the opened file.
 *
 * Typical implementation of API functions based on @fd is as follows:
 *      - call pfs_file_get to get the file refered to by @fd
 *      - do the file operation.
 *      - call pfs_file_put to put the file.
 */


/* libpfs version, 'strings libpfs.a' can get this info */
#define _TOSTR(a)	#a
#define TOSTR(a)	_TOSTR(a)
char pfs_build_version[] = "libpfs_version_" TOSTR(VERSION_DETAIL);

/*
 * pfs_unlink() should lock this mutex for thread-safe.
 * pfs_unlink() is already serialized by meta lock, so
 * this protection in API layer doesn't hurt perfomance.
 */
pthread_mutex_t	unlink_mtx;

/*
 * pfs_rename() should lock this mutex for thread-safe.
 * This function is vulnerable since it resolve two paths and
 * can lead to deadlock easily. We just lock it conservatively.
 */
pthread_mutex_t	rename_mtx;

#define OFF_MAX ~((off_t)1 << (sizeof(off_t) * 8 - 1))

/*
 * fd(int type)'s second bit from high end:
 * 1 means its a pbd fd,
 * 0 means its a local file system fd.
 */
#define PFS_FD_MAKE(fd) 					\
	(int)((unsigned int)(fd) | (1U << PFS_FD_VALIDBIT))

#define PFS_DIR_MAKE(dir) 					\
	(DIR *)((uint64_t)(dir) | (uint64_t)(0x01))

#define PFS_DIR_RAW(dir) 					\
	(DIR *)((uint64_t)(dir) & ~(uint64_t)(0x01))

#define PFS_DIR_CHECK(dir)					\
	( PFS_DIR_ISVALID(dir) && (PFS_DIR_RAW(dir))->d_mnt )

#define PATH_ARG(path)						\
	(path) ? (path) : "NULL"

#define PFS_STRM_MAKE(stream)					\
	(FILE *)((uint64_t)(stream) | (uint64_t)(0x03))

#define PFS_STRM_RAW(stream)					\
	(FILE *)((uint64_t)(stream) & ~(uint64_t)(0x03))

#define	API_ENTER(level, fmt, ...) do {				\
	if (err != 0 && err != -EAGAIN) {			\
		pfs_etrace("%s invalid args(" fmt ")\n",	\
		    __func__, __VA_ARGS__);			\
	} else if (PFS_TRACE_##level == PFS_TRACE_INFO) { 	\
		pfs_itrace("%s(" fmt ")\n",			\
		    __func__, __VA_ARGS__);			\
	} else if (PFS_TRACE_##level == PFS_TRACE_DBG) {	\
		pfs_dbgtrace("%s(" fmt ")\n",			\
		    __func__, __VA_ARGS__);			\
	}							\
} while(0)

#define	API_EXIT(err) do {					\
	if (err < 0) {						\
		errno_convert(err);				\
	}							\
} while(0)

static int error_number[] = {
	EACCES,
	EAGAIN,
	EBADF,
	EEXIST,
	EFBIG,
	EINVAL,
	EISDIR,
	EMFILE,
	ENAMETOOLONG,
	ENODEV,
	ENOENT,
	ENOTEMPTY,
	ENOMEM,
	ENOSPC,
	ENOTDIR,
	EXDEV,
	EOVERFLOW,
	EPFS_FILE_2MANY,
	EROFS,
	EBUSY,
	ERANGE,
	ENOTSUP,
	0,	/* sentinel */
};

enum {
	GTYPE_MOUNT_NAMEI = 1,
	GTYPE_MOUNT_FILE,
	GTYPE_MOUNT_DIR,
};

#define	GET_MOUNT_NAMEI(pbdpath, type, mp, np) 	do { 	\
	pfs_mount_t *_m;				\
							\
	err = pfs_namei_init(np, pbdpath, type);	\
	if (err < 0)					\
		return err;				\
	_m = pfs_get_mount((np)->ni_pbd);		\
	if (_m == NULL)					\
		ERR_RETVAL(ENODEV);			\
							\
	*(mp) = _m;					\
} while (0);						\
const int _gtype = GTYPE_MOUNT_NAMEI


#define	PUT_MOUNT_NAMEI(mnt, np) do {			\
	char _a[_gtype == GTYPE_MOUNT_NAMEI ? 1 : -1]	\
		__attribute__((unused));		\
	pfs_namei_fini(np);				\
	if (mnt) {					\
		pfs_put_mount(mnt);			\
		mnt = NULL;				\
	}						\
} while (0)


#define	GET_MOUNT_FILE(fd, locktype, mp, fp) do {	\
	pfs_file_t *_f;					\
	pfs_mount_t *_m;				\
							\
	_f = pfs_file_get(fd, locktype);		\
	if (_f == NULL)					\
		ERR_RETVAL(EBADF);			\
	_m = pfs_get_mount_byid(_f->f_mntid);		\
	/* Files must reset on a valid mount */		\
	PFS_ASSERT(_m != NULL);				\
							\
	*(mp) = _m;					\
	*(fp) = _f;					\
} while (0);						\
const int _gtype = GTYPE_MOUNT_FILE

#define	PUT_MOUNT_FILE(mnt, file) do {			\
	char _a[_gtype == GTYPE_MOUNT_FILE ? 1 : -1]	\
		__attribute__((unused));		\
	if (mnt) {					\
		pfs_put_mount(mnt);			\
		mnt = NULL;				\
	}						\
	if (file) {					\
		/* the file is still refered, put it */	\
		pfs_file_put(file);			\
		file = NULL;				\
	}						\
} while (0)

#define	GET_MOUNT_DIR(dir, mp) do {			\
	pfs_mount_t *_m;				\
							\
	_m = pfs_get_mount_byid((dir)->d_mntid);	\
	*(mp) = _m;					\
} while (0);						\
const int _gtype = GTYPE_MOUNT_DIR

#define	PUT_MOUNT_DIR(mnt) do {				\
	char _a[_gtype == GTYPE_MOUNT_DIR ? 1 : -1]	\
		__attribute__((unused));		\
	if (mnt) {					\
		pfs_put_mount(mnt);			\
		mnt = NULL;				\
	}						\
} while (0)

static void
errno_convert(int err)
{
	int eno = 0;
	size_t i = 0;

	PFS_ASSERT(err < 0);
	for (i = 0; (eno = error_number[i]) != 0; i++) {
		if (-err == eno) {
			errno = eno;
			return;
		}
	}
	errno = EIO;	/* the default error no */
}

static int
_pfs_truncate(const char *pbdpath, off_t len)
{
	int err, tmp;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_FILE, &mnt, &ni);

	err = pfs_file_open(mnt, &ni, 0, &file);
	if (err < 0) {
		PUT_MOUNT_NAMEI(mnt, &ni);
		return err;
	}

	err = pfs_file_xftruncate(file, len);

	tmp = pfs_file_close(file);
	PFS_VERIFY(tmp == 0);
	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

int
_pfs_ftruncate(int fd, off_t len)
{
	int err;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;

	GET_MOUNT_FILE(fd, RDLOCK_FLAG, &mnt, &file);

	err = pfs_file_xftruncate(file, len);

	PUT_MOUNT_FILE(mnt, file);
	return err;
}

static int
_pfs_open(const char *pbdpath, __attribute__((unused)) int flags,
    __attribute__((unused)) mode_t mode)
{
	int err, fd, tmp;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;
	int type = PFS_INODET_NONE;

	if (flags & (O_CREAT | O_TRUNC)) {
		/* O_CREAT and O_TRUNC are only for file */
		type = PFS_INODET_FILE;
	}
	GET_MOUNT_NAMEI(pbdpath, type, &mnt, &ni);

	fd = pfs_file_open(mnt, &ni, flags, &file);
	err = fd < 0 ? fd : 0;
	if (err < 0) {
		PUT_MOUNT_NAMEI(mnt, &ni);
		return err;
	}

	/*
	 * handle truncate and append
	 */
	if ((flags & O_TRUNC) != 0) {
		/*
		 * The file data is cleared and there must
		 * be no file hole.
		 */
		err = pfs_file_xftruncate(file, 0);
		if (err < 0)
			goto out;
	}

	PUT_MOUNT_NAMEI(mnt, &ni);
	return fd;

out:
	/* error after getting a valid file ptr */
	tmp = pfs_file_close(file);
	PFS_VERIFY(tmp == 0);
	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static int
_pfs_close(int fd)
{
	int err;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;

	GET_MOUNT_FILE(fd, WRLOCK_FLAG, &mnt, &file);

	err = pfs_file_close_locked(file);
	if (err == 0) {
		/* must set as null so that it will not be put again. */
		file = NULL;
	}

	PUT_MOUNT_FILE(mnt, file);
	return err;
}

static ssize_t
_pfs_read(int fd, void *buf, size_t len)
{
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;
	ssize_t rlen = -1;

	if (len == 0)
		return 0;

	GET_MOUNT_FILE(fd, RDLOCK_FLAG, &mnt, &file);

	rlen = pfs_file_xpread(file, buf, len, OFFSET_FILE_POS);

	PUT_MOUNT_FILE(mnt, file);
	return rlen;
}

static ssize_t
_pfs_write(int fd, const void *buf, size_t len)
{
	int err;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;
	ssize_t wlen = -1;

	if (len == 0)
		return 0;

	GET_MOUNT_FILE(fd, RDLOCK_FLAG, &mnt, &file);

	// Check whether result offset is bigger than off_t maximum.
	if ((size_t)(OFF_MAX - file->f_offset) < len)
		ERR_GOTO(EFBIG, finish);

	/*
	 * pfs_write isn't thread-safe. offset in fallocate and pwrite
	 * maybe not equal.
	 * Because argument -1 means do fallocate/pwrite from file's tail.
	 */
	err = pfs_file_xfallocate(file, OFFSET_FILE_POS, len, FALLOC_FL_KEEP_SIZE);
	if (err < 0)
		goto finish;

	wlen = pfs_file_xpwrite(file, buf, len, OFFSET_FILE_POS);

	PUT_MOUNT_FILE(mnt, file);
	return wlen;

finish:
	PUT_MOUNT_FILE(mnt, file);
	return err;
}

static ssize_t
_pfs_pread(int fd, void *buf, size_t len, off_t offset)
{
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;
	ssize_t rlen = -1;

	if (len == 0)
		return 0;

	GET_MOUNT_FILE(fd, RDLOCK_FLAG, &mnt, &file);

	rlen = pfs_file_xpread(file, buf, len, offset);

	PUT_MOUNT_FILE(mnt, file);
	return rlen;
}

static ssize_t
_pfs_pwrite(int fd, const void *buf, size_t len, off_t offset)
{
	int err;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;
	ssize_t wlen = -1;

	if (len == 0)
		return 0;

	if ((size_t)(OFF_MAX - offset) < len)
		ERR_RETVAL(EFBIG);

	GET_MOUNT_FILE(fd, RDLOCK_FLAG, &mnt, &file);

	err = pfs_file_xfallocate(file, offset, len, FALLOC_FL_KEEP_SIZE);
	if (err < 0) {
		PUT_MOUNT_FILE(mnt, file);
		return err;
	}

	wlen = pfs_file_xpwrite(file, buf, len, offset);

	PUT_MOUNT_FILE(mnt, file);
	return wlen;
}

static int
_pfs_fstat(int fd, struct stat *buf)
{
	int err;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;

	GET_MOUNT_FILE(fd, RDLOCK_FLAG, &mnt, &file);

	memset(buf, 0, sizeof(*buf));
	err = pfs_file_xstat(file, buf);

	PUT_MOUNT_FILE(mnt, file);
	return err;
}

static int
_pfs_stat(const char *pbdpath, struct stat *st)
{
	int err, fd, tmp;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_NONE, &mnt, &ni);

	fd = pfs_file_open(mnt, &ni, 0, &file);
	err = fd < 0 ? fd : 0;
	if (err < 0) {
		PUT_MOUNT_NAMEI(mnt, &ni);
		return err;
	}

	memset(st, 0, sizeof(*st));
	err = pfs_file_xstat(file, st);

	tmp = pfs_file_close(file);
	PFS_VERIFY(tmp == 0);
	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static int
_pfs_fallocate(int fd, int mode, off_t offset, off_t len)
{
	int err;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;

	GET_MOUNT_FILE(fd, RDLOCK_FLAG, &mnt, &file);

	err = pfs_file_xfallocate(file, offset, len,
	    FALLOC_PFSFL_FIXED_OFFSET | mode);

	PUT_MOUNT_FILE(mnt, file);
	return err;
}

static void __attribute__((constructor))
init_pfs_unlink_mtx()
{
	mutex_init(&unlink_mtx);
}

static int
_pfs_unlink(const char *pbdpath)
{
	int err;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_FILE, &mnt, &ni);

	err = pfs_memdir_xremove(mnt, &ni);
	if (err >= 0)
		err = pfs_file_release(mnt, ni.ni_ino, ni.ni_btime);

	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static off_t
_pfs_lseek(int fd, off_t offset, int whence)
{
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;
	off_t new_offset = -1;

	GET_MOUNT_FILE(fd, WRLOCK_FLAG, &mnt, &file);

	new_offset = pfs_file_xlseek(file, offset, whence);

	PUT_MOUNT_FILE(mnt, file);
	return new_offset;
}

static int
_pfs_setxattr(const char *pbdpath, const char *name, const void *value,
    size_t size, int flags)
{
	int err, fd, tmp;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;

	if (flags != 0)
		ERR_RETVAL(ENOTSUP);

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_NONE, &mnt, &ni);

	fd = pfs_file_open(mnt, &ni, 0, &file);
	err = fd < 0 ? fd : 0;
	if (err < 0) {
		PUT_MOUNT_NAMEI(mnt, &ni);
		return err;
	}

	err = pfs_file_xsetxattr(file, name, value, size);

	tmp = pfs_file_close(file);
	PFS_VERIFY(tmp == 0);

	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static int
_pfs_mkstemp(char *tmpl)
{
	int fd;

	fd = gen_tempname(tmpl, 0, 0, PFS_INODET_FILE);
	return fd;
}

static int
_pfs_fmap(int fd, fmap_entry_t *fmapv, int count)
{
	int err;
	pfs_mount_t *mnt = NULL;
	pfs_file_t *file = NULL;

	GET_MOUNT_FILE(fd, RDLOCK_FLAG, &mnt, &file);

	err = pfs_file_xmap(file, fmapv, count);

	PUT_MOUNT_FILE(mnt, file);
	return err;
}

static int
_pfs_mkdir(const char *pbdpath, __attribute__((unused)) mode_t mode)
{
	int err;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_DIR, &mnt, &ni);

	err = pfs_memdir_xlookup(mnt, &ni, O_CREAT|O_EXCL);

	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static int
_pfs_opendir(const char *pbdpath, DIR **dirp)
{
	int err;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_DIR, &mnt, &ni);

	err = pfs_memdir_xopen(mnt, &ni, dirp);

	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static int
_pfs_readdir(DIR *dir, struct dirent **dentp)
{
	int err;
	pfs_mount_t *mnt = NULL;
	struct direntplus *dplus = NULL;

	GET_MOUNT_DIR(dir, &mnt);

	err = pfs_memdir_xread(mnt, dir, NULL, &dplus, false);
	if (err == 0 && dplus != NULL)
		*dentp = &dplus->dp_sysde;
	else
		*dentp = NULL;

	PUT_MOUNT_DIR(mnt);

	return err;
}

static int
_pfs_readdir_r(DIR *dir, struct dirent *entry, struct dirent **result)
{
	int err;
	pfs_mount_t *mnt = NULL;
	struct direntplus *dplus = NULL;

	GET_MOUNT_DIR(dir, &mnt);

	err = pfs_memdir_xread(mnt, dir, entry, &dplus, false);
	if (err == 0 && dplus != NULL)
		*result = entry;
	else
		*result = NULL;

	PUT_MOUNT_DIR(mnt);
	return err;
}

static int
_pfs_readdirplus(DIR *dir, struct direntplus **dplusp)
{
	int err;
	pfs_mount_t *mnt = NULL;

	*dplusp = NULL;
	GET_MOUNT_DIR(dir, &mnt);

	err = pfs_memdir_xread(mnt, dir, NULL, dplusp, true);

	PUT_MOUNT_DIR(mnt);
	return err;
}

static int
_pfs_closedir(DIR *dir)
{
	int err;
	pfs_mount_t *mnt = NULL;

	/* close a stale dir returns no error */
	GET_MOUNT_DIR(dir, &mnt);

	err = pfs_memdir_close(mnt, dir);

	PUT_MOUNT_DIR(mnt);
	return err;
}

static int
_pfs_rmdir(const char *pbdpath)
{
	int err;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_DIR, &mnt, &ni);

	err = pfs_memdir_xremove(mnt, &ni);
	if (err >= 0) {
		err = pfs_inode_release(mnt, ni.ni_ino, ni.ni_btime, NULL);
	}

	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static void __attribute__((constructor))
init_pfs_rename_mtx()
{
	mutex_init(&rename_mtx);
}

static int
_pfs_rename(const char *oldpbdpath, const char *newpbdpath)
{
	int err;
	nameinfo_t oldni, newni;
	pfs_mount_t *mnt = NULL;

	err = pfs_namei_init(&oldni, oldpbdpath, PFS_INODET_NONE);
	if (err < 0)
		return err;
	err = pfs_namei_init(&newni, newpbdpath, PFS_INODET_NONE);
	if (err < 0)
		return err;

	/* Don't support rename between different PBD */
	if (strncmp(oldni.ni_pbd, newni.ni_pbd, PFS_MAX_PBDLEN) != 0)
		ERR_RETVAL(EXDEV);

	mnt = pfs_get_mount(oldni.ni_pbd);
	if (!mnt)
		ERR_RETVAL(ENODEV);
	err = pfs_memdir_xrename(mnt, &oldni, &newni);
	if (err >= 0 && newni.ni_ino != INVALID_INO
	    && newni.ni_ino != oldni.ni_ino) {
		if (newni.ni_tgt_type == PFS_INODET_DIR)
			err = pfs_inode_release(mnt, newni.ni_ino,
			    newni.ni_btime, NULL);
		else {
			PFS_ASSERT(newni.ni_tgt_type == PFS_INODET_FILE);
			err = pfs_file_release(mnt, newni.ni_ino,
			    newni.ni_btime);
		}
	}
	pfs_put_mount(mnt);
	return err;
}

static int
_pfs_access(const char *pbdpath, __attribute__((unused)) int amode)
{
	int err;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	if (amode != F_OK &&
	    (amode & (R_OK | W_OK | X_OK)) == 0) {
		ERR_RETVAL(EINVAL);
	}

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_NONE, &mnt, &ni);

	err = pfs_memdir_xlookup(mnt, &ni, 0);

	/*
	 * amode may be bitwise-inclusive OR of (R_OK, W_OK, X_OK)
	 * or F_OK.
	 * But, pfs doesn't has 'rwx' permissions, if file exists,
	 * return 0. Otherwise return -1.
	 */
	if (err) {
		err = (amode == F_OK ? -ENOENT : -EACCES);
	}

	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static int
_pfs_du(const char *pbdpath, int all, int depth, pfs_printer_t *printer)
{
	int err;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	GET_MOUNT_NAMEI(pbdpath, PFS_INODET_NONE, &mnt, &ni);

	err = pfs_memdir_xdu(mnt, &ni, all, 0, depth, printer, pbdpath);

	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static int
_pfs_fsync(int fd)
{
	return 0;
}

static ssize_t
_pfs_readlink(const char *pbdpath, char *buf, size_t bufsize)
{
	errno = EINVAL;
	return -1;
}

static int
_pfs_chmod(const char *pbdpath, mode_t mode)
{
	return 0;
}

static int
_pfs_fchmod(int fd, mode_t mode)
{
	return 0;
}

static int
_pfs_chown(const char *pbdpath, uid_t owner, gid_t group)
{
	return 0;
}

static int
_pfs_chdir(const char *path)
{
	int err;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	GET_MOUNT_NAMEI(path, PFS_INODET_DIR, &mnt, &ni);
	err = pfs_memdir_xsetwd(mnt, &ni);
	PUT_MOUNT_NAMEI(mnt, &ni);
	return err;
}

static int
_pfs_getwd(char *buf)
{
	int err;

	/*
	 * man getwd:
	 * The buf argument should be a pointer to an array at
	 * least PATH_MAX bytes long.
	 * If the length of the absolute pathname of the current
	 * working directory, including the terminating null byte,
	 * exceeds PATH_MAX bytes, NULL is returned, and errno is
	 * set to ENAMETOOLONG.
	 */
	err = pfs_memdir_xgetwd(buf, PATH_MAX);
	if (err == -ERANGE)
		err = -ENAMETOOLONG;
	return err;
}

static int
_pfs_getcwd(char *buf, size_t size)
{
	int err;

	err = pfs_memdir_xgetwd(buf, size);
	return err;
}

int
pfs_creat(const char *pbdpath, mode_t mode)
{
	int err = -EAGAIN;
	int fd = -1;
	MNT_STAT_API_BEGIN(MNT_STAT_API_CREAT);
	if (!pbdpath)
		err = -EINVAL;
	API_ENTER(INFO, "%s, %#x", PATH_ARG(pbdpath), mode);

	while (err == -EAGAIN) {
		fd = _pfs_open(pbdpath, O_CREAT | O_TRUNC | O_WRONLY, mode);
		err = fd < 0 ? fd : 0;
	}
	MNT_STAT_API_END(MNT_STAT_API_CREAT);

	API_EXIT(err);
	if (err < 0)
		return -1;
	fd = PFS_FD_MAKE(fd);
	return fd;
}

int
pfs_open(const char *pbdpath, int flags, mode_t mode)
{
	int err = -EAGAIN;
	int fd = -1;
	int open_type = MNT_STAT_API_OPEN;
	if (flags & O_CREAT)
		open_type = MNT_STAT_API_OPEN_CREAT;
	MNT_STAT_API_BEGIN(open_type);
	if (!pbdpath)
		err = -EINVAL;
	if (flags & (O_CREAT | O_TRUNC))
		API_ENTER(INFO, "%s, %#x, %#x", PATH_ARG(pbdpath), flags, mode);
	else
		API_ENTER(DEBUG, "%s, %#x, %#x", PATH_ARG(pbdpath), flags, mode);

	while (err == -EAGAIN) {
		fd = _pfs_open(pbdpath, flags, mode);
		err = fd < 0 ? fd : 0;
	}

	MNT_STAT_API_END(open_type);

	API_EXIT(err);
	if (err < 0) {
		pfs_dbgtrace("Failed to open: '%s'. Errno: %d.\n",
		    PATH_ARG(pbdpath), errno);
		return -1;
	}
	fd = PFS_FD_MAKE(fd);
	return fd;
}

ssize_t
pfs_read(int fd, void *buf, size_t len)
{
	int err = -EAGAIN;
	ssize_t rlen = -1;
	MNT_STAT_API_BEGIN(MNT_STAT_API_READ);
	if (!PFS_FD_ISVALID(fd))
		err = -EBADF;
	else if (!buf || (ssize_t)len < 0)
		err = -EINVAL;
	API_ENTER(DEBUG, "%d, %p, %lu", fd, buf, len);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		PFS_STAT_LATENCY_ENTRY();
		rlen = _pfs_read(fd, buf, len);
		err = rlen < 0 ? (int)rlen : 0;
		PFS_STAT_LATENCY(STAT_PFS_API_READ_DONE);
	}
	MNT_STAT_API_END_BANDWIDTH(MNT_STAT_API_READ, len);

	API_EXIT(err);
	if (err < 0)
		return -1;

	PFS_STAT_BANDWIDTH(STAT_PFS_API_READ_BW, len);
	return rlen;
}

ssize_t
pfs_write(int fd, const void *buf, size_t len)
{
	int err = -EAGAIN;
	ssize_t wlen = -1;
	bool fdok = PFS_FD_ISVALID(fd);
	MNT_STAT_API_BEGIN(MNT_STAT_API_WRITE);
	if (!fdok || !buf)
		err = !fdok ? -EBADF : -EINVAL;
	API_ENTER(DEBUG, "%d, %p, %lu", fd, buf, len);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		PFS_STAT_LATENCY_ENTRY();
		wlen = _pfs_write(fd, buf, len);
		err = wlen < 0 ? (int)wlen : 0;
		PFS_STAT_LATENCY(STAT_PFS_API_WRITE_DONE);
	}
	MNT_STAT_API_END_BANDWIDTH(MNT_STAT_API_WRITE, len);

	API_EXIT(err);
	if (err < 0)
		return -1;

	PFS_STAT_BANDWIDTH(STAT_PFS_API_WRITE_BW, len);
	return wlen;
}

ssize_t
pfs_pread(int fd, void *buf, size_t len, off_t offset)
{
	int err = -EAGAIN;
	ssize_t rlen = -1;
	MNT_STAT_API_BEGIN(MNT_STAT_API_PREAD);
	if (!PFS_FD_ISVALID(fd))
		err = -EBADF;
	else if (!buf)
		err = -EINVAL;
	else if (offset < 0 || (ssize_t)(offset + len) < 0)
		err = -EINVAL;
	API_ENTER(DEBUG, "%d, %p, %lu, %ld", fd, buf, len, offset);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		PFS_STAT_LATENCY_ENTRY();
		rlen = _pfs_pread(fd, buf, len, offset);
		err = rlen < 0 ? (int)rlen : 0;
		PFS_STAT_LATENCY(STAT_PFS_API_PREAD_DONE);
	}
	MNT_STAT_API_END_BANDWIDTH(MNT_STAT_API_PREAD, len);

	API_EXIT(err);
	if (err < 0)
		return -1;

	PFS_STAT_BANDWIDTH(STAT_PFS_API_PREAD_BW, len);
	return rlen;
}

ssize_t
pfs_pwrite(int fd, const void *buf, size_t len, off_t offset)
{
	int err = -EAGAIN;
	ssize_t wlen = -1;
	bool fdok = PFS_FD_ISVALID(fd);
	MNT_STAT_API_BEGIN(MNT_STAT_API_PWRITE);
	if (!fdok || !buf || offset < 0)
		err = !fdok ? -EBADF : -EINVAL;
	API_ENTER(DEBUG, "%d, %p, %lu, %ld", fd, buf, len, offset);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		PFS_STAT_LATENCY_ENTRY();
		wlen = _pfs_pwrite(fd, buf, len, offset);
		err = wlen < 0 ? (int)wlen : 0;
		PFS_STAT_LATENCY(STAT_PFS_API_PWRITE_DONE);
	}
	MNT_STAT_API_END_BANDWIDTH(MNT_STAT_API_PWRITE, len);

	API_EXIT(err);
	if (err < 0)
		return -1;

	PFS_STAT_BANDWIDTH(STAT_PFS_API_PWRITE_BW, len);
	return wlen;
}

int
pfs_close(int fd)
{
	int err = -EAGAIN;
	bool fdok = PFS_FD_ISVALID(fd);

	if (!fdok)
		err = -EBADF;
	API_ENTER(DEBUG, "%d", fd);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		err = _pfs_close(fd);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_truncate(const char *pbdpath, off_t len)
{
	int err = -EAGAIN;
	MNT_STAT_API_BEGIN(MNT_STAT_API_TRUNCATE);
	if (!pbdpath || len < 0)
		err = -EINVAL;
	API_ENTER(INFO, "%s, %ld", PATH_ARG(pbdpath), len);

	while (err == -EAGAIN) {
		err = _pfs_truncate(pbdpath, len);
	}
	MNT_STAT_API_END(MNT_STAT_API_TRUNCATE);

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_ftruncate(int fd, off_t len)
{
	int err = -EAGAIN;
	bool fdok = PFS_FD_ISVALID(fd);
	MNT_STAT_API_BEGIN(MNT_STAT_API_FTRUNCATE);
	if (!fdok || len < 0)
		err = !fdok ? -EBADF : -EINVAL;
	API_ENTER(INFO, "%d, %ld", fd, len);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		err = _pfs_ftruncate(fd, len);
	}
	MNT_STAT_API_END(MNT_STAT_API_FTRUNCATE);

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_unlink(const char *pbdpath)
{
	int err = -EAGAIN;
	MNT_STAT_API_BEGIN(MNT_STAT_API_UNLINK);
	if (!pbdpath)
		err = -EINVAL;
	API_ENTER(INFO, "%s", PATH_ARG(pbdpath));

	while (err == -EAGAIN) {
		mutex_lock(&unlink_mtx);
		err = _pfs_unlink(pbdpath);
		mutex_unlock(&unlink_mtx);
	}
	MNT_STAT_API_END(MNT_STAT_API_UNLINK);

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_stat(const char *pbdpath, struct stat *buf)
{
	int err = -EAGAIN;
	MNT_STAT_API_BEGIN(MNT_STAT_API_STAT);
	if (!pbdpath || !buf)
		err = -EINVAL;
	API_ENTER(DEBUG, "%s, %p", PATH_ARG(pbdpath), buf);

	while (err == -EAGAIN) {
		err = _pfs_stat(pbdpath, buf);
	}
	MNT_STAT_API_END(MNT_STAT_API_STAT);

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_fstat(int fd, struct stat *buf)
{
	int err = -EAGAIN;
	bool fdok = PFS_FD_ISVALID(fd);
	MNT_STAT_API_BEGIN(MNT_STAT_API_FSTAT);
	if (!fdok || !buf)
		err = !fdok ? -EBADF : -EINVAL;
	API_ENTER(DEBUG, "%d, %p", fd, buf);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		err = _pfs_fstat(fd, buf);
	}
	MNT_STAT_API_END(MNT_STAT_API_FSTAT);

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_posix_fallocate(int fd, off_t offset, off_t len)
{
	int err = -EAGAIN;
	bool fdok = PFS_FD_ISVALID(fd);
	MNT_STAT_API_BEGIN(MNT_STAT_API_FALLOCATE);
	if (!fdok || offset < 0 || len <= 0)
		err = !fdok ? -EBADF : -EINVAL;
	API_ENTER(DEBUG, "%d, %ld, %ld", fd, offset, len);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		err = _pfs_fallocate(fd, 0x0, offset, len);
	}
	MNT_STAT_API_END(MNT_STAT_API_FALLOCATE);

	//API_EXIT(err);
	if (err < 0)
		return -err;
	return 0;
}

int
pfs_fallocate(int fd, int mode, off_t offset, off_t len)
{
	int err = -EAGAIN;
	bool fdok = PFS_FD_ISVALID(fd);
	MNT_STAT_API_BEGIN(MNT_STAT_API_FALLOCATE);
	if (!fdok || offset < 0 || len <= 0)
		err = !fdok ? -EBADF : -EINVAL;
	API_ENTER(DEBUG, "%d, %#x, %ld, %ld", fd, mode, offset, len);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		err = _pfs_fallocate(fd, mode, offset, len);
	}
	MNT_STAT_API_END(MNT_STAT_API_FALLOCATE);

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

off_t
pfs_lseek(int fd, off_t offset, int whence)
{
	int err = -EAGAIN;
	off_t new_offset = -1;
	bool fdok = PFS_FD_ISVALID(fd);
	MNT_STAT_API_BEGIN(MNT_STAT_API_LSEEK);
	if (!fdok)
		err = -EBADF;
	API_ENTER(DEBUG, "%d, %ld, %d", fd, offset, whence);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		new_offset = _pfs_lseek(fd, offset, whence);
		err = new_offset < 0 ? (int)new_offset : 0;
	}
	MNT_STAT_API_END(MNT_STAT_API_LSEEK);

	API_EXIT(err);
	if (err < 0)
		return -1;
	return new_offset;
}

int
pfs_setxattr(const char *pbdpath, const char *name, const void *value,
    size_t size, int flags)
{
	int err = -EAGAIN;

	if (!pbdpath || !name || !value)
		err = -EINVAL;
	API_ENTER(DEBUG, "%s, %s, %p, %lu, %d", PATH_ARG(pbdpath), name, value, size, flags);

	while (err == -EAGAIN) {
		err = _pfs_setxattr(pbdpath, name, value, size, flags);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_mkstemp(char *tmpl)
{
	int err = -EAGAIN;
	int fd = -1;

	if (!tmpl)
		err = -EINVAL;
	API_ENTER(DEBUG, "%s", PATH_ARG(tmpl));

	while (err == -EAGAIN) {
		fd = _pfs_mkstemp(tmpl);
		err = fd < 0 ? fd : 0;
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return fd;
}

int
pfs_fmap(int fd, fmap_entry_t *fmapv, int count)
{
	int err = -EAGAIN;
	bool fdok = PFS_FD_ISVALID(fd);

	if (!fdok || count <= 0 || !fmapv)
		err = !fdok ? -EBADF : -EINVAL;
	API_ENTER(DEBUG, "%d, %p, %d", fd, fmapv, count);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		err = _pfs_fmap(fd, fmapv, count);
	}
	MNT_STAT_CLEAR();
	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_mkdir(const char *pbdpath, mode_t mode)
{
	int err = -EAGAIN;

	if (!pbdpath)
		err = -EINVAL;
	API_ENTER(INFO, "%s, %#x", PATH_ARG(pbdpath), mode);

	while (err == -EAGAIN) {
		err = _pfs_mkdir(pbdpath, mode);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

DIR *
pfs_opendir(const char *pbdpath)
{
	int err = -EAGAIN;
	DIR *dir = NULL;

	if (!pbdpath)
		err = -EINVAL;
	API_ENTER(INFO, "%s", PATH_ARG(pbdpath));

	while (err == -EAGAIN) {
		err = _pfs_opendir(pbdpath, &dir);
	}

	API_EXIT(err);
	if (err < 0)
		return NULL;

	dir = PFS_DIR_MAKE(dir);
	return dir;
}

struct dirent *
pfs_readdir(DIR *dir)
{
	int err = -EAGAIN;
	struct dirent *dent = NULL;
	bool dirok = PFS_DIR_CHECK(dir);

	if (!dirok)
		err = -EBADF;
	API_ENTER(DEBUG, "%p", dir);

	dir = PFS_DIR_RAW(dir);
	while (err == -EAGAIN) {
		err = _pfs_readdir(dir, &dent);
	}

	API_EXIT(err);
	if (err < 0)
		return NULL;
	return dent;
}

int
pfs_readdir_r(DIR *dir, struct dirent *entry, struct dirent **result)
{
	int err = -EAGAIN;
	bool dirok = PFS_DIR_CHECK(dir);

	if (!dirok || !entry || !result)
		err = !dirok ? -EBADF : -EINVAL;
	API_ENTER(DEBUG, "%p, %p, %p", dir, entry, result);

	dir = PFS_DIR_RAW(dir);
	while (err == -EAGAIN) {
		err = _pfs_readdir_r(dir, entry, result);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

struct direntplus *
pfs_readdirplus(DIR *dir)
{
	int err = -EAGAIN;
	struct direntplus *dplus = NULL;
	bool dirok = PFS_DIR_CHECK(dir);

	if (!dirok)
		err = -EBADF;
	API_ENTER(DEBUG, "%p", dir);

	dir = PFS_DIR_RAW(dir);
	while (err == -EAGAIN) {
		err = _pfs_readdirplus(dir, &dplus);
	}

	API_EXIT(err);
	if (err < 0)
		return NULL;
	return dplus;
}

int
pfs_closedir(DIR *dir)
{
	int err = -EAGAIN;
	bool dirok = PFS_DIR_CHECK(dir);

	if (!dirok)
		err = -EBADF;
	API_ENTER(DEBUG, "%p", dir);

	dir = PFS_DIR_RAW(dir);
	while (err == -EAGAIN) {
		err = _pfs_closedir(dir);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_rmdir(const char *pbdpath)
{
	int err = -EAGAIN;

	if (!pbdpath)
		err = -EINVAL;
	API_ENTER(INFO, "%s", PATH_ARG(pbdpath));

	while (err == -EAGAIN) {
		err = _pfs_rmdir(pbdpath);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_rename(const char *opath, const char *npath)
{
	int err = -EAGAIN;

	if (!opath || !npath)
		err = -EINVAL;
	API_ENTER(INFO, "%s, %s", PATH_ARG(opath), PATH_ARG(npath));

	while (err == -EAGAIN) {
		mutex_lock(&rename_mtx);
		err = _pfs_rename(opath, npath);
		mutex_unlock(&rename_mtx);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_chdir(const char *pbdpath)
{
	int err = -EAGAIN;

	if (!pbdpath)
		err = -EINVAL;
	API_ENTER(INFO, "%s", PATH_ARG(pbdpath));

	while (err == -EAGAIN) {
		err = _pfs_chdir(pbdpath);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

char *
pfs_getwd(char *buf)
{
	int err = -EAGAIN;

	if (!buf)
		err = -EINVAL;
	API_ENTER(DEBUG, "%p", buf);

	while (err == -EAGAIN) {
		err = _pfs_getwd(buf);
	}

	API_EXIT(err);
	if (err < 0)
		return NULL;
	return buf;
}

char *
pfs_getcwd(char *buf, size_t size)
{
	int err = -EAGAIN;

	if (!buf || size == 0)
		err = -EINVAL;
	API_ENTER(DEBUG, "%p, %zu", buf, size);

	while (err == -EAGAIN) {
		err = _pfs_getcwd(buf, size);
	}

	API_EXIT(err);
	if (err < 0)
		return NULL;
	return buf;
}

int
pfs_access(const char *pbdpath, int amode)
{
	int err = -EAGAIN;

	if (!pbdpath)
		err = -EINVAL;
	API_ENTER(DEBUG, "%s, %#x", PATH_ARG(pbdpath), amode);

	while (err == -EAGAIN) {
		err = _pfs_access(pbdpath, amode);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

int
pfs_fsync(int fd)
{
	int err = -EAGAIN;
	bool fdok = PFS_FD_ISVALID(fd);
	MNT_STAT_API_BEGIN(MNT_STAT_API_FSYNC);
	if (!fdok)
		err = -EBADF;
	API_ENTER(DEBUG, "%d", fd);

	fd = PFS_FD_RAW(fd);
	while (err == -EAGAIN) {
		err = _pfs_fsync(fd);
	}
	MNT_STAT_API_END(MNT_STAT_API_FSYNC);

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

ssize_t
pfs_readlink(const char *path, char *buf, size_t bufsize)
{
	return _pfs_readlink(path, buf, bufsize);
}

int
pfs_chmod(const char *path, mode_t mode)
{
	return _pfs_chmod(path, mode);
}

int
pfs_fchmod(int fd, mode_t mode)
{
	return _pfs_fchmod(fd, mode);
}

int
pfs_chown(const char *path, uid_t owner, gid_t group)
{
	return _pfs_chown(path, owner, group);
}

int
pfs_du(const char *pbdpath, int all, int depth, pfs_printer_t *printer)
{
	int err = -EAGAIN;

	if (!pbdpath || all < 0)
		err = -EINVAL;
	API_ENTER(INFO, "%s, %d, %d, %p", PATH_ARG(pbdpath), all, depth,
	    printer);

	while (err == -EAGAIN) {
		err = _pfs_du(pbdpath, all, depth, printer);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

static int
_pfs_fopen(const char *pbdpath, const char *mode, FILE **streamp)
{
	pfs_fstrm_t **fstrmp = (pfs_fstrm_t **)streamp;
	int err;

	err = pfs_fstrm_open(pbdpath, mode, fstrmp);
	return err;
}

static int
_pfs_fclose(FILE *stream)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	int err;

	err = pfs_fstrm_xclose(fstrm);
	return err;
}

static int
_pfs_fgetc(FILE *stream, char *c)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	size_t nitem;
	int err;

	err = pfs_fstrm_xread(fstrm, c, 1, 1, &nitem);
	if (err == 0 && nitem == 0)
		err = EOF;
	PFS_ASSERT(err < 0 || nitem == 1);
	return err;
}

static int
_pfs_fread(FILE *stream, void *buf, size_t size, size_t nmemb, size_t *nitemp)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	int err;

	err = pfs_fstrm_xread(fstrm, buf, size, nmemb, nitemp);
	return err;
}

static int
_pfs_fwrite(FILE *stream, const void *buf, size_t size, size_t nmemb, size_t *nitemp)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	int err;

	err = pfs_fstrm_xwrite(fstrm, buf, size, nmemb, nitemp);
	return err;
}

static int
_pfs_fflush(FILE *stream)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	int err;

	err = pfs_fstrm_xflush(fstrm);
	return err;
}

static int
_pfs_rewind(FILE *stream)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	off_t newoff;
	int err;

	newoff = pfs_fstrm_xseekoff(fstrm, 0, SEEK_SET, true, true);
	err = newoff < 0 ? newoff : 0;
	return err;
}

static int
_pfs_fseek(FILE *stream, off_t offset, int whence)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	off_t newoff;
	int err;

	newoff = pfs_fstrm_xseekoff(fstrm, offset, whence, true, false);
	err = newoff < 0 ? newoff : 0;
	return err;
}

static int
_pfs_ftell(FILE *stream, off_t *offset)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	off_t newoff;
	int err;

	newoff = pfs_fstrm_xseekoff(fstrm, 0, SEEK_CUR, false, false);
	err = newoff < 0 ? newoff : 0;
	if (err < 0)
		return err;
	*offset = newoff;
	return 0;
}

static int
_pfs_feof(FILE *stream, bool *iseof)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	int err;

	err = pfs_fstrm_xeof(fstrm, iseof);
	return err;
}

static int
_pfs_fileno(FILE *stream, int *fileno)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	int err;

	err = pfs_fstrm_xfileno(fstrm, fileno);
	return err;
}

static int
_pfs_ferror(FILE *stream, bool *haserr)
{
	pfs_fstrm_t *fstrm = (pfs_fstrm_t *)stream;
	int err;

	err = pfs_fstrm_xerror(fstrm, haserr);
	return err;
}

FILE *
pfs_fopen(const char *pbdpath, const char *mode)
{
	int err = -EAGAIN;
	FILE *stream = NULL;

	if (!pbdpath || !mode)
		err = -EINVAL;
	API_ENTER(INFO, "%s, %s", PATH_ARG(pbdpath), PATH_ARG(mode));

	while (err == -EAGAIN) {
		err = _pfs_fopen(pbdpath, mode, &stream);
	}

	API_EXIT(err);
	if (err < 0)
		return NULL;

	stream = PFS_STRM_MAKE(stream);
	return stream;
}

int
pfs_fclose(FILE *stream)
{
	int err = -EAGAIN;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	API_ENTER(DEBUG, "%p", stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_fclose(stream);
	}

	API_EXIT(err);
	if (err < 0)
		return EOF;
	return 0;
}

int
pfs_fgetc(FILE *stream)
{
	int err = -EAGAIN;
	char rchar;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	API_ENTER(DEBUG, "%p", stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_fgetc(stream, &rchar);
	}

	API_EXIT(err);
	if (err < 0)
		return err;
	return (int)rchar;
}

size_t
pfs_fread(void *buf, size_t size, size_t nmemb, FILE *stream)
{
	int err = -EAGAIN;
	size_t nitem = 0;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	else if (!buf)
		err = -EINVAL;
	API_ENTER(DEBUG, "%p, %lu, %lu, %p", buf, size, nmemb, stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_fread(stream, buf, size, nmemb, &nitem);
	}

	API_EXIT(err);
	return nitem;
}

size_t
pfs_fwrite(const void *buf, size_t size, size_t nmemb, FILE *stream)
{
	int err = -EAGAIN;
	size_t nitem = 0;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	else if (!buf)
		err = -EINVAL;
	API_ENTER(DEBUG, "%p, %lu, %lu, %p", buf, size, nmemb, stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_fwrite(stream, buf, size, nmemb, &nitem);
	}

	API_EXIT(err);
	return nitem;
}

int
pfs_fflush(FILE *stream)
{
	int err = -EAGAIN;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	API_ENTER(DEBUG, "%p", stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_fflush(stream);
	}

	API_EXIT(err);
	if (err < 0)
		return EOF;
	return 0;
}

void
pfs_rewind(FILE *stream)
{
	int err = -EAGAIN;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	API_ENTER(DEBUG, "%p", stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_rewind(stream);
	}

	API_EXIT(err);
}

int
pfs_fseek(FILE *stream, off_t offset, int whence)
{
	int err = -EAGAIN;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	API_ENTER(DEBUG, "%p, %lu, %lu", stream, offset, whence);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_fseek(stream, offset, whence);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return 0;
}

off_t
pfs_ftell(FILE *stream)
{
	int err = -EAGAIN;
	off_t offset = -1;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	API_ENTER(DEBUG, "%p", stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_ftell(stream, &offset);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return offset;
}

int
pfs_feof(FILE *stream)
{
	int err = -EAGAIN;
	bool iseof = false;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	API_ENTER(DEBUG, "%p", stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_feof(stream, &iseof);
	}

	API_EXIT(err);
	if (iseof)
		return 1;
	return 0;
}

int
pfs_fileno(FILE *stream)
{
	int err = -EAGAIN;
	int fileno = -1;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
	API_ENTER(DEBUG, "%p", stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_fileno(stream, &fileno);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	return fileno;
}

int
pfs_ferror(FILE *stream)
{
	int err = -EAGAIN;
	bool haserr = true;

	if (!PFS_STRM_ISVALID(stream))
		err = -EBADF;
       API_ENTER(DEBUG, "%p", stream);

	stream = PFS_STRM_RAW(stream);
	while (err == -EAGAIN) {
		err = _pfs_ferror(stream, &haserr);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;
	if (haserr)
		return 1;
	return 0;
}
