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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pfs_impl.h"
#include "pfs_namei.h"
#include "pfs_inode.h"
#include "pfs_mount.h"
#include "pfs_trace.h"
#include "pfs_api.h"
#include "pfsd_api.h"
#include "pfsd_zlog.h"
#include "pfs_file.h"

#include "pfs_file.cc"

#define OFF_MAX ~((off_t)1 << (sizeof(off_t) * 8 - 1))
#define INVALID_INO  (~0LL)

#define PATH_ARG(path)						\
	(path) ? (path) : "NULL"

#define	API_ENTER(level, fmt, ...) do {				\
	if (err != 0 && err != -EAGAIN) {			\
		pfsd_error("%s invalid args(" fmt ")",	\
			__func__, __VA_ARGS__);			\
	} else if (PFS_TRACE_##level == PFS_TRACE_INFO) {	\
		pfsd_info("%s(" fmt ")",			\
			__func__, __VA_ARGS__);			\
	} else if (PFS_TRACE_##level == PFS_TRACE_DBG) {	\
		pfsd_debug("%s(" fmt ")",			\
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
	0,	/* sentinel */
};

enum {
	GTYPE_MOUNT_NAMEI = 1,
	GTYPE_MOUNT_FILE,
	GTYPE_MOUNT_DIR,
};

#define	GET_MOUNT_NAMEI(pbdpath, type, mp, np)	do {	\
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


#define	PUT_MOUNT_NAMEI(mnt, ni) do {			\
	char _a[_gtype == GTYPE_MOUNT_NAMEI ? 1 : -1]	\
		__attribute__((unused));		\
	/* nothing to do for ni */			\
	if (mnt) {					\
		pfs_put_mount(mnt);			\
		mnt = NULL;				\
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

/* return err */
static int
pfsd_file_open_impl(pfs_mount_t *mnt, pfs_ino_t ino, pfs_inode_t **out_inode,
    uint64_t btime)
{
	int err = 0;

	*out_inode = NULL;
	pfs_inode_t* in = pfs_inode_get(mnt, ino);
	if (in == NULL)
		ERR_GOTO(ENOMEM, out);

	*out_inode = in;

	pfs_inode_lock(in);
	err = pfs_inode_sync_first(in, PFS_INODET_NONE, btime, false);
	pfs_inode_unlock(in);

	if (err < 0)
		goto out;

	return err;

out:
	if (in) {
		pfs_inode_put(in);
		in = NULL;
	}

	return err;
}

static int
pfsd_file_xftruncate(pfs_mount_t *mnt, pfs_inode_t *in, off_t len, uint64_t btime)
{
	ssize_t fsize;
	int err = 0;

	PFS_ASSERT(len >= 0);

	/*
	 * pfs_file_truncate() may not truncate file size to len
	 * if truncated size is too large, so we should check whether
	 * it needs to retry.
	 */
	do {
		tls_write_begin(mnt);
		pfs_inode_lock(in);
		fsize = pfs_file_truncate(in, len, btime);
		err = fsize < 0 ? fsize : 0;
		pfs_inode_unlock(in);
		tls_write_end(err);
	} while (err == 0 && fsize != len);

	return err;
}

static int
_pfsd_open_svr(const char *pbdpath, int type, int flags, int64_t *ino,
    uint64_t *btime, int32_t *file_type)
{
	int err = 0;

	nameinfo_t ni;
	pfs_mount_t *mnt;

	MNT_STAT_BEGIN();
	GET_MOUNT_NAMEI(pbdpath, type, &mnt, &ni);
	*file_type = pfs_get_file_type(ni.ni_path);
	pfs_mntstat_set_file_type(*file_type);

	pfs_inode_t *in = NULL;
	err = pfs_memdir_xlookup(mnt, &ni, flags);
	if (err == 0)
		err = pfsd_file_open_impl(mnt, ni.ni_ino, &in, ni.ni_btime);

	/*
	 *  handle truncate and append
	 */
	if (err == 0 && (flags & O_TRUNC) != 0) {
		/*
		 * The file data is cleared and there must
		 * be no file hole.
		 */
		err = pfsd_file_xftruncate(mnt, in, 0, ni.ni_btime);
	}

	if (in != NULL)
		pfs_put_inode(mnt, in);
	*btime = ni.ni_btime;
	*ino = ni.ni_ino;
	PUT_MOUNT_NAMEI(mnt, ni);
	if (flags & O_CREAT)
		MNT_STAT_END(MNT_STAT_FILE_OPEN_CREAT);
	else
		MNT_STAT_END(MNT_STAT_FILE_OPEN);
	return err;
}

int64_t
pfsd_open_svr(const char *pbdpath, int flags, mode_t mode,
    uint64_t *btime, int32_t *file_type)
{
	int err = -EAGAIN;
	int64_t ino = -1;

	if (!pbdpath)
		err = -EINVAL;

	if (flags & (O_CREAT | O_TRUNC))
		API_ENTER(INFO, "%s, %#x, %#x", PATH_ARG(pbdpath), flags, mode);
	else
		API_ENTER(DEBUG, "%s, %#x, %#x", PATH_ARG(pbdpath), flags, mode);

	int type = PFS_INODET_NONE;
	if (flags & (O_CREAT | O_TRUNC)) {
		/* O_CREAT and O_TRUNC are only for file */
		type = PFS_INODET_FILE;
	}

	while (err == -EAGAIN) {
		err = _pfsd_open_svr(pbdpath, type, flags, &ino, btime, file_type);
	}

	API_EXIT(err);
	if (err < 0) {
		if (errno != ENOENT)
			pfs_etrace("Failed to open: '%s'. Errno: %d.\n",
			    PATH_ARG(pbdpath), errno);
		return -1;
	}

	return ino;
}

int64_t
pfsd_creat_svr(const char *pbdpath, mode_t m, uint64_t *btime, int32_t *file_type)
{
	return pfsd_open_svr(pbdpath, O_CREAT, m, btime, file_type);
}

static ssize_t
_pfsd_pread_svr(pfs_mount_t *mnt, pfs_inode_t *in, void *buf, size_t len,
    off_t offset, uint64_t btime)
{
	ssize_t rlen = -1;

	if (len == 0)
		return 0;

	int err;
	tls_read_begin(mnt);
	pfs_inode_lock(in);
	rlen = pfs_file_read(in, buf, len, offset, true, btime);
	err = rlen < 0 ? rlen : 0;
	pfs_inode_unlock(in);
	tls_read_end(err);

	return rlen;
}

ssize_t
pfsd_pread_svr(pfs_mount_t *mnt, pfs_inode_t *inode, void *buf, size_t len,
    off_t off, uint64_t btime)
{
	assert (mnt && inode && off >= 0);

	int err = -EAGAIN;
	ssize_t rlen = -1;

	API_ENTER(DEBUG, "%ld, %p, %lu, %ld", inode->in_ino, buf, len, off);

	while (err == -EAGAIN) {
		PFS_STAT_LATENCY_ENTRY();
		rlen = _pfsd_pread_svr(mnt, inode, buf, len, off, btime);
		err = rlen < 0 ? (int)rlen : 0;
		PFS_STAT_LATENCY(STAT_PFS_API_PREAD_DONE);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;

	PFS_STAT_BANDWIDTH(STAT_PFS_API_PREAD_BW, len);
	return rlen;
}

static int
pfsd_file_xfallocate(pfs_mount_t *mnt, pfs_inode_t *in, off_t offset,
    size_t len, int mode, uint64_t btime)
{
	off_t off2;
	ssize_t newfsize;
	int err;

	MNT_STAT_BEGIN();
	off2 = offset;

	PFS_ASSERT(off2 >= 0 || off2 == OFFSET_FILE_SIZE);

	tls_write_begin(mnt);
	pfs_inode_lock(in);
	newfsize = pfs_file_allocate(in, off2, len, mode, btime);
	err = newfsize < 0 ? newfsize : 0;
	pfs_inode_unlock(in);
	tls_write_end(err);
	MNT_STAT_END(MNT_STAT_FILE_FALLOCATE);
	return err;
}

static ssize_t
pfsd_file_xpwrite(pfs_mount_t *mnt, pfs_inode_t *in, int flags, const void *buf,
    size_t len, off_t off, ssize_t *file_len, uint64_t btime)
{
	ssize_t wlen;
	int err;
	off_t off2 = off;

	if (len <= 0)
		return 0;

	MNT_STAT_BEGIN();
	pfs_inode_lock(in);
	wlen = pfs_file_write(in, buf, len, &off2, true, btime);
	err = wlen < 0 ? wlen : 0;
	pfs_inode_unlock(in);

	/*
	 * File with O_APPEND flag can't tolerate ETIMEDOUT error,
	 * because new file size may be already written into journal
	 * even we get an ETIMEDOUT error. Then retrying append
	 * operations results in multiple writing.
	 */
	tls_write_begin_flags(mnt, flags & O_APPEND);
	pfs_inode_lock(in);

	/*
	 * Always transform writemodify to tx if it's not empty.
	 * So if err<0 or commit failed, the rollback of tx will
	 * restore metadata and the callback will clear sync events.
	 */
	err |= pfs_inode_writemodify_commit(in);
	if (err == 0)
		*file_len = in->in_size2;
	pfs_inode_unlock(in);
	tls_write_end(err);

	if (err)
		wlen = err;
	MNT_STAT_END(MNT_STAT_FILE_WRITE);
	return wlen;
}

static ssize_t
_pfsd_pwrite_svr(pfs_mount_t *mnt, pfs_inode_t *in, int flags, const void *buf,
    size_t len, off_t offset, ssize_t *file_size, uint64_t btime)
{
	int err;
	ssize_t wlen = -1;

	if (len == 0)
		return 0;

	if ((size_t)(OFF_MAX - offset) < len)
		return -EFBIG;

	err = pfsd_file_xfallocate(mnt, in, offset, len, FALLOC_FL_KEEP_SIZE,
	    btime);
	if (err < 0)
		return err;

	wlen = pfsd_file_xpwrite(mnt, in, flags, buf, len, offset, file_size,
	    btime);
	return wlen;
}

ssize_t
pfsd_pwrite_svr(pfs_mount_t *mnt, pfs_inode_t *inode, int flags,
    const void *buf, size_t len, off_t off, ssize_t *file_size, uint64_t btime)
{
	assert (mnt && inode);

	int err = -EAGAIN;
	ssize_t wlen = -1;

	API_ENTER(DEBUG, "%ld, %p, %lu, %ld", inode->in_ino, buf, len, off);

	while (err == -EAGAIN) {
		PFS_STAT_LATENCY_ENTRY();
		wlen = _pfsd_pwrite_svr(mnt, inode, flags, buf, len, off,
		    file_size, btime);
		err = wlen < 0 ? (int)wlen : 0;
		PFS_STAT_LATENCY(STAT_PFS_API_PWRITE_DONE);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;

	PFS_STAT_BANDWIDTH(STAT_PFS_API_PWRITE_BW, len);
	return wlen;
}

int
pfsd_ftruncate_svr(pfs_mount_t *mnt, pfs_inode_t *in, off_t len, uint64_t btime)
{
	assert (mnt && in);
	int err = -EAGAIN;
	API_ENTER(INFO, "%ld, %ld", in->in_ino, len);

	while (err == -EAGAIN) {
		err = pfsd_file_xftruncate(mnt, in, len, btime);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;

	return 0;
}

int
pfsd_unlink_svr(const char *pbdpath)
{
	return pfs_unlink(pbdpath);
}

int
pfsd_truncate_svr(const char *pbdpath, off_t len)
{
	int err = -EAGAIN;
	if (!pbdpath || len < 0)
		err = -EINVAL;

	API_ENTER(INFO, "%s, %ld", PATH_ARG(pbdpath), len);

	int type = PFS_INODET_FILE;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	while (err == -EAGAIN) {
		GET_MOUNT_NAMEI(pbdpath, type, &mnt, &ni);

		pfs_inode_t* in = NULL;
		err = pfs_memdir_xlookup(mnt, &ni, 0);
		if (err == 0)
			err = pfsd_file_open_impl(mnt, ni.ni_ino, &in,
			    ni.ni_btime);

		if (err == 0)
			err = pfsd_file_xftruncate(mnt, in, len, ni.ni_btime);

		if (in != NULL)
			pfs_put_inode(mnt, in);
		PUT_MOUNT_NAMEI(mnt, ni);
	}

	API_EXIT(err);

	if (err < 0)
		return -1;

	return 0;
}


static int
pfsd_file_xstat(pfs_mount_t *mnt, pfs_inode_t *in, struct stat *st,
    uint64_t btime)
{
	int err;

	MNT_STAT_BEGIN();
	tls_read_begin(mnt);
	pfs_inode_lock(in);
	err = pfs_file_stat(in, st, btime);
	pfs_inode_unlock(in);
	tls_read_end(err);
	MNT_STAT_END(MNT_STAT_FILE_FSTAT);
	return err;
}

int
pfsd_fstat_svr(pfs_mount_t *mnt, pfs_inode_t *in, struct stat *buf,
    uint64_t btime)
{
	assert (mnt && in && buf);
	int err = -EAGAIN;

	API_ENTER(DEBUG, "%ld, %p", in->in_ino, buf);

	memset(buf, 0, sizeof(struct stat));
	while (err == -EAGAIN) {
		err = pfsd_file_xstat(mnt, in, buf, btime);
	}

	API_EXIT(err);
	if (err < 0)
		return -1;

	return 0;
}

static int
_pfsd_stat_svr(const char *pbdpath, struct stat *buf)
{
	int type = PFS_INODET_NONE;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;
	int err = 0;

	GET_MOUNT_NAMEI(pbdpath, type, &mnt, &ni);

	pfs_inode_t *in = NULL;
	err = pfs_memdir_xlookup(mnt, &ni, 0);
	if (err == 0)
		err = pfsd_file_open_impl(mnt, ni.ni_ino, &in, ni.ni_btime);

	if (err == 0)
		err = pfsd_file_xstat(mnt, in, buf, ni.ni_btime);

	if (in != NULL)
		pfs_put_inode(mnt, in);

	PUT_MOUNT_NAMEI(mnt, ni);
	return err;
}

int
pfsd_stat_svr(const char *pbdpath, struct stat *buf)
{
	int err = -EAGAIN;
	if (!pbdpath || !buf)
		err = -EINVAL;

	API_ENTER(DEBUG, "%s, %p", PATH_ARG(pbdpath), buf);

	memset(buf, 0, sizeof(*buf));
	while (err == -EAGAIN) {
		err = _pfsd_stat_svr(pbdpath, buf);
	}

	API_EXIT(err);

	if (err < 0)
		return -1;

	return 0;
}

int
pfsd_fallocate_svr(pfs_mount_t *mnt, pfs_inode_t *in, off_t off, off_t len,
    int mode, uint64_t btime)
{
	assert (mnt && in && off >= 0);

	int err = -EAGAIN;

	API_ENTER(INFO, "%ld %ld %ld", in->in_ino, off, len);
	while (err == -EAGAIN) {
		err = pfsd_file_xfallocate(mnt, in, off, len,
		    FALLOC_PFSFL_FIXED_OFFSET | mode, btime);
	}

	API_EXIT(err);
	return err;
}

extern
void pfs_direntry_getname(pfs_mount_t *mnt, pfs_direntry_phy_t *headde, 
    char *buf,size_t len);

static ssize_t
pfsd_dir_path_impl(pfs_mount_t *mnt, int64_t deno, char *path, size_t len)
{
	ssize_t nused;
	size_t n, namelen;
	pfs_direntry_phy_t *de;
	pfs_inode_phy_t *dirin;
	char namebuf[PFS_MAX_NAMELEN];

	if (deno == 0) {
		n = snprintf(path, len, "/%s", mnt->mnt_pbdname);
		return (n >= len) ?  -ENAMETOOLONG : n;
	}

	de = pfs_meta_get_direntry(mnt, deno, NULL);
	if (de->de_ino == INVALID_INO)
		ERR_RETVAL(ENOENT);
	pfs_direntry_getname(mnt, de, namebuf, sizeof(namebuf));
	namelen = 1 + strlen(namebuf); /* "/" + dename */
	if (namelen >= len)
		ERR_RETVAL(ENAMETOOLONG);

	dirin = pfs_meta_get_inode(mnt, de->de_dirino, NULL);
	nused = pfsd_dir_path_impl(mnt, dirin->in_deno, path, len - namelen);
	if (nused < 0)
		return nused;

	PFS_ASSERT(nused >= 0 && namelen + nused < len);
	n = snprintf(&path[nused], len - nused, "/%s", namebuf);
	PFS_VERIFY(n == namelen);
	return nused + namelen;
}

static int
pfsd_dir_path(pfs_mount_t *mnt, int64_t ino, char *path, size_t len)
{
	int err;
	ssize_t nused;
	pfs_inode_phy_t *in;

	in = pfs_meta_get_inode(mnt, ino, NULL);
	if (in->in_type == PFS_INODET_NONE) {
		ERR_RETVAL(ENOENT);
	}

	nused = pfsd_dir_path_impl(mnt, in->in_deno, path, len);
	err = (nused < 0) ? (int)nused : 0;
	if (err < 0)
		return err;

	/* ROOT_DIR should add one slash at the end */
	PFS_ASSERT((size_t)nused == strlen(path));
	if (ino == 0) {
		if ((size_t)nused + 1 >= len)
			ERR_RETVAL(ENAMETOOLONG);
		path[nused] = '/';
		path[nused + 1] = '\0';
	}

	return 0;
}

static int
_pfsd_chdir_svr(const char *pbdpath)
{
	int err = 0;
	int type = PFS_INODET_DIR;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;
	pfs_inode_t *in;

	GET_MOUNT_NAMEI(pbdpath, type, &mnt, &ni);

	tls_read_begin(mnt);
	err = pfs_path_enter(mnt, &ni, 0, NULL, &in, NULL);
	if (err == 0) {
		pfs_inode_lock(in);
		err = pfs_inode_sync_first(in, ni.ni_tgt_type, ni.ni_btime, false);
		if (err == 0)
			err = pfs_path_check(mnt, &ni, ni.ni_tgt_type);
		if (err == 0) {
			/* get absoulte path of work directory */
			char pathbuf[PFS_MAX_PATHLEN];
			err = pfsd_dir_path(mnt, ni.ni_ino, pathbuf, PFS_MAX_PATHLEN);
		}
		pfs_inode_unlock(in);
	}
	pfs_path_exit(&ni);
	tls_read_end(err);

	PUT_MOUNT_NAMEI(mnt, ni);
	return err;
}

int
pfsd_chdir_svr(const char *pbdpath)
{
	int err = -EAGAIN;
	if (!pbdpath)
		err = -EINVAL;

	API_ENTER(INFO, "%s", PATH_ARG(pbdpath));

	while (err == -EAGAIN) {
		err = _pfsd_chdir_svr(pbdpath);
	}

	API_EXIT(err);

	if (err < 0)
		return -1;

	return 0;
}

static int
pfsd_dir_open(pfs_mount_t *mnt, nameinfo_t *ni, int64_t *deno, int64_t *first_ino)
{
	int err;
	pfs_inode_phy_t *phyin;
	pfs_inode_t *in;

	err = pfs_path_enter(mnt, ni, 0, NULL, &in, NULL);
	if (err == 0) {
		pfs_inode_lock(in);
		err = pfs_inode_sync_first(in, ni->ni_tgt_type, ni->ni_btime, false);
		if (err == 0)
			err = pfs_path_check(mnt, ni, ni->ni_tgt_type);
		if (err == 0) {
			phyin = pfs_meta_get_inode(mnt, ni->ni_ino, NULL);
			PFS_VERIFY(phyin != NULL);
			PFS_ASSERT((phyin->in_size % sizeof(pfs_metaobj_phy_t)) == 0);
			*deno = ni->ni_ino;
			*first_ino = MONO_FIRST(phyin);
		}
		pfs_inode_unlock(in);
	}
	pfs_path_exit(ni);

	return err;
}

int
pfsd_opendir_svr(const char *pbdpath, int64_t *deno, int64_t *first_ino)
{
	int err = -EAGAIN;

	if (!pbdpath)
		err = -EINVAL;

	API_ENTER(INFO, "%s", PATH_ARG(pbdpath));

	int type = PFS_INODET_DIR;
	nameinfo_t ni;
	pfs_mount_t *mnt = NULL;

	while (err == -EAGAIN) {
		GET_MOUNT_NAMEI(pbdpath, type, &mnt, &ni);

		MNT_STAT_BEGIN();
		tls_read_begin(mnt);
		err = pfsd_dir_open(mnt, &ni, deno, first_ino);
		tls_read_end(err);

		PUT_MOUNT_NAMEI(mnt, ni);
		MNT_STAT_END(MNT_STAT_DIR_OPENDIR);
	}

	API_EXIT(err);

	if (err < 0)
		return -1;

	return 0;
}


static pfs_direntry_phy_t* 
pfsd_dirent_ino(pfs_mount_t *mnt, int64_t dino, int64_t ino)
{
	pfs_direntry_phy_t *de = pfs_meta_get_direntry(mnt, ino, NULL);

	if (de->de_ino != INVALID_INO && de->de_dirino == dino)
		return de;

	return NULL;
}

int
pfsd_readdir_svr(pfs_mount_t *mnt, int64_t dino, int64_t ino, uint64_t offset, 
    struct dirent *entry, int64_t *next_ino)
{
	int err = 0;
	pfs_direntry_phy_t *de = NULL;
	int64_t cino = ino;
	pfs_inode_phy_t *dirin = NULL;

	MNT_STAT_BEGIN();
	tls_read_begin(mnt);
	/* Try got info for cino at offset */
	de = pfsd_dirent_ino(mnt, dino, cino);
	if (de == NULL) {
		/* cino is deleted, now open dirin's dentry-list to traverse */
		if (!dirin)
			dirin = pfs_meta_get_inode(mnt, dino, NULL);

		if (!dirin || dirin->in_deno == INVALID_DENO) {
			/* If directory lost, treat it as EOF, do NOT set errno as ext4 */
			err = PFSD_DIR_END;
			de = NULL;
		} else {
			uint64_t off = 0;
			uint64_t deno;
			/* cino at offset is deleted, so try relocate to new ino at offset */
			for (deno = MONO_FIRST(dirin); off < offset && MONO_VALID(deno); deno = MONO_NEXT(de)) {
				off++;
				de = pfs_meta_get_direntry(mnt, deno, NULL);
				assert (de);
			}

			if (!MONO_VALID(deno)) {
				/* too many files are deleted, offset is not exist */
				err = PFSD_DIR_END;
				de = NULL;
			}
		}
	}

	if (de) {
		pfs_inode_phy_t *in = pfs_meta_get_inode(mnt, de->de_ino, NULL);
		entry->d_ino = de->de_ino;
		entry->d_type = in->in_type;
		pfs_direntry_getname(mnt, de, entry->d_name, sizeof(entry->d_name));

		*next_ino = MONO_NEXT(de);
	}

	tls_read_end(err);
	MNT_STAT_END(MNT_STAT_DIR_READDIR);

	return err;
}

/* SEEK_END */
static off_t
pfsd_file_xlseek(pfs_mount_t *mnt, pfs_inode_t *in, off_t offset,
    uint64_t btime)
{
	int err;
	off_t curoff = -1;

	pfs_file_t file;
	file.f_inode = in;
	file.f_btime = btime;

	tls_read_begin(mnt);
	curoff = pfs_file_lseek(&file, offset, SEEK_END);
	err = curoff < 0 ? curoff : 0;
	tls_read_end(err);

	return curoff;
}

off_t
pfsd_lseek_end_svr(pfs_mount_t* mnt, pfs_inode_t* in, off_t off, uint64_t btime)
{
	assert (in);

	off_t newoff = -1;
	int err = -EAGAIN;

	API_ENTER(DEBUG, "%ld, %ld", in->in_ino, off);

	while (err == -EAGAIN) {
		newoff = pfsd_file_xlseek(mnt, in, off, btime);
		err = newoff < 0 ? newoff : 0;
	}

	API_EXIT(err);
	return newoff;
}

