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
#include <fcntl.h>
#include <stdlib.h>

#include "pfs_fstream.h"
#include "pfs_api.h"
#include "pfs_impl.h"
#include "pfs_memory.h"
#include "pfs_option.h"

#define	FSTRM_BUFSIZE		(4096)

#define	CHECK_FILE(fp)					\
	if (pfs_fstrmf_check(fp, FSTRMF_MAGIC))		\
		ERR_RETVAL(EINVAL)

enum {
	FSTRMF_MAGIC			= 0xFFFF0000,
	/* buffer type */
	FSTRMF_UNBUFFERED		= 0x1,
	FSTRMF_LINE_BUF			= 0x2,
	/* status bit */
	FSTRMF_EOF_SEEN			= 0x4,
	FSTRMF_ERR_SEEN			= 0x8,
	/* rwa mode */
	FSTRMF_READABLE			= 0x10,
	FSTRMF_WRITABLE			= 0x20,
	FSTRMF_IS_APPENDING		= 0x40,	// unused
	/* link in chain */
	FSTRMF_LINKED			= 0x80,
	/* unimplemented */
	/*
	FSTRMF_USER_BUF
	FSTRMF_DELETE_DONT_CLOSE
	FSTRMF_IN_BACKUP
	FSTRMF_TIED_PUT_GET
	FSTRMF_CURRENTLY_PUTTING
	FSTRMF_IS_FILEBUF
	FSTRMF_BAD_SEEN
	FSTRMF_USER_LOCK
	*/
};

enum {
	FSTRM_IO_SYNC			= 0,
	FSTRM_IO_READING		= 1,
	FSTRM_IO_WRITING		= 2,
};

static pfs_fstrm_t *		fstrm_chain = NULL;
static pthread_mutex_t		fstrm_chain_lock = PTHREAD_MUTEX_INITIALIZER;

static inline void
pfs_fstrmf_set(pfs_fstrm_t *fp, uint64_t flags, uint64_t mask)
{
	/* set bits exclusively in subgroup */
	fp->f_flags = ((fp->f_flags & ~(mask)) | (flags & mask));
}

static inline bool
pfs_fstrmf_check(pfs_fstrm_t *fp, uint64_t flags)
{
	return ((fp->f_flags & flags) == flags);
}

static void
pfs_fstrmf_set_buftype(pfs_fstrm_t *fp, int type)
{
	int mask;
	uint64_t flags;

	mask = FSTRMF_UNBUFFERED|FSTRMF_LINE_BUF;
	switch (type) {
	case _IONBF:
		flags = FSTRMF_UNBUFFERED;
		break;

	case _IOLBF:
		flags = FSTRMF_LINE_BUF;
		break;

	case _IOFBF:
		flags = 0;
		break;

	default:
		pfs_etrace("invalid buf type %d\n", type);
		PFS_ASSERT("unreachable" == NULL);
	}

	pfs_fstrmf_set(fp, flags, mask);
}

static inline void
pfs_fstrmf_set_eof(pfs_fstrm_t *fp)
{
	pfs_fstrmf_set(fp, FSTRMF_EOF_SEEN, FSTRMF_EOF_SEEN);
}

static inline void
pfs_fstrmf_unset_eof(pfs_fstrm_t *fp)
{
	pfs_fstrmf_set(fp, 0, FSTRMF_EOF_SEEN);
}

/*
 * error bit is set on the spot
 */
static inline void
pfs_fstrmf_set_err(pfs_fstrm_t *fp)
{
	pfs_fstrmf_set(fp, FSTRMF_ERR_SEEN, FSTRMF_ERR_SEEN);
}

static inline void
pfs_fstrmf_unset_err(pfs_fstrm_t *fp)
{
	pfs_fstrmf_set(fp, 0, FSTRMF_EOF_SEEN);
}

static void
pfs_fstrmf_set_rwmode(pfs_fstrm_t *fp, int accmode)
{
	uint64_t flags;
	int mask;

	flags = 0;
	mask = FSTRMF_READABLE|FSTRMF_WRITABLE|FSTRMF_IS_APPENDING;
	switch (accmode) {
	case O_RDONLY:
		flags = FSTRMF_READABLE;
		break;

	case O_WRONLY:
		flags = FSTRMF_WRITABLE;
		break;

	case O_RDWR:
		flags = FSTRMF_READABLE|FSTRMF_WRITABLE;
		break;

	case O_WRONLY|O_APPEND:
		flags = FSTRMF_WRITABLE|FSTRMF_IS_APPENDING;
		break;

	case O_RDWR|O_APPEND:
		flags = FSTRMF_READABLE|FSTRMF_WRITABLE|FSTRMF_IS_APPENDING;
		break;

	default:
		pfs_etrace("invalid accmode: %#x\n", accmode);
		PFS_ASSERT("unreachable" == NULL);
	}

	pfs_fstrmf_set(fp, flags, mask);
}

static void
pfs_fstrm_link_chain(pfs_fstrm_t *fp)
{
	PFS_ASSERT(!(fp->f_flags & FSTRMF_LINKED));
	mutex_lock(&fstrm_chain_lock);

	fp->f_next = fstrm_chain;
	fstrm_chain = fp;
	pfs_fstrmf_set(fp, FSTRMF_LINKED, FSTRMF_LINKED);

	mutex_unlock(&fstrm_chain_lock);
}

static void
pfs_fstrm_unlink_chain(pfs_fstrm_t *fp)
{
	pfs_fstrm_t *prev, *cur;
	PFS_ASSERT(fp->f_flags & FSTRMF_LINKED);
	mutex_lock(&fstrm_chain_lock);

	prev = NULL;
	cur = fstrm_chain;
	while (cur != fp) {
		prev = cur;
		cur = cur->f_next;
	}
	PFS_ASSERT(cur == fp);
	if (prev != NULL)
		prev->f_next = fp->f_next;
	pfs_fstrmf_set(fp, 0, FSTRMF_LINKED);

	mutex_unlock(&fstrm_chain_lock);
}

static inline void
pfs_fstrm_lock(pfs_fstrm_t *fp)
{
	mutex_lock(&fp->f_mtx);
}

static inline void
pfs_fstrm_unlock(pfs_fstrm_t *fp)
{
	mutex_unlock(&fp->f_mtx);
}

static inline int
pfs_api_open(pfs_fstrm_t *fp, const char *pbdpath, int flags, int mode)
{
	int fd;

	fd = pfs_open(pbdpath, flags, mode);
	if (fd < 0) {
		pfs_fstrmf_set_err(fp);
		return -errno;
	}
	return fd;
}

static inline int
pfs_api_close(pfs_fstrm_t *fp)
{
	int err;

	err = pfs_close(fp->f_fileno);
	if (err < 0) {
		pfs_fstrmf_set_err(fp);
		return -errno;
	}
	return 0;
}

static off_t
pfs_api_lseek(pfs_fstrm_t *fp, off_t off, int whence)
{
	off_t newoff;

	newoff = pfs_lseek(fp->f_fileno, off, whence);
	if (newoff < 0) {
		pfs_fstrmf_set_err(fp);
		return -errno;
	}
	return newoff;
}

static ssize_t
pfs_api_read(pfs_fstrm_t *fp, char *buf, size_t len)
{
	ssize_t rlen;

	rlen = pfs_read(fp->f_fileno, buf, len);
	if (rlen < 0) {
		pfs_fstrmf_set_err(fp);
		return -errno;
	}
	if (rlen == 0)
		pfs_fstrmf_set_eof(fp);

	return rlen;
}

static ssize_t
pfs_api_write(pfs_fstrm_t *fp, const char *buf, size_t len)
{
	ssize_t wlen;

	wlen = pfs_write(fp->f_fileno, buf, len);
	PFS_ASSERT(wlen < 0 || (size_t)wlen == len);	// guaranteed by pfs_write()
	if (wlen < 0) {
		pfs_fstrmf_set_err(fp);
		return -errno;
	}

	return wlen;
}

static pfs_fstrm_t *
pfs_fstrm_create()
{
	size_t bufsz = FSTRM_BUFSIZE;
	pfs_fstrm_t *fp;

	fp = (pfs_fstrm_t *)pfs_mem_malloc(sizeof(*fp) + bufsz, M_FSTRM);
	if (fp == NULL) {
		pfs_etrace("failed to create fstream: no memory\n");
		return NULL;
	}
	memset(fp, 0, sizeof(*fp) + bufsz);

	fp->f_fileno = -1;
	fp->f_flags = 0;
	fp->f_next = NULL;
	mutex_init(&fp->f_mtx);
	fp->f_base = (char *)(fp + 1);
	fp->f_bufsz = bufsz;
	fp->f_rw = FSTRM_IO_SYNC;
	fp->f_cur = fp->f_end = fp->f_base;
	return fp;
}

static void
pfs_fstrm_destroy(pfs_fstrm_t *fp)
{
	mutex_destroy(&fp->f_mtx);
	pfs_mem_free(fp, M_FSTRM);
}

static int
pfs_fstrm_open_mode(const char *mode, int *omodep, int *oflagsp)
{
	int oflags = 0, omode;

	switch (*mode) {
	case 'r':
		omode = O_RDONLY;
		break;

	case 'w':
		omode = O_WRONLY;
		oflags = O_CREAT|O_TRUNC;
		break;

	case 'a':
		omode = O_WRONLY;
		oflags = O_CREAT|O_APPEND;
		break;

	default:
		ERR_RETVAL(EINVAL);
	}

	while (*++mode != '\0') {
		switch (*mode) {
		case '+':
			omode = O_RDWR;
			continue;

		/* mode extensions are unsupported now */
		case 'x':
		case 'b':
		case 'm':
		case 'c':
		case 'e':
			break;
		default:
			ERR_RETVAL(EINVAL);
		}
	}

	*omodep = omode;
	*oflagsp = oflags;
	return 0;
}

static int
pfs_fstrm_open_fd(pfs_fstrm_t *fp, const char *pbdpath, int flags, int mode)
{
	int fd;

	fd = pfs_api_open(fp, pbdpath, flags, mode);
	if (fd < 0)
		return fd;

	fp->f_fileno = fd;
	return 0;
}

static int
pfs_fstrm_close_fd(pfs_fstrm_t *fp)
{
	int err;

	err = pfs_api_close(fp);
	if (err < 0)
		return err;

	fp->f_fileno = -1;
	return 0;
}

static off_t
pfs_fstrm_seekoff(pfs_fstrm_t *fp, off_t offset, int whence)
{
	PFS_ASSERT(fp->f_rw == FSTRM_IO_SYNC);
	return pfs_api_lseek(fp, offset, whence);
}

static ssize_t
pfs_fstrmb_read_prepare(pfs_fstrm_t *fp)
{
	ssize_t rlen;

	PFS_ASSERT(fp->f_rw == FSTRM_IO_SYNC);
	rlen = pfs_api_read(fp, fp->f_base, fp->f_bufsz);
	if (rlen <= 0)
		return rlen;
	PFS_ASSERT(rlen <= (ssize_t)fp->f_bufsz);

	/* INVARIANT: f_end indicates fd's offset */
	fp->f_rw = FSTRM_IO_READING;
	fp->f_cur = fp->f_base;
	fp->f_end = fp->f_base + rlen;
	return rlen;
}

static void
pfs_fstrmb_read_consume(pfs_fstrm_t *fp, char *buf, size_t len)
{
	PFS_ASSERT(fp->f_rw == FSTRM_IO_READING);
	PFS_ASSERT(len <= (size_t)(fp->f_end - fp->f_cur));
	memcpy(buf, fp->f_cur, len);
	fp->f_cur += len;
	if (fp->f_cur == fp->f_end) {
		fp->f_rw = FSTRM_IO_SYNC;
		fp->f_cur = fp->f_end = fp->f_base;
	}
}

static int
pfs_fstrmb_read_discard(pfs_fstrm_t *fp)
{
	off_t off;

	PFS_ASSERT(fp->f_rw == FSTRM_IO_READING);
	off = pfs_api_lseek(fp, fp->f_cur - fp->f_end, SEEK_CUR);
	if (off < 0)
		return off;

	fp->f_rw = FSTRM_IO_SYNC;
	fp->f_cur = fp->f_end = fp->f_base;
	return 0;
}

static void
pfs_fstrmb_write_prepare(pfs_fstrm_t *fp)
{
	PFS_ASSERT(fp->f_rw == FSTRM_IO_SYNC);
	fp->f_rw = FSTRM_IO_WRITING;
	fp->f_cur = fp->f_base;
	fp->f_end = fp->f_base + fp->f_bufsz;
}

static void
pfs_fstrmb_write_fill(pfs_fstrm_t *fp, const char *buf, size_t len)
{
	PFS_ASSERT(fp->f_rw == FSTRM_IO_WRITING);
	PFS_ASSERT(len <= (size_t)(fp->f_end - fp->f_cur));
	memcpy(fp->f_cur, buf, len);
	fp->f_cur += len;
}

static ssize_t
pfs_fstrmb_write_flush(pfs_fstrm_t *fp)
{
	ssize_t wlen, reqlen;

	PFS_ASSERT(fp->f_rw == FSTRM_IO_WRITING);
	reqlen = (ssize_t)(fp->f_cur - fp->f_base);
	wlen = pfs_api_write(fp, fp->f_base, reqlen);
	if (wlen < 0)
		return wlen;

	/* INVARIANT: f_base indicates fd's offset */
	fp->f_rw = FSTRM_IO_SYNC;
	fp->f_cur = fp->f_end = fp->f_base;
	return wlen;
}

/*
 * @donesz is guaranteed to be set
 */
static int
pfs_fstrm_getn(pfs_fstrm_t *fp, char *buf, size_t reqsz, size_t *donesz)
{
	char *rptr = buf;
	size_t buffered, todo;
	ssize_t rlen, iolen;
	int err;

	*donesz = 0;
	if (!pfs_fstrmf_check(fp, FSTRMF_READABLE))
		ERR_RETVAL(EBADF);

	if (fp->f_rw == FSTRM_IO_WRITING) {
		iolen = pfs_fstrmb_write_flush(fp);
		if (iolen < 0)
			return iolen;
	}
	if (fp->f_rw == FSTRM_IO_SYNC) {
		iolen = pfs_fstrmb_read_prepare(fp);
		if (iolen <= 0)
			return iolen;
	}
	PFS_ASSERT(fp->f_rw == FSTRM_IO_READING);

	err = 0;
	for (todo = reqsz; todo > 0; todo -= rlen, rptr += rlen) {
		// ignore EOF and ERR bit

		/* consume buffer if not empty */
		buffered = fp->f_end - fp->f_cur;
		rlen = MIN(todo, buffered);
		if (rlen > 0) {
			pfs_fstrmb_read_consume(fp, rptr, rlen);
			continue;
		}

		PFS_ASSERT(fp->f_cur == fp->f_end);
		/* buffer consumed, need to be refilled for last part */
		if (todo < fp->f_bufsz) {
			iolen = pfs_fstrmb_read_prepare(fp);
			err = iolen < 0 ? iolen : 0;
			if (err < 0 || iolen == 0)
				break;
			rlen = 0;
			continue;
		}

		iolen = todo & ~(fp->f_bufsz - 1);
		rlen = pfs_api_read(fp, rptr, iolen);
		err = rlen < 0 ? rlen : 0;
		if (err < 0 || rlen == 0)
			break;
	}

	*donesz = reqsz - todo;
	PFS_ASSERT(*donesz == (size_t)(rptr - buf));
	return err;
}

/*
 * @donesz is guaranteed to be set
 */
static int
pfs_fstrm_putn(pfs_fstrm_t *fp, const char *buf, size_t reqsz, size_t *donesz)
{
	const char *wptr = buf;
	size_t todo, space;
	ssize_t wlen, iolen;
	int err;

	*donesz = 0;
	if (!pfs_fstrmf_check(fp, FSTRMF_WRITABLE))
		ERR_RETVAL(EBADF);

	if (fp->f_rw == FSTRM_IO_READING) {
		err = pfs_fstrmb_read_discard(fp);
		if (err < 0)
			return err;
	}
	if (fp->f_rw == FSTRM_IO_SYNC)
		pfs_fstrmb_write_prepare(fp);
	PFS_ASSERT(fp->f_rw == FSTRM_IO_WRITING);

	for (todo = reqsz; todo > 0; todo -= wlen, wptr += wlen) {
		// ignore EOF and ERR bit

		/* fill when buffer is not full */
		space = fp->f_end - fp->f_cur;
		wlen = MIN(todo, space);
		if (wlen > 0) {
			pfs_fstrmb_write_fill(fp, wptr, wlen);
			continue;
		}

		PFS_ASSERT(fp->f_cur == fp->f_end);
		/* buffer is full, need flush before writing more data */
		iolen = pfs_fstrmb_write_flush(fp);
		err = iolen < 0 ? iolen : 0;
		if (err < 0)
			break;

		pfs_fstrmb_write_prepare(fp);

		/* last part can be buffered */
		if (todo < fp->f_bufsz) {
			wlen = todo;
			pfs_fstrmb_write_fill(fp, wptr, wlen);
			continue;
		}

		iolen = todo & ~(fp->f_bufsz - 1);
		wlen = pfs_api_write(fp, wptr, iolen);
		err = wlen < 0 ? wlen : 0;
		if (err < 0)
			break;
	}

	*donesz = reqsz - todo;
	PFS_ASSERT(*donesz == (size_t)(wptr - buf));
	return err;
}

static int
pfs_fstrm_sync(pfs_fstrm_t *fp)
{
	int err;
	ssize_t wlen;

	if (fp->f_rw == FSTRM_IO_SYNC) {
		PFS_ASSERT((fp->f_cur == fp->f_base) && (fp->f_end == fp->f_base));
		return 0;
	}

	if (fp->f_rw == FSTRM_IO_READING) {
		err = pfs_fstrmb_read_discard(fp);
	} else {
		PFS_ASSERT(fp->f_rw == FSTRM_IO_WRITING);
		wlen = pfs_fstrmb_write_flush(fp);
		err = wlen < 0 ? wlen : 0;
	}

	if (err < 0)
		return err;

	PFS_ASSERT(fp->f_rw == FSTRM_IO_SYNC);
	PFS_ASSERT((fp->f_cur == fp->f_base) && (fp->f_end == fp->f_base));
	return 0;
}

int
pfs_fstrm_open(const char *pbdpath, const char *mode, pfs_fstrm_t **fpp)
{
	pfs_fstrm_t *fp;
	int err, omode, oflags;

	err = pfs_fstrm_open_mode(mode, &omode, &oflags);
	if (err < 0)
		return err;

	fp = pfs_fstrm_create();
	if (fp == NULL)
		ERR_RETVAL(ENOMEM);

	err = pfs_fstrm_open_fd(fp, pbdpath, omode|oflags, 0666);
	if (err < 0) {
		pfs_fstrm_destroy(fp);
		return err;
	}
#define	FSTRMF_MASK	(O_RDONLY|O_WRONLY|O_RDWR|O_APPEND)
	pfs_fstrmf_set_rwmode(fp, (omode|oflags) & FSTRMF_MASK);
	pfs_fstrmf_set_buftype(fp, _IOFBF);
	pfs_fstrm_link_chain(fp);

	*fpp = fp;
	return 0;
}

int
pfs_fstrm_xclose(pfs_fstrm_t *fp)
{
	int err, serr;

	CHECK_FILE(fp);

	pfs_fstrm_lock(fp);
	pfs_fstrm_unlink_chain(fp);
	serr = pfs_fstrm_sync(fp);
	err = pfs_fstrm_close_fd(fp);
	pfs_fstrm_unlock(fp);

	pfs_fstrm_destroy(fp);
	return err ? err : serr;
}

int
pfs_fstrm_xread(pfs_fstrm_t *fp, void *buf, size_t size, size_t nmemb,
    size_t *nitem)
{
	size_t reqsz, donesz;
	int err;

	CHECK_FILE(fp);
	reqsz = size * nmemb;
	if (reqsz == 0) {
		*nitem = 0;
		return 0;
	}

	pfs_fstrm_lock(fp);
	err = pfs_fstrm_getn(fp, (char *)buf, reqsz, &donesz);
	pfs_fstrm_unlock(fp);

	*nitem = (reqsz == donesz) ? nmemb : donesz / size;
	return err;
}

int
pfs_fstrm_xwrite(pfs_fstrm_t *fp, const void *buf, size_t size, size_t nmemb,
    size_t *nitem)
{
	size_t reqsz, donesz;
	int err;

	CHECK_FILE(fp);
	reqsz = size * nmemb;
	if (reqsz == 0) {
		*nitem = 0;
		return 0;
	}

	pfs_fstrm_lock(fp);
	err = pfs_fstrm_putn(fp, (const char *)buf, reqsz, &donesz);
	pfs_fstrm_unlock(fp);

	*nitem = (reqsz == donesz) ? nmemb : donesz / size;
	return err;
}

int
pfs_fstrm_xflush(pfs_fstrm_t *fp)
{
	int err;

	CHECK_FILE(fp);

	pfs_fstrm_lock(fp);
	err = pfs_fstrm_sync(fp);
	pfs_fstrm_unlock(fp);

	return err;
}

off_t
pfs_fstrm_xseekoff(pfs_fstrm_t *fp, off_t offset, int whence, bool reseteof, bool reseterr)
{
	off_t off;
	int err;

	CHECK_FILE(fp);

	pfs_fstrm_lock(fp);
	err = pfs_fstrm_sync(fp);
	if (err < 0)
		goto out;

	off = pfs_fstrm_seekoff(fp, offset, whence);
	err = off < 0 ? off : 0;
	if (err < 0)
		goto out;

	if (reseteof)
		pfs_fstrmf_unset_eof(fp);
	if (reseterr)
		pfs_fstrmf_unset_err(fp);

	pfs_fstrm_unlock(fp);
	return off;

out:
	pfs_fstrm_unlock(fp);
	return err;
}

int
pfs_fstrm_xfileno(pfs_fstrm_t *fp, int *fileno)
{
	CHECK_FILE(fp);

	if (fp->f_fileno < 0)
		ERR_RETVAL(EBADF);
	pfs_fstrm_lock(fp);
	*fileno = fp->f_fileno;
	pfs_fstrm_unlock(fp);
	return 0;
}

int
pfs_fstrm_xeof(pfs_fstrm_t *fp, bool *iseof)
{
	CHECK_FILE(fp);

	pfs_fstrm_lock(fp);
	*iseof = pfs_fstrmf_check(fp, FSTRMF_EOF_SEEN);
	pfs_fstrm_unlock(fp);
	return 0;
}

int
pfs_fstrm_xerror(pfs_fstrm_t *fp, bool *haserr)
{
	CHECK_FILE(fp);

	pfs_fstrm_lock(fp);
	*haserr = pfs_fstrmf_check(fp, FSTRMF_ERR_SEEN);
	pfs_fstrm_unlock(fp);
	return 0;
}

int
pfs_fstrm_xclearerr(pfs_fstrm_t *fp)
{
	CHECK_FILE(fp);

	pfs_fstrm_lock(fp);
	pfs_fstrmf_unset_eof(fp);
	pfs_fstrmf_unset_err(fp);
	pfs_fstrm_unlock(fp);
	return 0;
}
