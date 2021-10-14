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

#include "pfs_blkio.h"
#include "pfs_devio.h"
#include "pfs_mount.h"


typedef int pfs_blkio_fn_t(int, pfs_bda_t, size_t, char*, pfs_bda_t, size_t,
	char*, int);

/*
 * pfs_blkio_align:
 *
 * 	Align bda and calculate the io len. New IO bda and length
 * 	must be 512 aligned.
 *
 * 	@data_bda:	I/O, the bda for data PBD io.
 * 	@io_len: 	output, the len for PBD io.
 * 	@op_len: 	output, the actual len for op(read or write).
 *
 * 	return val:	the aligned bda.
 */
#if 0
pfs_bda_t
pfs_blkio_align(pfs_mount_t *mnt, pfs_bda_t bda, size_t length,
    size_t *iolength, size_t *oplength)
{
	pfs_bda_t iobda, endbda;
	const pfs_bda_t alignsize = 512;

	/*
	 * iobda and iolength are always 512 aligned. It decides
	 * the position of IO window's left edge. It may move IO
	 * window to the left.
	 */
	iobda = bda & ~(alignsize - 1);
	endbda = roundup(bda + length, alignsize);
	if (endbda > iobda + mnt->mnt_fragsize)
		endbda = iobda + mnt->mnt_fragsize;
	PFS_ASSERT(endbda > 0 && (bda & ~(mnt->mnt_blksize - 1)) ==
	    ((endbda - 1) & ~(mnt->mnt_blksize - 1)));

	*iolength = endbda - iobda;
	*oplength = MIN(endbda - bda, length);

	PFS_ASSERT((*iolength & (alignsize - 1)) == 0);
	PFS_ASSERT(iobda < mnt->mnt_disksize);
	PFS_ASSERT(iobda + *iolength <= mnt->mnt_disksize);

	return iobda;
}
#endif

static pfs_bda_t
pfs_blkio_align(pfs_mount_t *mnt, pfs_bda_t data_bda, size_t data_len,
    size_t *io_len, size_t *op_len)
{
	pfs_bda_t aligned_bda;
	size_t sect_off, frag_off;

	sect_off = data_bda & (mnt->mnt_sectsize - 1);
	frag_off = data_bda & (mnt->mnt_fragsize - 1);
	if (sect_off != 0) {
		aligned_bda = data_bda - sect_off;
		*op_len = MIN(mnt->mnt_sectsize - sect_off, data_len);
		*io_len = mnt->mnt_sectsize;
	} else {
		aligned_bda = data_bda;
		*op_len = MIN(mnt->mnt_fragsize - frag_off, data_len);
		*io_len = roundup(*op_len, mnt->mnt_sectsize);
	}

	PFS_ASSERT(aligned_bda <= data_bda);
	PFS_ASSERT(aligned_bda < mnt->mnt_disksize);
	PFS_ASSERT(aligned_bda + *io_len <= mnt->mnt_disksize);
	PFS_ASSERT(*io_len <= mnt->mnt_fragsize);
	PFS_ASSERT((data_bda - aligned_bda) + *op_len <= mnt->mnt_fragsize);

	return aligned_bda;
}


static int
pfs_blkio_read_segment(int iodesc, pfs_bda_t albda, size_t allen, char *albuf,
    pfs_bda_t bda, size_t len, char *buf, int nowait)
{
	int err;

	if (allen != len) {
		PFS_ASSERT(albuf != NULL);
		PFS_INC_COUNTER(STAT_PFS_UnAligned_R_4K);
		err = pfsdev_pread(iodesc, albuf, allen, albda);
		if (err < 0)
			return err;
		memcpy(buf, &albuf[bda - albda], len);
		return 0;
	}

	PFS_ASSERT(albda == bda);
	err = pfsdev_pread_flags(iodesc, buf, len, bda, nowait);
	return err;
}

static int
pfs_blkio_write_segment(int iodesc, pfs_bda_t albda, size_t allen, char *albuf,
    pfs_bda_t bda, size_t len, char *buf, int nowait)
{
	int err;

	if (allen != len) {
		PFS_ASSERT(albuf != NULL);
		PFS_INC_COUNTER(STAT_PFS_UnAligned_W_4K);
		err = pfsdev_pread(iodesc, albuf, allen, albda);
		if (err < 0)
			return err;
		memcpy(&albuf[bda - albda], buf, len);
		err = pfsdev_pwrite(iodesc, albuf, allen, albda);
		return err;
	}

	PFS_ASSERT(albda == bda);
	err = pfsdev_pwrite_flags(iodesc, buf, len, bda, nowait);
	return err;
}

static int
pfs_blkio_done(int iodesc, int nowait)
{
	if (!nowait)
		return 0;
	return pfsdev_wait_io(iodesc);
}

static ssize_t
pfs_blkio_execute(pfs_mount_t *mnt, char *data, pfs_blkno_t blkno,
    off_t off, ssize_t len, pfs_blkio_fn_t *iofunc)
{
	char *albuf = NULL;
	int err, err1, nowait;
	pfs_bda_t bda, albda;
	size_t allen, iolen, left;

	err = 0;
	nowait = (len >= 2*PFS_FRAG_SIZE) ? IO_NOWAIT : 0;
	left = len;
	while (left > 0) {
		allen = iolen = 0;
		bda = blkno * mnt->mnt_blksize + off;
		albda = pfs_blkio_align(mnt, bda, left, &allen, &iolen);

		if (allen != iolen && albuf == NULL) {
			albuf = (char *)pfs_mem_malloc(PFS_FRAG_SIZE,
			    M_IO_TMPBUF);
			PFS_VERIFY(albuf != NULL);
		}

		err = (*iofunc)(mnt->mnt_ioch_desc, albda, allen, albuf, bda,
		    iolen, data, nowait);
		if (err < 0)
			break;

		data += iolen;
		off += iolen;
		left -= iolen;
	}

	/*
	 * albuf should never be used by nowait I/O,
	 * so free it before wait_io() is safe.
	 */
	if (albuf) {
		pfs_mem_free(albuf, M_IO_TMPBUF);
		albuf = NULL;
	}

	err1 = pfs_blkio_done(mnt->mnt_ioch_desc, nowait);
	ERR_UPDATE(err, err1);
	if (err < 0) {
		if (err == -ETIMEDOUT)
			ERR_RETVAL(ETIMEDOUT);
		ERR_RETVAL(EIO);
	}

	return len;
}

ssize_t
pfs_blkio_read(pfs_mount_t *mnt, char *data, pfs_blkno_t blkno,
    off_t off, ssize_t len)
{
	ssize_t iolen = 0;

	PFS_ASSERT(off + len <= mnt->mnt_blksize);
	iolen = pfs_blkio_execute(mnt, data, blkno, off, len,
	    pfs_blkio_read_segment);
	return iolen;
}

ssize_t
pfs_blkio_write(pfs_mount_t *mnt, char *data, pfs_blkno_t blkno,
    off_t off, ssize_t len)
{
	ssize_t iolen = 0;
	void *zerobuf = NULL;

	PFS_ASSERT(off + len <= mnt->mnt_blksize);
	if (data == NULL) {
		zerobuf = pfs_mem_malloc(len, M_ZERO_BUF);
		PFS_VERIFY(zerobuf != NULL);
		memset(zerobuf, 0, len);
		data = (char *)zerobuf;
	}
	iolen = pfs_blkio_execute(mnt, data, blkno, off, len,
	    pfs_blkio_write_segment);

	if (zerobuf) {
		pfs_mem_free(zerobuf, M_ZERO_BUF);
		zerobuf = NULL;
	}
	return iolen;
}
