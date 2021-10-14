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

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>

#include "pfs_chunk.h"
#include "pfs_impl.h"
#include "pfs_paxos.h"
#include "pfs_meta.h"
#include "pfs_mount.h"
#include "pfs_trace.h"
#include "pfs_util.h"
static const char	*meta_file_path = "/var/run/pfs";

#define	CHUNKFILE_MAGIC		0x43CB40FA34
#define	CHUNKFILE_VERSION	0x01
#define	METACACHE_MAGIC		0x0F1A341D
#define CHUNK_FRAG_SIZE		(4096)

enum {
	CHUNK_READ_HEADER = 0,
	CHUNK_READ_META,
	CHUNK_READ_DATA,
	CHUNK_READ_CRC,
	CHUNK_READ_FINISH,
};

enum {
	CHUNK_WRITE_HEADER = 0,
	CHUNK_WRITE_META,
	CHUNK_WRITE_DATA,
	CHUNK_WRITE_CRC,
	CHUNK_WRITE_FINISH,
};

typedef struct pfs_chunkfile_header {
	/* header info */
	uint64_t	cf_magic;
	uint64_t	cf_version;
	uint64_t	cf_ctime;	/* create time, unit is second */
	bool		cf_enablecrc;

	/* pbd info */
	char		cf_pbdname[PFS_MAX_PBDLEN];
	uint64_t	cf_chunksz;
	uint32_t	cf_blksz;
	uint32_t	cf_fragsz;
	uint32_t	cf_sectsz;

	/* chunk info */
	uint32_t	cf_nchunk;	/* formatted chunk number of PBD */
	uint32_t	cf_ckid;	/* chunkid of this cf object */
	uint32_t	cf_metasz;
	uint32_t	cf_crcsz;
	uint64_t	cf_streamsz;
}__attribute__((aligned(4096))) pfs_chunkfile_header_t;

typedef struct metacache_header {
	uint32_t	mh_magic;
	uint64_t	mh_run_version;	/* running pfs version */
}metacache_header_t;

typedef struct block_usedinfo {
	uint64_t	bu_blkno;
	uint8_t 	bu_used;
	uint32_t	bu_holeoff;
} block_usedinfo_t;

typedef struct block_meta_head
{
	int64_t		mh_blko;
	int64_t		mh_datalen;
} block_meta_head_t;

typedef struct pfs_chunk_readstream {
	pfs_chunkstream_t		cr_chunk_stream;
	block_meta_head_t		*cr_meta_buf;
	uint32_t			*cr_crc_buf;
	int64_t				cr_metasz;
	int64_t				cr_crcsz;
	int64_t				cr_streamsz;
	int64_t				cr_readsz;
	int32_t				cr_stage;
	pfs_chunkfile_header_t		cr_cf;
	int64_t				cr_metareadsz;
	int64_t				cr_blkpos;
	int64_t				cr_blkreadsz;
	int64_t				cr_crcreadsz;
	int64_t				cr_ncrcfrag;
} pfs_chunk_readstream_t;

typedef struct pfs_chunk_writestream {
	pfs_chunkstream_t	cw_chunk_stream;
	block_meta_head_t	*cw_meta_buf;
	pfs_chunkfile_header_t	cw_ck_header;
	uint64_t		cw_writesz;
	uint32_t		*cw_ccrc_buf;	/*calc crc by write*/
	uint32_t		*cw_fcrc_buf;	/*store in file crc*/
	int32_t			cw_stage;
	int64_t			cw_metawritesz;
	int64_t			cw_blkpos;
	int64_t			cw_blkwritesz;
	int64_t			cw_crcwritesz;
	int64_t			cw_ncrcfrag;
} pfs_chunk_writestream_t;

static inline bool
pfs_chunk_isbackup(int flags)
{
	return (flags & CHUNK_BACKUP) == CHUNK_BACKUP;
}

static inline bool
pfs_chunk_isrestore(int flags)
{
	return (flags & CHUNK_RESTORE) == CHUNK_RESTORE;
}

static inline bool
chunk_enablecrc(const pfs_chunkstream_desc_t *desc)
{
	return (desc->csd_flags & CHUNK_CRC) != 0;
}

static int
paxos_leader_read(int iodesc, char *buf, size_t buflen)
{
	int err;
	pfs_leader_record_t *lr;

	PFS_ASSERT(buflen == PBD_SECTOR_SIZE);
	memset(buf, 0, buflen);
	err = pfsdev_pread(iodesc, buf, buflen, PFS_BLOCK_SIZE);
	if (err < 0) {
		pfs_etrace("failed to read paxos leader: %d\n", err);
		return err;
	}

	lr = (pfs_leader_record_t *)buf;
	if (lr->checksum != leader_checksum(lr)) {
		pfs_etrace("paxos leader checksum %u is invalid\n",
		    lr->checksum);
		ERR_RETVAL(EINVAL);
	}
	return 0;
}

static int
paxos_leader_write(int devi, char *buf, size_t buflen)
{
	int err;

	PFS_ASSERT(buflen == PBD_SECTOR_SIZE);
	err = pfsdev_pwrite(devi, buf, buflen, PFS_BLOCK_SIZE);
	if (err < 0) {
		pfs_etrace("failed to write paxos leader: %d\n");
		return err;
	}

	return 0;
}

static int
paxos_leader_reset(int devi, const char *pbdname)
{
	return 0;
}
static int
metacache_open(const char *pbdname, int mode)
{
	int err, fd;
	char path[PFS_MAX_PATHLEN];

	err = mkdir(meta_file_path, 0777);
	if (err < 0 && errno != EEXIST) {
		pfs_etrace("mkdir %s failed, err=%d, errno=%d\n", meta_file_path,
		    err, errno);
		return err;
	}

	snprintf(path, PFS_MAX_PATHLEN, "%s/pbd%s.metacache", meta_file_path,
	    pbdname);
	path[PFS_MAX_PATHLEN-1] = '\0';
	fd = open(path, mode, 0655);
	if (fd < 0) {
		pfs_etrace("open file %s failed, fd=%d, errno=%d\n", path,
		    fd, errno);
		return fd;
	}
	return fd;
}

static int
metacache_check_leader(int fd, int iochd)
{
	int err;
	ssize_t rlen;
	char buf[PBD_SECTOR_SIZE];
	pfs_leader_record_t flr, *lr;

	/* read paxos leader from metacache */
	rlen = pread(fd, &flr, sizeof(flr), sizeof(metacache_header_t));
	if (rlen != sizeof(flr)) {
		pfs_etrace("read fd %d @ 0 failed, rlen=%d, errno=%d\n",
		    fd, rlen, errno);
		ERR_RETVAL(EIO);
	}
	if (flr.checksum != leader_checksum(&flr)) {
		pfs_etrace("paxos leader checksum %u is invalid in file fd %d\n",
		    flr.checksum, fd);
		ERR_RETVAL(EINVAL);
	}

	/* check paxos leader */
	err = paxos_leader_read(iochd, buf, sizeof(buf));
	if (err < 0)
		ERR_RETVAL(EIO);
	lr = (pfs_leader_record_t *)buf;
	if (memcmp(lr, &flr, sizeof(*lr))) {
		pfs_itrace("paxos leaders on pbd and metafile are different\n");
		ERR_RETVAL(EINVAL);
	}

	return 0;
}

static bool
chunk_isvalid(const pfs_chunk_phy_t *phyck, uint32_t ckid)
{
	if (!chunk_magic_valid(phyck->ck_number, phyck->ck_magic)) {
		pfs_etrace("chunk %llu pfs magic mismatch %#llx vs %#llx\n",
		    phyck->ck_number, (unsigned long long)phyck->ck_magic,
		    (unsigned long long)PFS_CHUNK_MAGIC);
		return false;
	}
	if (phyck->ck_chunksize != PBD_CHUNK_SIZE) {
		pfs_etrace("chunk %u chunk size mismatch %#llx vs %#llx\n",
		    ckid, (unsigned long long)phyck->ck_chunksize,
		    (unsigned long long)PBD_CHUNK_SIZE);
		return false;
	}
	if (phyck->ck_sectsize != PBD_SECTOR_SIZE) {
		pfs_etrace("chunk %u sector size mismatch %#llx vs %#llx\n",
		    ckid, (unsigned long long)phyck->ck_sectsize,
		    (unsigned long long)PBD_SECTOR_SIZE);
		return false;
	}
	if (phyck->ck_number != ckid) {
		pfs_etrace("chunk %u id mismatch %u vs %u\n", ckid,
		    phyck->ck_number, ckid);
		return false;
	}
	if (phyck->ck_checksum &&
	    (phyck->ck_checksum != crc32c_compute(phyck, sizeof(*phyck),
	    offsetof(struct pfs_chunk_phy, ck_checksum)))) {
		pfs_etrace("chunk %u checksum %u is invalid\n",
		    ckid, phyck->ck_checksum);
		return false;
	}

	return true;
}

static int
metacache_check_header(pfs_chunkstream_desc_t *desc)
{
	ssize_t rlen;
	uint32_t mhsz;
	metacache_header_t mh;

	mhsz = sizeof(metacache_header_t);

	rlen = read(desc->csd_meta_fd, &mh, mhsz);
	if (rlen != mhsz)
		ERR_RETVAL(EIO);

	if (mh.mh_magic != METACACHE_MAGIC) {
		pfs_etrace("wrong meta cache magic(%u)\n", mh.mh_magic);
		ERR_RETVAL(EINVAL);
	}

	desc->csd_pfs_run_ver = mh.mh_run_version;

	return 0;
}

static int
metacache_check_bust(pfs_chunkstream_desc_t *desc)
{
	int err, fd, iochd;
	struct pbdinfo pi;
	struct stat st;
	uint32_t fcrc, crc, ckid, fnck, mhsz;
	ssize_t rlen, datasz, bustsz, offset;
	pfs_chunk_phy_t *phyck;
	block_usedinfo_t bust[PFS_NBT_PERCHUNK];
	char sectbuf[PBD_SECTOR_SIZE];

	fd = desc->csd_meta_fd;
	iochd = desc->csd_ioch_desc;
	bustsz = PFS_NBT_PERCHUNK * sizeof(block_usedinfo_t);
	mhsz = sizeof(metacache_header_t);
	/*
	 * The BUST number must be equal with total chunk number in pbd.
	 */
	err = fstat(fd, &st);
	if (err < 0) {
		pfs_etrace("cant get metafile %d size, err=%d, errno=%d\n",
		    fd, err, errno);
		return err;
	}

	datasz = st.st_size - PBD_SECTOR_SIZE - mhsz;
	if (datasz <= 0 || datasz % (sizeof(uint32_t) + bustsz) != 0) {
		pfs_etrace("file size %ld is invalid\n", st.st_size);
		ERR_RETVAL(EINVAL);
	}

	/* check total chunk count */
	fnck = datasz / (sizeof(uint32_t) + bustsz);
	err = pfsdev_info(iochd, &pi);
	if (err < 0) {
		pfs_etrace("cant get pbd info, err=%d\n", err);
		ERR_RETVAL(EIO);
	}
	if (pi.pi_chunksize != PBD_CHUNK_SIZE ||
	    pi.pi_disksize != (uint64_t)fnck * PBD_CHUNK_SIZE) {
		pfs_etrace("pbd parameters mismatch, disksize %llu vs"
		    " %llu, chunksize %llu vs %llu\n",
		    (unsigned long long)pi.pi_disksize,
		    (unsigned long long)fnck * PBD_CHUNK_SIZE,
		    (unsigned long long)pi.pi_chunksize,
		    (unsigned long long)PBD_CHUNK_SIZE);
		ERR_RETVAL(EINVAL);
	}

	offset = lseek(fd, PBD_SECTOR_SIZE + mhsz, SEEK_SET);
	if (offset != PBD_SECTOR_SIZE + mhsz)
		ERR_RETVAL(errno);

	for (ckid = 0; ckid < fnck; ckid++) {
		rlen = read(fd, &fcrc, sizeof(fcrc));
		if (rlen != sizeof(fcrc))
			ERR_RETVAL(EIO);

		memset(bust, false, bustsz);
		rlen = read(fd, bust, bustsz);
		if (rlen != bustsz)
			ERR_RETVAL(EIO);

		crc = crc32c((uint32_t)~1, (uint8_t *)bust, bustsz);
		if (crc != fcrc) {
			pfs_etrace("metacache chunk %u BUST checksum mismatch,"
			    " %u vs %u\n", crc, fcrc);
			ERR_RETVAL(EINVAL);
		}
	}
	/*
	 * compare valid chunk number in metacache with nchunk in
	 * the first chunk header on pbd.
	 */
	memset(sectbuf, 0, sizeof(sectbuf));
	err = pfsdev_pread(iochd, sectbuf, PBD_SECTOR_SIZE, 0);
	if (err < 0) {
		pfs_etrace("cant read the first chunk header\n");
		ERR_RETVAL(EIO);
	}
	phyck = (pfs_chunk_phy_t *)sectbuf;
	if (!chunk_isvalid(phyck, 0))
		ERR_RETVAL(EINVAL);

	if (fnck != phyck->ck_nchunk) {
		pfs_etrace("valid chunk number mismatch %u vs %u\n",
		    fnck, phyck->ck_nchunk);
		ERR_RETVAL(EINVAL);
	}
	desc->csd_nchunk = fnck;

	return 0;
}

static bool
metacache_isvalid(pfs_chunkstream_desc_t *desc)
{
	int err;

	err = metacache_check_header(desc);
	if (err < 0) {
		pfs_etrace("metacache check header failed");
		return false;
	}

	desc->csd_ioch_desc = pfsdev_open(desc->csd_cluster, desc->csd_pbdname,
	    DEVFLG_RD);
	if (desc->csd_ioch_desc < 0) {
		pfs_etrace("cant open pbd %s\n", desc->csd_pbdname);
		return false;
	}

	err = metacache_check_leader(desc->csd_meta_fd, desc->csd_ioch_desc);
	if (err < 0) {
		pfs_etrace("metacache paxos leader is invalid\n");
		goto out;
	}

	err = metacache_check_bust(desc);
	if (err < 0) {
		pfs_etrace("metacache BUST is invalid\n");
		goto out;
	}

	pfsdev_close(desc->csd_ioch_desc);
	desc->csd_ioch_desc = -1;
	return true;

out:
	pfsdev_close(desc->csd_ioch_desc);
	desc->csd_ioch_desc = -1;
	return false;
}

static uint64_t
mono2blkno(uint64_t btno)
{
	uint64_t ckno, btid;	/* chunk number and blktag id */
	uint32_t shift;

	shift = ffs(roundup_power2(PFS_NBT_PERCHUNK)) - 1;
	ckno = btno >> shift;
	btid = btno - (ckno << shift);
	return btid;
}

static void
visitfn_metaobj_used_block(void *data, pfs_metaobj_phy_t *mo)
{
	pfs_blktag_phy_t *blktag = MO2BT(mo);
	block_usedinfo_t *but = (block_usedinfo_t *)data;
	uint64_t blkno = mono2blkno(MONO_CURR(blktag));
	PFS_ASSERT(blkno < PFS_NBT_PERCHUNK);
	but[blkno].bu_blkno = blkno;

	if (mo->mo_used) {
		but[blkno].bu_holeoff = blktag->bt_holeoff;
		but[blkno].bu_used = 1;
	}
	else
		but[blkno].bu_used = 0;

}

static int
metacache_update(pfs_chunkstream_desc_t *desc)
{
	int err, fd;
	uint32_t ckid, crc;
	pfs_mount_t *mnt;
	ssize_t offset, wlen;
	block_usedinfo_t but[PFS_NBT_PERCHUNK];
	char sectbuf[PBD_SECTOR_SIZE];
	uint32_t butsz = sizeof(block_usedinfo_t) * PFS_NBT_PERCHUNK;
	metacache_header_t mh;
	uint32_t mhsz = sizeof(metacache_header_t);

	fd = desc->csd_meta_fd;
	err = ftruncate(fd, 0);
	if (err < 0) {
		pfs_etrace("truncate fd %d failed, err=%d, errno=%d\n",
		    fd, err, errno);
		return err;
	}

	err = pfs_mount(desc->csd_cluster, desc->csd_pbdname, 0, PFS_RD | PFS_TOOL);
	if (err < 0)
		return err;

	mnt = pfs_get_mount(desc->csd_pbdname);
	PFS_ASSERT(mnt != NULL && mnt->mnt_blksize == PFS_BLOCK_SIZE);

	mh.mh_magic = METACACHE_MAGIC;
	mh.mh_run_version = mnt->mnt_run_version;

	desc->csd_pfs_run_ver = mh.mh_run_version;
	desc->csd_nchunk = mnt->mnt_nchunk;
	/*
	 * metadata SHOULD be written into local metacache before paxos leader.
	 */
	offset = lseek(fd, PBD_SECTOR_SIZE + mhsz, SEEK_SET);
	if (offset != PBD_SECTOR_SIZE + mhsz)
		ERR_GOTO(errno, out);
	for (ckid = 0; ckid < desc->csd_nchunk; ckid++) {
		/*
		 * Only formatted chunk checks block used status.
		 */
		memset(but, 0, butsz);
		pfs_meta_visit(mnt, MT_BLKTAG, ckid, -1,
		    visitfn_metaobj_used_block, &but);

		crc = crc32c((uint32_t)~1, (uint8_t *)but, butsz);
		wlen = write(fd, &crc, sizeof(crc));
		if (wlen != sizeof(crc))
			ERR_GOTO(EIO, out);

		wlen = write(fd, but, butsz);
		if (wlen != butsz)
			ERR_GOTO(EIO, out);
	}

	/* cache paxos leader */
	memset(sectbuf, 0, PBD_SECTOR_SIZE);
	err = paxos_leader_read(mnt->mnt_ioch_desc, sectbuf, sizeof(sectbuf));
	if (err < 0)
		ERR_GOTO(EIO, out);
	wlen = pwrite(fd, sectbuf, PBD_SECTOR_SIZE, mhsz);
	if (wlen != PBD_SECTOR_SIZE)
		ERR_GOTO(EIO, out);

	wlen = pwrite(fd, &mh, mhsz, 0);
	if (wlen != mhsz)
		ERR_GOTO(EIO, out);

	pfs_itrace("update metafile successful\n");
	pfs_put_mount(mnt);
	pfs_umount(desc->csd_pbdname);
	return 0;

out:
	pfs_etrace("update metafile failed\n");
	pfs_put_mount(mnt);
	pfs_umount(desc->csd_pbdname);
	return err;
}

static void
metachache_close(pfs_chunkstream_desc_t *desc)
{
	close(desc->csd_meta_fd);
	desc->csd_meta_fd = -1;
}

static int
metacache_init(pfs_chunkstream_desc_t *desc)
{
	int err, fd;

	fd = metacache_open(desc->csd_pbdname,  O_CREAT | O_RDWR);
	if (fd < 0)
		return fd;

	desc->csd_meta_fd = fd;

	err = flock(fd, LOCK_EX);
	if (err < 0) {
		pfs_etrace("flock file for %s/pbd%s.metacache failed, err=%d,"
		    "errno=%d\n", meta_file_path, desc->csd_pbdname, err, errno);
		ERR_GOTO(errno, fail);
	}

	if (!metacache_isvalid(desc)) {
		pfs_itrace("metafile is invalid, update it\n");
		err = metacache_update(desc);
		if (err < 0)
			ERR_GOTO(EIO, fail);
	}

	flock(fd, LOCK_UN);
	pfs_itrace("desc init success\n");
	return 0;
fail:
	flock(fd, LOCK_UN);
	metachache_close(desc);
	return err;
}


static inline void
chunkheader_dump(const pfs_chunkfile_header_t *cf)
{
	pfs_itrace("Chunkfile header:\n"
	    "magic:0x%lx\nver:0x%lx\nctime:%lu\npbd:%s\ncksz:%lu\nblksz:%u\n"
	    "fragsz:%u\nsectsz:%u\nnck:%u\nckid:%u\nstreamsz:%lu\nenablecrc:%d\n"
	    "crcsz:%u\nmetasz:%u\n", cf->cf_magic, cf->cf_version, cf->cf_ctime,
	    cf->cf_pbdname, cf->cf_chunksz, cf->cf_blksz, cf->cf_fragsz,
	    cf->cf_sectsz, cf->cf_nchunk, cf->cf_ckid, cf->cf_streamsz,
	    cf->cf_enablecrc, cf->cf_crcsz, cf->cf_metasz);
}

static int
readstream_load(pfs_chunk_readstream_t *cr)
{
	off_t offset;
	uint32_t i, crc, fcrc, bustsz;
	ssize_t rlen;
	int err, fd, ckid;
	block_usedinfo_t* bust;
	pfs_chunkstream_desc_t *desc;
	bool holeoff;

	desc = cr->cr_chunk_stream.cs_desc;
	bustsz = sizeof(block_usedinfo_t) * PFS_NBT_PERCHUNK;
	bust = (block_usedinfo_t *)pfs_mem_malloc(bustsz, M_CHUNK_BLOCKUSED);
	if (bust == NULL)
		ERR_GOTO(ENOMEM, out);

	fd = desc->csd_meta_fd;
	ckid = cr->cr_chunk_stream.cs_ckid;
	holeoff = pfs_version_has_features(desc->csd_pfs_run_ver,
		    PFS_FEATURE_BLKHOLE);

	if (fd < 0)
		ERR_GOTO(EBADF, out);

	offset = sizeof(metacache_header_t) + PBD_SECTOR_SIZE + ckid *
	    (sizeof(fcrc) + bustsz);

	rlen = pread(fd, &fcrc, sizeof(fcrc), offset);
	if (rlen != sizeof(fcrc))
		ERR_GOTO(EIO, out);

	rlen = pread(fd, bust, bustsz, offset + sizeof(fcrc));
	if (rlen != bustsz)
		ERR_GOTO(EIO, out);

	crc = crc32c((uint32_t)~1, (uint8_t *)(bust), bustsz);
	if (crc != fcrc) {
		pfs_etrace("init metafile, chunk %d BUST crc is invalid %u vs"
		    " %u\n", ckid, crc, fcrc);
		ERR_GOTO(EINVAL, out);
	}

	for (i = 0; i < PFS_NBT_PERCHUNK; i++) {
		block_usedinfo_t *bu = &bust[i];
		if (!holeoff || (i == 0))
			bu->bu_holeoff = PFS_BLOCK_SIZE;

		block_meta_head_t *mh = &cr->cr_meta_buf[i];
		mh->mh_blko = bu->bu_blkno;
		if (bu->bu_used == 0 || bu->bu_holeoff == 0)
			mh->mh_datalen = 0;
		else
			mh->mh_datalen = roundup(bu->bu_holeoff, CHUNK_FRAG_SIZE);

		cr->cr_streamsz += mh->mh_datalen;
	}

	pfs_mem_free(bust, M_CHUNK_BLOCKUSED);
	return 0;
out:
	if (bust)
		pfs_mem_free(bust, M_CHUNK_BLOCKUSED);

	return err;
}

pfs_chunkstream_t *
pfs_chunk_readstream_open(const pfs_chunkstream_desc_t *desc, int chunkid)
{
	int err;
	pfs_chunk_readstream_t *cr;

	cr = (pfs_chunk_readstream_t *)pfs_mem_malloc(sizeof(*cr),
	    M_CHUNK_READSTREAM);
	if (cr == NULL) {
		pfs_etrace("mem alloc chunk stream failed!");
		return NULL;
	}

	cr->cr_metasz = roundup(sizeof(block_meta_head_t) * PFS_NBT_PERCHUNK,
	    CHUNK_FRAG_SIZE);
	cr->cr_meta_buf = (block_meta_head_t *)pfs_mem_malloc(cr->cr_metasz,
	    M_CHUNK_METABUF);
	if (cr->cr_meta_buf == NULL)
		ERR_GOTO(ENOMEM, fail);

	memset(cr->cr_meta_buf, 0, cr->cr_metasz);
	cr->cr_chunk_stream.cs_desc = (pfs_chunkstream_desc_t *)desc;
	cr->cr_chunk_stream.cs_ckid = chunkid;
	cr->cr_readsz = 0;
	cr->cr_streamsz = sizeof(pfs_chunkfile_header_t) + cr->cr_metasz;
	cr->cr_stage = CHUNK_READ_HEADER;

	err = readstream_load(cr);
	if (err != 0)
		ERR_GOTO(EIO, fail);

	if (chunk_enablecrc(desc)) {
		cr->cr_crcsz = roundup(sizeof(uint32_t) *
		    (cr->cr_streamsz / CHUNK_FRAG_SIZE), CHUNK_FRAG_SIZE);
		cr->cr_crc_buf = (uint32_t *)pfs_mem_malloc(cr->cr_crcsz,
		    M_CHUNK_CRCBUF);
		if (cr->cr_crc_buf == NULL)
			ERR_GOTO(ENOMEM, fail);
		memset(cr->cr_crc_buf, 0, cr->cr_crcsz);
		cr->cr_streamsz += cr->cr_crcsz;
	}

	if (cr->cr_streamsz % CHUNK_FRAG_SIZE != 0)
		ERR_GOTO(EINVAL, fail);

	cr->cr_metareadsz = 0;
	cr->cr_blkpos = PFS_NBT_PERCHUNK - 1;
	cr->cr_blkreadsz = 0;
	cr->cr_crcreadsz = 0;
	cr->cr_ncrcfrag = 0;

	pfs_itrace("open read stream success, pbdname=%s, io_desc=%d, metafd=%d,"
	    " ckid=%d, metasz=%u, streamsz=%lu, crcsz=%ld\n", desc->csd_pbdname,
	    desc->csd_ioch_desc, desc->csd_meta_fd,
	    cr->cr_chunk_stream.cs_ckid, cr->cr_metasz, cr->cr_streamsz,
	    cr->cr_crcsz);

	return (pfs_chunkstream_t *)cr;

fail:
	pfs_itrace("open read stream fail, pbdname=%s, io_desc=%d, metafd=%d,"
	    " ckid=%d, metasz=%u, streamsz=%lu\n", desc->csd_pbdname,
	    desc->csd_ioch_desc, desc->csd_meta_fd,
	    cr->cr_chunk_stream.cs_ckid, cr->cr_metasz, cr->cr_streamsz);

	if(cr->cr_meta_buf) {
		pfs_mem_free(cr->cr_meta_buf, M_CHUNK_METABUF);
		cr->cr_meta_buf = NULL;
	}

	if(cr->cr_crc_buf) {
		pfs_mem_free(cr->cr_crc_buf, M_CHUNK_CRCBUF);
		cr->cr_crc_buf = NULL;
	}

	pfs_mem_free(cr, M_CHUNK_READSTREAM);
	cr = NULL;
	return NULL;
}

pfs_chunkstream_t *
pfs_chunk_writestream_open(const pfs_chunkstream_desc_t *desc, int chunkid)
{
	pfs_chunk_writestream_t *cw;

	cw = (pfs_chunk_writestream_t *)pfs_mem_malloc(sizeof(*cw),
	    M_CHUNK_WRITESTREAM);
	if (cw == NULL) {
		pfs_etrace("mem alloc chunk stream failed!");
		return NULL;
	}
	cw->cw_chunk_stream.cs_desc = (pfs_chunkstream_desc_t *)desc;
	cw->cw_writesz = 0;
	cw->cw_chunk_stream.cs_ckid = chunkid;
	cw->cw_stage = CHUNK_WRITE_HEADER;
	cw->cw_blkpos = PFS_NBT_PERCHUNK - 1;
	cw->cw_blkwritesz = 0;
	cw->cw_metawritesz = 0;
	cw->cw_crcwritesz = 0;
	cw->cw_ncrcfrag = 0;

	pfs_itrace("open write stream, pbdname=%s, io_desc=%d, metafd=%d,"
	    "ckid=%d\n", desc->csd_pbdname, desc->csd_ioch_desc,
	    desc->csd_meta_fd, cw->cw_chunk_stream.cs_ckid);

	return (pfs_chunkstream_t *)cw;
}

static int
chunkheader_init(pfs_chunkfile_header_t *cf, const pfs_chunk_readstream_t *cr)
{
	memset(cf, 0, sizeof(*cf));
	cf->cf_magic = CHUNKFILE_MAGIC;
	cf->cf_version = CHUNKFILE_VERSION;
	cf->cf_ctime = time(NULL);
	cf->cf_enablecrc = chunk_enablecrc(cr->cr_chunk_stream.cs_desc);
	strncpy_safe(cf->cf_pbdname, cr->cr_chunk_stream.cs_desc->csd_pbdname,
	    sizeof(cf->cf_pbdname));
	cf->cf_chunksz = PBD_CHUNK_SIZE;
	cf->cf_blksz = PFS_BLOCK_SIZE;
	cf->cf_fragsz = PFS_FRAG_SIZE;
	cf->cf_sectsz = PBD_SECTOR_SIZE;
	cf->cf_nchunk = cr->cr_chunk_stream.cs_desc->csd_nchunk;
	cf->cf_ckid = cr->cr_chunk_stream.cs_ckid;
	cf->cf_metasz = cr->cr_metasz;
	cf->cf_streamsz = cr->cr_streamsz;
	cf->cf_crcsz = cr->cr_crcsz;

	return sizeof(*cf);
}

static int
block_read(void *buf, size_t blksz, const pfs_chunkfile_header_t *cf, int iodesc,
    uint64_t bda)
{
	int err;
	char *ptr;
	pfs_bda_t fragbda;
	uint64_t rsum;
	size_t rlen, left;

	PFS_ASSERT(cf->cf_fragsz == PFS_FRAG_SIZE);

	fragbda = bda;
	ptr = (char *)buf;
	for (rsum = 0; rsum < blksz; rsum += rlen) {
		left = blksz - rsum;
		rlen = MIN(cf->cf_fragsz, left);
		err = pfsdev_pread_flags(iodesc, ptr, rlen, fragbda, IO_NOWAIT);
		if (err < 0) {
			pfs_etrace("Read chunk %u %lu failed, err=%d\n",
			    cf->cf_ckid, fragbda, err);
			return err;
		}
		fragbda += rlen;
		ptr += rlen;
	}

	err = pfsdev_wait_io(iodesc);
	if (err < 0) {
		pfs_etrace("Read chunk %u failed, err=%d\n", cf->cf_ckid, err);
		return err;
	}
	return 0;
}

static int
block_write(const void *buf, size_t blksz, const pfs_chunkfile_header_t *cf,
    int iodesc, int64_t bda)
{
	int err;
	char *ptr;
	pfs_bda_t fragbda;
	uint64_t wsum;
	size_t wlen, left;

	PFS_ASSERT(cf->cf_fragsz == PFS_FRAG_SIZE);

	ptr = (char *)buf;
	fragbda = bda;
	for (wsum = 0; wsum < blksz; wsum += wlen) {
		left = blksz - wsum;
		wlen = MIN(cf->cf_fragsz, left);
		err = pfsdev_pwrite_flags(iodesc, ptr, wlen, fragbda, IO_NOWAIT);
		if (err < 0) {
			pfs_etrace("Write chunk %u %lu failed, err=%d\n",
			    cf->cf_ckid, fragbda, err);
			return err;
		}
		fragbda += wlen;
		ptr += wlen;
	}

	err = pfsdev_wait_io(iodesc);
	if (err < 0) {
		pfs_etrace("Write chunk %u failed, err=%d\n", cf->cf_ckid, err);
		return err;
	}
	return 0;
}


int
pfs_chunk_backup_init(pfs_chunkstream_desc_t *desc)
{
	int err;

	err = metacache_init(desc);
	if (err < 0)
		return err;

	desc->csd_ioch_desc = pfsdev_open(desc->csd_cluster,
	    desc->csd_pbdname, DEVFLG_RDWR);
	if (desc->csd_ioch_desc < 0) {
		pfs_etrace("cant open pbd %s\n", desc->csd_pbdname);
		metachache_close(desc);
		return -EINVAL;
	}

	pfs_itrace("chunk backup init. pbdname=%s, nchunk=%d, io_desc=%d, "
	    "meta_fd=%d, flags=%d\n", desc->csd_pbdname, desc->csd_nchunk,
	    desc->csd_ioch_desc, desc->csd_meta_fd, desc->csd_flags);
	return 0;
}

int
pfs_chunk_restore_init(pfs_chunkstream_desc_t *desc)
{
	desc->csd_ioch_desc = pfsdev_open(desc->csd_cluster,
	    desc->csd_pbdname, DEVFLG_RDWR);
	if (desc->csd_ioch_desc < 0) {
		pfs_etrace("cant open pbd %s\n", desc->csd_pbdname);
		return -EINVAL;
	}

	pfs_itrace("chunk restore init. pbdname=%s, nchunk=%d, io_desc=%d,"
	    "meta_fd=%d\n", desc->csd_pbdname, desc->csd_nchunk,
	    desc->csd_ioch_desc, desc->csd_meta_fd);
	return 0;
}

static void
chunk_read_header(pfs_chunk_readstream_t *cr, char *buf, ssize_t *rlen)
{
	*rlen = chunkheader_init(&cr->cr_cf, cr);
	memcpy(buf, &cr->cr_cf, *rlen);
	cr->cr_chunk_stream.cs_time_us =  gettimeofday_us();
	cr->cr_stage = CHUNK_READ_META;
}

static void
chunk_read_meta(pfs_chunk_readstream_t *cr, char *buf, ssize_t *rlen,
    ssize_t left)
{
	char *meta_buf = NULL;

	*rlen = MIN(cr->cr_metasz - cr->cr_metareadsz, left);
	meta_buf = (char *)cr->cr_meta_buf + cr->cr_metareadsz;
	memcpy(buf, meta_buf, *rlen);
	cr->cr_metareadsz += *rlen;

	if (cr->cr_metareadsz == cr->cr_metasz)
		cr->cr_stage = CHUNK_READ_DATA;
}

static inline void
chunk_read_block_next(pfs_chunk_readstream_t *cr)
{
	cr->cr_blkpos--;
	cr->cr_blkreadsz = 0;
}

static int
chunk_read_data(pfs_chunk_readstream_t *cr, char *buf, ssize_t *rlen,
    ssize_t left)
{
	int err;
	int ioch = cr->cr_chunk_stream.cs_desc->csd_ioch_desc;
	uint64_t fragbda;
	const pfs_chunkfile_header_t *cf = &cr->cr_cf;

	if (cr->cr_blkpos < 0) {
		if (chunk_enablecrc(cr->cr_chunk_stream.cs_desc))
			cr->cr_stage = CHUNK_READ_CRC;
		return 0;
	}

	const block_meta_head_t *mh = &cr->cr_meta_buf[cr->cr_blkpos];
	if (mh->mh_blko != cr->cr_blkpos) {
		pfs_etrace("read metablk(%ld) not match blkpos(%ld)\n",
		    mh->mh_blko, cr->cr_blkpos);
		return -EINVAL;
	}

	if (mh->mh_datalen == 0) {
		chunk_read_block_next(cr);
		return 0;
	}

	*rlen = MIN(mh->mh_datalen - cr->cr_blkreadsz, left);
	if(mh->mh_datalen % CHUNK_FRAG_SIZE != 0) {
		pfs_etrace("invalid data len(%ld)\n", mh->mh_datalen);
		return -EINVAL;
	}

	if(*rlen % CHUNK_FRAG_SIZE  != 0) {
		pfs_etrace("invalid  rlen(%ld)\n", *rlen);
		return -EINVAL;
	}

	fragbda = cf->cf_ckid * cf->cf_chunksz + cr->cr_blkpos * cf->cf_blksz
	    + cr->cr_blkreadsz;
	err = block_read(buf, *rlen, cf, ioch, fragbda);
	if (err < 0)
		return err;

	cr->cr_blkreadsz += *rlen;
	if (cr->cr_blkreadsz == mh->mh_datalen) {
		chunk_read_block_next(cr);
	}

	return 0;
}

static void
chunk_read_crc(pfs_chunk_readstream_t *cr, char *buf, ssize_t *rlen,
    ssize_t left)
{
	char *crc_buf = NULL;

	*rlen = MIN(cr->cr_crcsz - cr->cr_crcreadsz, left);
	crc_buf = (char *)cr->cr_crc_buf + cr->cr_crcreadsz;
	memcpy(buf, crc_buf, *rlen);
	cr->cr_crcreadsz += *rlen;
}

static int
chunk_read_finish(pfs_chunk_readstream_t *cr)
{
	uint64_t end;
	int64_t ncrcfrag;

	if (cr->cr_readsz != cr->cr_streamsz) {
		pfs_etrace("read failed! readsz=%ld, streasz=%ld\n",
		    cr->cr_readsz, cr->cr_streamsz);
		return -EINVAL;
	}

	if (chunk_enablecrc(cr->cr_chunk_stream.cs_desc)) {
		ncrcfrag = (cr->cr_streamsz - cr->cr_crcsz) / CHUNK_FRAG_SIZE;
		if (cr->cr_ncrcfrag != ncrcfrag) {
			pfs_etrace("read finish failed, realcrcfrag(%ld) not "
			    "equal ncrcfrag(%ld)\n", cr->cr_ncrcfrag, ncrcfrag);
			return -EINVAL;
		}
	}

	cr->cr_stage = CHUNK_READ_FINISH;
	end = gettimeofday_us();
	pfs_itrace("read finish, read_size(%ld), time_cost_sec(%lu), ckid=%d\n",
	    cr->cr_readsz, (end - cr->cr_chunk_stream.cs_time_us)/1000/1000,
	    cr->cr_chunk_stream.cs_ckid);
	return 0;
}

static void
chunk_calc_frag_crc(const char *src_buf, uint32_t *dst_buf, int64_t len,
    int64_t *ncrcfrag)
{
	int i, nfrag;
	uint32_t crc;
	char *ptr = (char *)src_buf;

	if (len <= 0)
		return;

	nfrag = len / CHUNK_FRAG_SIZE;
	for (i = 0; i < nfrag; i++) {
		crc = crc32c((uint32_t)~1, ptr, CHUNK_FRAG_SIZE);
		dst_buf[(*ncrcfrag)++] = crc;
		ptr += CHUNK_FRAG_SIZE;
	}
}

int64_t
pfs_chunk_readstream(pfs_chunkstream_t *cs, char *buf, size_t len)
{
	int err;
	char *data_buf = NULL;
	pfs_chunk_readstream_t *cr = (pfs_chunk_readstream_t *)cs;
	ssize_t rlen, rsum, left;

	if (len % CHUNK_FRAG_SIZE != 0) {
		pfs_etrace("invalid len(%ld)\n", len);
		return -EINVAL;
	}

	if (cr->cr_stage == CHUNK_READ_FINISH)
		return 0;

	for (rsum = 0; rsum < (ssize_t)len;) {
		left = len - rsum;
		data_buf = buf + rsum;
		rlen = 0;

		if (left % CHUNK_FRAG_SIZE != 0) {
			pfs_etrace("invalid left(%ld)\n", left);
			return -EINVAL;
		}

		switch(cr->cr_stage) {
		case CHUNK_READ_HEADER:
			chunk_read_header(cr, data_buf, &rlen);
			break;
		case CHUNK_READ_META:
			chunk_read_meta(cr, data_buf, &rlen, left);
			break;
		case CHUNK_READ_DATA:
			err = chunk_read_data(cr, data_buf, &rlen, left);
			if (err < 0)
				return err;
			break;
		case CHUNK_READ_CRC:
			chunk_read_crc(cr, data_buf, &rlen, left);
			break;
		default:
			pfs_etrace("invalid stage(%d)\n", cr->cr_stage);
			return -EINVAL;
		}

		if (rlen % CHUNK_FRAG_SIZE != 0) {
			pfs_etrace("invalid left(%ld)\n", rlen);
			return -EINVAL;
		}

		cr->cr_readsz += rlen;
		rsum += rlen;

		if (cr->cr_stage != CHUNK_READ_CRC &&
		    chunk_enablecrc(cs->cs_desc))
			chunk_calc_frag_crc(data_buf, cr->cr_crc_buf, rlen,
			    &cr->cr_ncrcfrag);

		if (cr->cr_readsz >= cr->cr_streamsz) {
			err = chunk_read_finish(cr);
			if (err < 0)
				return err;
			return rsum;
		}
	}

	return rsum;
}

static int
chunk_write_crc_buf_init(pfs_chunk_writestream_t *cw)
{
	uint32_t crcsz;

	crcsz = cw->cw_ck_header.cf_crcsz;
	if (crcsz == 0 || crcsz % CHUNK_FRAG_SIZE != 0)
		return EINVAL;
	cw->cw_ccrc_buf = (uint32_t *)pfs_mem_malloc(crcsz, M_CHUNK_CRCBUF);
	if (cw->cw_ccrc_buf == NULL)
		return ENOMEM;
	cw->cw_fcrc_buf = (uint32_t *)pfs_mem_malloc(crcsz, M_CHUNK_CRCBUF);
	if (cw->cw_fcrc_buf == NULL)
		return ENOMEM;
	memset(cw->cw_ccrc_buf, 0, crcsz);
	memset(cw->cw_fcrc_buf, 0, crcsz);
	return 0;
}

static int
chunk_write_header(pfs_chunk_writestream_t *cw, const char *buf, ssize_t *wlen)
{
	int err = 0;
	uint64_t streamsz;
	uint32_t metasz;

	cw->cw_ck_header = *(pfs_chunkfile_header_t *)buf;

	chunkheader_dump(&cw->cw_ck_header);

	if (cw->cw_ck_header.cf_magic != CHUNKFILE_MAGIC)
		ERR_GOTO(EINVAL, out);
	if (cw->cw_ck_header.cf_version != CHUNKFILE_VERSION)
		ERR_GOTO(EINVAL, out);
	if (cw->cw_ck_header.cf_chunksz != PBD_CHUNK_SIZE)
		ERR_GOTO(EINVAL, out);
	if (cw->cw_ck_header.cf_blksz != PFS_BLOCK_SIZE)
		ERR_GOTO(EINVAL, out);
	if (cw->cw_ck_header.cf_fragsz != PFS_FRAG_SIZE)
		ERR_GOTO(EINVAL, out);
	if (cw->cw_ck_header.cf_sectsz != PBD_SECTOR_SIZE)
		ERR_GOTO(EINVAL, out);

	streamsz = cw->cw_ck_header.cf_streamsz;
	metasz = cw->cw_ck_header.cf_metasz;
	if (streamsz == 0 || streamsz % CHUNK_FRAG_SIZE != 0)
		ERR_GOTO(EINVAL, out);
	if (metasz == 0 || metasz % CHUNK_FRAG_SIZE != 0)
		ERR_GOTO(EINVAL, out);

	if (cw->cw_ck_header.cf_enablecrc) {
		err = chunk_write_crc_buf_init(cw);
		if (0 != err)
			ERR_GOTO(err, out);
	}

	cw->cw_chunk_stream.cs_time_us =  gettimeofday_us();
	cw->cw_meta_buf = (block_meta_head_t *)pfs_mem_malloc(metasz,
	    M_CHUNK_METABUF);
	if (cw->cw_meta_buf == NULL)
		ERR_GOTO(ENOMEM, out);
	*wlen = sizeof(cw->cw_ck_header);

	cw->cw_stage = CHUNK_WRITE_META;
out:
	return err;
}

static void
chunk_write_meta(pfs_chunk_writestream_t *cw, const char *buf, ssize_t *wlen,
    ssize_t left)
{
	char *meta_buf = NULL;

	*wlen = MIN(cw->cw_ck_header.cf_metasz - cw->cw_metawritesz, left);
	meta_buf = (char *)cw->cw_meta_buf + cw->cw_metawritesz;
	memcpy(meta_buf, buf, *wlen);
	cw->cw_metawritesz += *wlen;

	if (cw->cw_metawritesz == cw->cw_ck_header.cf_metasz)
		cw->cw_stage = CHUNK_WRITE_DATA;
}

static inline void
chunk_write_block_next(pfs_chunk_writestream_t *cw)
{
	cw->cw_blkpos--;
	cw->cw_blkwritesz = 0;
}

static int
chunk_write_data(pfs_chunk_writestream_t *cw, const char *buf, ssize_t *wlen,
    ssize_t left)
{
	int err;
	int ioch = cw->cw_chunk_stream.cs_desc->csd_ioch_desc;
	uint64_t fragbda;
	const pfs_chunkfile_header_t *cf = &cw->cw_ck_header;

	if (cw->cw_blkpos < 0) {
		if (cw->cw_ck_header.cf_enablecrc)
			cw->cw_stage = CHUNK_WRITE_CRC;
		return 0;
	}

	block_meta_head_t *mh = &cw->cw_meta_buf[cw->cw_blkpos];
	if (mh->mh_blko != cw->cw_blkpos) {
		pfs_etrace("write metablk(%ld) not match blkpos(%ld)\n",
		    mh->mh_blko, cw->cw_blkpos);
		return -EINVAL;
	}

	if (mh->mh_datalen == 0) {
		chunk_write_block_next(cw);
		return 0;
	}

	*wlen = MIN(mh->mh_datalen - cw->cw_blkwritesz, left);
	if(mh->mh_datalen % CHUNK_FRAG_SIZE != 0) {
		pfs_etrace("invalid data len(%ld)\n", mh->mh_datalen);
		return -EINVAL;
	}

	if(*wlen % CHUNK_FRAG_SIZE  != 0) {
		pfs_etrace("invalid  wlen(%ld)\n", *wlen);
		return -EINVAL;
	}

	fragbda = cf->cf_ckid * cf->cf_chunksz + cw->cw_blkpos * cf->cf_blksz
	    + cw->cw_blkwritesz;
	err = block_write(buf, *wlen, cf, ioch, fragbda);
	if (err < 0)
		return err;

	cw->cw_blkwritesz += *wlen;
	if (cw->cw_blkwritesz == mh->mh_datalen) {
		chunk_write_block_next(cw);
	}

	return 0;
}

static void
chunk_write_crc(pfs_chunk_writestream_t *cw, char *buf, ssize_t *wlen,
    ssize_t left)
{
	char *crc_buf = NULL;

	*wlen = MIN(cw->cw_ck_header.cf_crcsz - cw->cw_crcwritesz, left);
	crc_buf = (char *)cw->cw_fcrc_buf + cw->cw_crcwritesz;
	memcpy(crc_buf, buf, *wlen);
	cw->cw_crcwritesz += *wlen;
}

static int
chunk_write_finish(pfs_chunk_writestream_t *cw)
{
	int err;
	uint64_t end;

	if (cw->cw_writesz != cw->cw_ck_header.cf_streamsz) {
		pfs_etrace("write failed! writesz=%ld, streasz=%ld\n",
		    cw->cw_writesz, cw->cw_ck_header.cf_streamsz);
		return -EINVAL;
	}

	if (cw->cw_ck_header.cf_enablecrc &&
	    memcmp(cw->cw_ccrc_buf, cw->cw_fcrc_buf,
	    cw->cw_ck_header.cf_crcsz) != 0) {
		pfs_etrace("crc compare failed! crc1=%u, crc2=%u, size=%u\n",
		cw->cw_ccrc_buf[0], cw->cw_fcrc_buf[1], cw->cw_ck_header.cf_crcsz);
		return -EINVAL;
	}

	if (cw->cw_chunk_stream.cs_ckid == 0) {
		err = paxos_leader_reset(
		    cw->cw_chunk_stream.cs_desc->csd_ioch_desc,
		    cw->cw_chunk_stream.cs_desc->csd_pbdname);
		if (err < 0)
			return err;
	}

	cw->cw_stage = CHUNK_WRITE_FINISH;

	end = gettimeofday_us();
	pfs_itrace("write finish, write_size(%ld), time_cost_sec(%lu),ckid=%d\n",
	    cw->cw_writesz, (end - cw->cw_chunk_stream.cs_time_us)/1000/1000,
	    cw->cw_chunk_stream.cs_ckid);
	return 0;
}

int64_t
pfs_chunk_writestream(pfs_chunkstream_t *cs, const char *buf, size_t len)
{
	int err;
	pfs_chunk_writestream_t *cw = (pfs_chunk_writestream_t *)cs;
	char *data_buf = NULL;
	ssize_t wlen, wsum, left;

	if (len % CHUNK_FRAG_SIZE != 0) {
		pfs_etrace("invalid len(%ld)\n", len);
		return -EINVAL;
	}

	if (cw->cw_stage == CHUNK_WRITE_FINISH)
		return 0;

	for (wsum = 0; wsum < (ssize_t)len;) {
		left = len - wsum;
		data_buf = (char *)buf + wsum;
		wlen = 0;

		if (left % CHUNK_FRAG_SIZE != 0) {
			pfs_etrace("invalid left(%ld)\n", left);
			return -EINVAL;
		}

		switch(cw->cw_stage) {
		case CHUNK_WRITE_HEADER:
			err = chunk_write_header(cw, data_buf, &wlen);
			if (err < 0)
				return err;
			break;
		case CHUNK_WRITE_META:
			chunk_write_meta(cw, data_buf, &wlen, left);
			break;
		case CHUNK_WRITE_DATA:
			err = chunk_write_data(cw, data_buf, &wlen, left);
			if (err < 0)
				return err;
			break;
		case CHUNK_WRITE_CRC:
			chunk_write_crc(cw, data_buf, &wlen, left);
			break;
		default:
			pfs_etrace("invalid stage(%d)\n", cw->cw_stage);
			return -EINVAL;
		}

		if (wlen % CHUNK_FRAG_SIZE != 0) {
			pfs_etrace("invalid wlen(%ld)\n", wlen);
			return -EINVAL;
		}

		cw->cw_writesz += wlen;
		wsum += wlen;

		if (cw->cw_stage != CHUNK_WRITE_CRC &&
		    cw->cw_ck_header.cf_enablecrc)
			chunk_calc_frag_crc(data_buf, cw->cw_ccrc_buf, wlen,
			    &cw->cw_ncrcfrag);

		if (cw->cw_writesz >= cw->cw_ck_header.cf_streamsz) {
			err = chunk_write_finish(cw);
			if (err < 0)
				return err;
			return wsum;
		}
	}
	return wsum;
}

void
pfs_chunk_readstream_close(pfs_chunkstream_t *cs)
{
	pfs_itrace("close read stream, ckid=%d\n", cs->cs_ckid);
	pfs_chunk_readstream_t *cr = (pfs_chunk_readstream_t *)cs;

	if(chunk_enablecrc(cs->cs_desc)) {
		pfs_mem_free(cr->cr_crc_buf, M_CHUNK_CRCBUF);
		cr->cr_crc_buf = NULL;
	}

	pfs_mem_free(cr->cr_meta_buf, M_CHUNK_METABUF);
	cr->cr_meta_buf = NULL;

	pfs_mem_free(cr, M_CHUNK_READSTREAM);
	cr = NULL;
}

void
pfs_chunk_writesteam_close(pfs_chunkstream_t *cs)
{
	pfs_itrace("close write stream, ckid=%d\n", cs->cs_ckid);
	pfs_chunk_writestream_t *cw = (pfs_chunk_writestream_t *)cs;

	if (cw->cw_meta_buf) {
		pfs_mem_free(cw->cw_meta_buf, M_CHUNK_METABUF);
		cw->cw_meta_buf = NULL;
	}

	if(cw->cw_ck_header.cf_enablecrc) {
		if (cw->cw_fcrc_buf) {
			pfs_mem_free(cw->cw_fcrc_buf, M_CHUNK_CRCBUF);
			cw->cw_fcrc_buf = NULL;
		}

		if (cw->cw_ccrc_buf) {
			pfs_mem_free(cw->cw_ccrc_buf, M_CHUNK_CRCBUF);
			cw->cw_ccrc_buf = NULL;
		}
	}

	pfs_mem_free(cw, M_CHUNK_WRITESTREAM);
	cw = NULL;
}

void
pfs_chunk_fini(pfs_chunkstream_desc_t *desc)
{
	pfs_itrace("pfs chunk fini\n");
	if (desc->csd_ioch_desc >= 0) {
		pfsdev_close(desc->csd_ioch_desc);
	}

	if (desc->csd_meta_fd >= 0) {
		close(desc->csd_meta_fd);
	}

	pfs_mem_free(desc, M_CHUNK_META);
	desc = NULL;
}

int
pfs_chunk_readstream_isfinish(pfs_chunkstream_t *cs)
{
	pfs_chunk_readstream_t *cr = (pfs_chunk_readstream_t *)cs;
	if (cr->cr_readsz == cr->cr_streamsz)
		return 0;
	return 1;
}

int
pfs_chunk_writestream_isfinish(pfs_chunkstream_t *cs)
{
	pfs_chunk_writestream_t *cw = (pfs_chunk_writestream_t *)cs;
	if (cw->cw_ck_header.cf_streamsz != 0 &&
	    cw->cw_writesz == cw->cw_ck_header.cf_streamsz)
		return 0;
	return 1;
}

pfs_chunkstream_desc_t *
pfs_chunkstream_init(const char *cluster, const char *pbdname, int flags)
{
	int err;
	pfs_chunkstream_desc_t *desc = NULL;

	if (cluster == NULL)
		cluster = CL_DEFAULT;

	if (pbdname == NULL) {
		pfs_etrace("pbdname is NULL, cluster=%s, mode=%d\n", cluster,
		    flags);
		return NULL;
	}

	desc = (pfs_chunkstream_desc_t *)pfs_mem_malloc(sizeof(*desc),
	    M_CHUNK_META);
	if (desc == NULL) {
		pfs_etrace("mem alloc desc failed!\n");
		return NULL;
	}

	err = strncpy_safe(desc->csd_pbdname, pbdname, PFS_MAX_PBDLEN);
	if (err < 0) {
		pfs_etrace("cp pbdname(%s) failed\n", pbdname);
		goto fail;
	}

	err = strncpy_safe(desc->csd_cluster, cluster, PFS_MAX_CLUSTERLEN);
	if (err < 0) {
		pfs_etrace("cp cluster(%s) failed\n", cluster);
		goto fail;
	}

	desc->csd_flags = flags;
	if (pfs_chunk_isbackup(flags)) {
		if (flags & CHUNK_RESTORE) {
			pfs_etrace("backup do not support restore flag(%d)\n",
			    flags);
			goto fail;
		}
		err = pfs_chunk_backup_init(desc);
	}
	else if (pfs_chunk_isrestore(flags)) {
		if (flags & CHUNK_CRC || flags & CHUNK_BACKUP) {
			pfs_etrace("restore invalid flag(%d)\n", flags);
			goto fail;
		}
		err = pfs_chunk_restore_init(desc);
	}
	else {
		pfs_etrace("invalid flags(%d), pbdname=%s, cluster=%s\n",
		    flags, pbdname, cluster);
		goto fail;
	}

	if (err < 0)
		ERR_GOTO(err, fail);
	return desc;
fail:
	pfs_mem_free(desc, M_CHUNK_META);
	desc = NULL;
	return NULL;
}

pfs_chunkstream_t *
pfs_chunkstream_open(const pfs_chunkstream_desc_t *desc, int chunkid)
{
	int flags;
	pfs_chunkstream_t * chunkstream = NULL;

	if (desc == NULL) {
		pfs_etrace("open desc is NULL");
		return NULL;
	}

	flags = desc->csd_flags;

	if (pfs_chunk_isbackup(flags))
		chunkstream = pfs_chunk_readstream_open(desc, chunkid);
	else if (pfs_chunk_isrestore(flags))
		chunkstream = pfs_chunk_writestream_open(desc, chunkid);
	else
		pfs_etrace("invalid flags(%d), pbdname=%s \n", flags,
		    desc->csd_pbdname);

	return chunkstream;
}

int64_t
pfs_chunkstream_read(pfs_chunkstream_t *stream, char *buf, size_t len)
{
	if (stream == NULL || buf == NULL || len <= 0)
		return -EINVAL;

	return pfs_chunk_readstream(stream, buf, len);
}

int64_t
pfs_chunkstream_write(pfs_chunkstream_t *stream, const char *buf, size_t len)
{
	if (stream == NULL || buf == NULL || len <=0)
		return -EINVAL;

	return pfs_chunk_writestream(stream, buf, len);
}

int
pfs_chunkstream_close(pfs_chunkstream_t *stream)
{
	int flags;

	if (stream == NULL) {
		pfs_etrace("close stream is NULL");
		return -EINVAL;
	}

	flags = stream->cs_desc->csd_flags;
	if (pfs_chunk_isbackup(flags))
		pfs_chunk_readstream_close(stream);
	else if (pfs_chunk_isrestore(flags))
		pfs_chunk_writesteam_close(stream);
	else {
		pfs_etrace("invalid mode(%d), pbdname=%s \n", flags,
		    stream->cs_desc->csd_pbdname);
		return -EINVAL;
	}

	return 0;
}

int
pfs_chunkstream_fini(pfs_chunkstream_desc_t *desc)
{
	if (desc == NULL) {
		pfs_etrace("close desc is NULL");
		return -EINVAL;
	}

	pfs_chunk_fini(desc);
	return 0;
}

int
pfs_chunkstream_isfinish(pfs_chunkstream_t *stream)
{
	int flags, err;

	if (stream == NULL) {
		pfs_etrace("eof stream is NULL");
		return -EINVAL;
	}

	flags = stream->cs_desc->csd_flags;
	if (pfs_chunk_isbackup(flags))
		err = pfs_chunk_readstream_isfinish(stream);
	else if (pfs_chunk_isrestore(flags))
		err = pfs_chunk_writestream_isfinish(stream);
	else {
		pfs_etrace("invalid mode(%d), pbdname=%s \n", flags,
		    stream->cs_desc->csd_pbdname);
		return -EINVAL;
	}

	return err;
}

void
pfs_chunkstream_get_nchunk(const pfs_chunkstream_desc_t *desc, int *nchunk)
{
	*nchunk = desc->csd_nchunk;
}
