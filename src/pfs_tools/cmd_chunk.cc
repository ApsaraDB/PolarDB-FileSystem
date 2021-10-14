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

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>

#include "cmd_impl.h"
#include "pfs_impl.h"
#include "pfs_mount.h"
#include "pfs_meta.h"
#include "pfs_util.h"
#include "pfs_tx.h"
#include "pfs_paxos.h"

#ifndef PFS_DISK_IO_ONLY
#include "pfs_iochnl.h"
#endif

/*
 * a. Block used status table(BUST)
 * ------
 *
 * A BUST records every block's used status. It is a bool array with fixed size
 * PFS_NBT_PERCHUNK. Its index means the block index in current chunk(starts
 * from 0). Its value means whether the block is used.
 *
 * b. Used block table(UBT)
 * ------
 *
 * An UBT records all used blocks position ([0, PFS_NBT_PERCHUNK)) in one
 * chunk. Its index means the block index in stream(or oss file). Its value
 * means the block position in chunk.
 *
 * Block ids in an UBT are in descending order, which means superblock(block id
 * is 0) is usually written at last. When restore cmd restries, the superblock
 * would not be regarded as formatted improperly.
 *
 * c. Local metacache
 * ------
 *
 * A local metacache includes BUST information of whole pbd. Its local path is
 * usually '/var/run/pfs/pbd{pbdno-version}.metacache'.
 * The BUST number in metacache must be equal with total chunk number in pbd.
 *
 * Local metacache consists of two parts: paxos leader and BUSTs.
 *     { paxos leader record(4KB) } | { {CK0: CRC | BUST0} ... {CKn} }
 * Both paxos leader and BUST have crc. If any crc or chunk number mismatches,
 * the metafile is invalid. Paxos leader is used to check whether metafile is
 * stale(although it's impossible for SNAPSHOT).
 *
 * d. OSS file
 * ------
 *
 * An backup OSS file include 3 parts: oss file header, UBT and blocks data.
 *     { OSS file header(4KB) | one UBT | n Blocks(4MB/block) }
 *
 * 1. Backup
 * ------
 *
 * Backup cmd firstly tries to load BUST of current chunk from local metacache.
 * If local metafile is invalid, pfstool would mount pbd and update metacache.
 * The pbd must be a SNAPSHOT so the local metafile is always the same with
 * what in pbd. This strategy could avoid loading whole metadata and journal
 * from pbd when pfstool starts.
 *
 * After get BUST, backup cmd inits UBT and then uploads oss file header,
 * UBT of current chunk, used blocks data to stdout.
 *
 * Note:
 * A snapshot maybe created during growfs, new chunks' UBTs are empty. These
 * new chunks oss file only has an oss file header.
 * When backup a empty chunk, a flag '-f' is needed.
 *
 * 2. Restore
 * ------
 *
 * Restore cmd reads all data from stdin. It firstly reads oss file header with
 * a fixed length(4KB) and the UBT, then reads all used blocks data and writes to
 * their relevant positions in PBD.
 *
 * Note:
 * When restore oss to a formatted chunk, a flag '-f' is needed.
 */

#define OSSFILE_MAGIC	0x4F535346494C45	/* OSSFILE */
#define OSSFILE_VERSION 0x01
typedef struct pfs_ossfile_header {
	/* header info */
	uint64_t	oss_magic;
	uint64_t	oss_version;
	uint64_t	oss_ctime;	/* create time, unit is second */
	uint32_t	oss_checksum;

	/* pbd info */
	char		oss_pbdname[PFS_MAX_PBDLEN];
	uint64_t	oss_chunksize;
	uint32_t	oss_blksize;
	uint32_t	oss_fragsize;
	uint32_t	oss_sectsize;

	/* chunk info */
	uint32_t	oss_nsumck;	/* total chunk number of PBD */
	uint32_t	oss_nchunk;	/* formatted chunk number of PBD */
	uint32_t	oss_ckid;	/* chunkid of this oss object */

	/* used blk info */
	uint32_t	oss_nusedblk;	/* used blk number, if chunk isn't
					   formatted, its value is 0. */
}__attribute__((aligned(4096))) pfs_ossfile_header_t;

enum {
	MODE_INVALID	= 0,
	MODE_BACKUP	= 1,
	MODE_RESTORE	= 2
};
typedef struct opts_chunk {
	opts_common_t	common;
	int		mode;
	int32_t		ckid; /* start ckid */
	int32_t		endckid; /* end ckid, may not exist */
	bool		force;
} opts_chunk_t;

static const char	*metapath = "/var/run/pfs";
static const char	*cluster;
static const char	*pbdname;
static int		ioch_desc = -1;
static char		blkbuf[PFS_BLOCK_SIZE];
static char		sectbuf[PBD_SECTOR_SIZE];

static struct option chunk_long_opts[] = {
	{ "mode",		required_argument,	NULL,	'm' },
	{ "chunkid",		required_argument,	NULL,	'c' },
	{ "endchunkid",		optional_argument,	NULL,	'e' },
	{ "force",		optional_argument,	NULL,	'f' },
	{ 0 },
};

void
usage_chunk()
{
	printf("pfs chunk [-m|--mode=<backup|restore>] [-c|--chunkid=<chunkid>] [-e|--endchunkid=<chunkid>] [-f|--force] pbdno-version\n"
	    "    -m, --mode: work mode:\n"
	    "        backup: backup a chunk into stdout\n"
	    "        restore: restore a chunk from stdin\n"
	    "    -c, --chunkid: chunkid, start from 0\n"
	    "    -e, --endchunkid: endchunkid, bigger than chunkid, chunks between [chunkid, endchunkid) will be processed\n"
	    "    -f, --force: backup/restore forcedly (default is disabled)\n");
}

int
getopt_chunk(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_chunk_t *co_chunk = (opts_chunk_t *)co;

	co_chunk->mode = MODE_INVALID;
	co_chunk->ckid = -1;
	co_chunk->endckid = -1;
	co_chunk->force = false;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hc:e:m:f",  chunk_long_opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			co_chunk->ckid =  strtol(optarg, NULL, 10);
			break;

		case 'e':
			co_chunk->endckid = strtol(optarg, NULL, 10);
			break;

		case 'm':
			if (strncmp(optarg, "backup", 6) == 0)
				co_chunk->mode = MODE_BACKUP;
			else if (strncmp(optarg, "restore", 7) == 0)
				co_chunk->mode = MODE_RESTORE;
			else {
				pfs_etrace("unknown mode %s\n", optarg);
				return -1;
			}
			break;

		case 'f':
			co_chunk->force = true;
			break;

		case 'h':
		default:
			return -1;
		}
	}

	if (co_chunk->ckid < 0 || co_chunk->mode == MODE_INVALID) {
		return -1;
	} else {
		if (co_chunk->endckid == -1)
			co_chunk->endckid = co_chunk->ckid + 1;
		else if (co_chunk->endckid <= co_chunk->ckid)
			return -1;

		return optind;
	}
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

int
paxos_leader_reset(int devi, const char *pbdname)
{
	return 0;
}

static int
stream_input(void *buf, ssize_t size)
{
	ssize_t nrd, nsum;
	char *ptr = (char *)buf;

	for (nsum = 0; nsum < size && !feof(stdin) && !ferror(stdin);
	    nsum += nrd) {
		nrd = fread(ptr, 1, size - nsum, stdin);
		ptr += nrd;
	}

	if (nsum < size) {
		pfs_etrace("read from stdin failed, nsum=%zd, size=%zd, feof=%d,"
		    " ferror=%d\n", nsum, size, feof(stdin), ferror(stdin));
		return -1;
	}
	return 0;
}

static int
stream_output(const void *buf, ssize_t size)
{
	ssize_t nwr, nsum;
	const char *ptr = (const char *)buf;

	for (nsum = 0; nsum < size && !ferror(stdout); nsum += nwr) {
		nwr = fwrite(ptr, 1, size - nsum, stdout);
		ptr += nwr;
	}

	if (nsum < size) {
		pfs_etrace("write to stdout failed, nsum=%zd, size=%zd,"
		    " ferror=%d\n", nsum, size, ferror(stdout));
		return -1;
	}
	return 0;
}

static int
block_read(void *buf, size_t blksz, pfs_ossfile_header_t *oss, int iodesc,
    pfs_blkid_t blkid)
{
	int err;
	char *ptr;
	pfs_bda_t fragbda;
	uint64_t rsum;

	PFS_ASSERT(oss->oss_fragsize == PFS_FRAG_SIZE &&
	     blksz == oss->oss_blksize);

	memset(buf, 0, blksz);
	ptr = (char *)buf;
	fragbda = oss->oss_ckid * oss->oss_chunksize + blkid * oss->oss_blksize;
	for (rsum = 0; rsum < oss->oss_blksize; rsum += oss->oss_fragsize) {
		err = pfsdev_pread_flags(iodesc, ptr, oss->oss_fragsize,
		    fragbda, IO_NOWAIT);
		if (err < 0) {
			pfs_etrace("Read chunk %u blk %ld @ %lu failed, err=%d\n",
			    oss->oss_ckid, blkid, fragbda, err);
			return err;
		}
		fragbda += oss->oss_fragsize;
		ptr += oss->oss_fragsize;
	}
	PFS_ASSERT(rsum == oss->oss_blksize);

	err = pfsdev_wait_io(iodesc);
	if (err < 0) {
		pfs_etrace("Read chunk %u blk %ld failed, err=%d\n",
		    oss->oss_ckid, blkid, err);
		return err;
	}
	return 0;
}

static int
block_write(void *buf, size_t blksz, const pfs_ossfile_header_t *oss, int iodesc,
    pfs_blkid_t blkid)
{
	int err;
	char *ptr;
	pfs_bda_t fragbda;
	uint64_t wsum;

	PFS_ASSERT(oss->oss_fragsize == PFS_FRAG_SIZE &&
	     blksz == oss->oss_blksize);

	ptr = (char *)buf;
	fragbda = oss->oss_ckid * oss->oss_chunksize + blkid * oss->oss_blksize;
	for (wsum = 0; wsum < oss->oss_blksize; wsum += oss->oss_fragsize) {
		err = pfsdev_pwrite_flags(iodesc, ptr, oss->oss_fragsize,
		    fragbda, IO_NOWAIT);
		if (err < 0) {
			pfs_etrace("Write chunk %u blk %ld @ %lu failed, err=%d\n",
			    oss->oss_ckid, blkid, fragbda, err);
			return err;
		}
		fragbda += oss->oss_fragsize;
		ptr += oss->oss_fragsize;
	}
	PFS_ASSERT(wsum == oss->oss_blksize);
	err = pfsdev_wait_io(iodesc);
	if (err < 0) {
		pfs_etrace("Write chunk %u blk %ld failed, err=%d\n",
		    oss->oss_ckid, blkid, err);
		return err;
	}
	return 0;
}

static bool
block_isused(pfs_mount_t *mnt, uint32_t ckid, pfs_blkid_t blkid)
{
	int used;
	uint32_t opcs;
	uint64_t btno;

	opcs = ffs(roundup_power2(PFS_NBT_PERCHUNK)) - 1;
	btno = MONO_MAKE(ckid << opcs, blkid);
	used = pfs_mount_block_isused(mnt, btno);
	PFS_ASSERT(used >= 0);

	return used;
}

static inline void
ossheader_dump(const pfs_ossfile_header_t *oss)
{
	pfs_itrace("OSSfile header:\n"
	    "magic:0x%lx\nver:0x%lx\nctime:%lu\ncrc:%u\npbd:%s\ncksz:%lu\n"
	    "blksz:%u\nfragsz:%u\nsectsz:%u\nnsumck:%u\nnck:%u\nckid:%u\nnusedblk:%u\n",
	    oss->oss_magic, oss->oss_version, oss->oss_ctime, oss->oss_checksum,
	    oss->oss_pbdname, oss->oss_chunksize, oss->oss_blksize, oss->oss_fragsize,
	    oss->oss_sectsize, oss->oss_nsumck, oss->oss_nchunk, oss->oss_ckid,
	    oss->oss_nusedblk);
}

static int
ossheader_init(pfs_ossfile_header_t *oss, uint32_t nchunk, uint32_t nsumck,
			uint32_t ckid, uint32_t nusedblk)
{
	int err;

	memset(oss, 0, sizeof(*oss));
	oss->oss_magic = OSSFILE_MAGIC;
	oss->oss_version = OSSFILE_VERSION;
	oss->oss_ctime = time(NULL);
	err = strncpy_safe(oss->oss_pbdname, pbdname, sizeof(oss->oss_pbdname));
	if (err <= 0) {
		pfs_etrace("pbdname %s is invalid, its length should be (0, %d)\n",
		    pbdname, sizeof(oss->oss_pbdname));
		ERR_RETVAL(ENAMETOOLONG);
	}
	oss->oss_chunksize = PBD_CHUNK_SIZE;
	oss->oss_blksize = PFS_BLOCK_SIZE;
	oss->oss_fragsize = PFS_FRAG_SIZE;
	oss->oss_sectsize = PBD_SECTOR_SIZE;
	oss->oss_nsumck = nsumck;
	oss->oss_nchunk = nchunk;
	oss->oss_ckid = ckid;
	oss->oss_nusedblk = nusedblk;
	oss->oss_checksum = crc32c_compute(oss, sizeof(*oss),
	    offsetof(struct pfs_ossfile_header, oss_checksum));

	ossheader_dump(oss);
	return 0;
}

static int
metacache_open()
{
	int err, fd;
	char path[PFS_MAX_PATHLEN];

	err = mkdir(metapath, 0777);
	if (err < 0 && errno != EEXIST) {
		pfs_etrace("mkdir %s failed, err=%d, errno=%d\n", metapath,
		    err, errno);
		return err;
	}

	snprintf(path, PFS_MAX_PATHLEN, "%s/pbd%s.metacache", metapath, pbdname);
	path[PFS_MAX_PATHLEN-1] = '\0';
	fd = open(path, O_CREAT | O_RDWR, 0655);
	if (fd < 0) {
		pfs_etrace("open file %s failed, fd=%d, errno=%d\n", path,
		    fd, errno);
		return fd;
	}

	return fd;
}

static void
metacache_close(int fd)
{
	(void)close(fd);
}

static int
metacache_check_leader(int fd, int iochd)
{
	int err;
	ssize_t rlen;
	char buf[PBD_SECTOR_SIZE];
	pfs_leader_record_t flr, *lr;

	/* read paxos leader from metacache */
	rlen = pread(fd, &flr, sizeof(flr), 0);
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

static int
metacache_check_bust(int fd, int iochd, uint32_t *nck, uint32_t *nsumck)
{
	int err;
	struct pbdinfo pi;
	struct stat st;
	uint32_t fcrc, crc, ckid, fnsumck, fnck;
	ssize_t rlen, datasz, offset;
	pfs_chunk_phy_t *phyck;
	bool bust[PFS_NBT_PERCHUNK];
	const ssize_t bustsz = PFS_NBT_PERCHUNK * sizeof(bool);

	/*
	 * The BUST number must be equal with total chunk number in pbd.
	 */
	err = fstat(fd, &st);
	if (err < 0) {
		pfs_etrace("cant get metafile %d size, err=%d, errno=%d\n",
		    fd, err, errno);
		return err;
	}
	datasz = st.st_size - PBD_SECTOR_SIZE;
	if (datasz <= 0 || datasz % (sizeof(uint32_t) + bustsz) != 0) {
		pfs_etrace("file size %ld is invalid\n", st.st_size);
		ERR_RETVAL(EINVAL);
	}

	/* check total chunk count */
	fnsumck = datasz / (sizeof(uint32_t) + bustsz);
	err = pfsdev_info(iochd, &pi);
	if (err < 0) {
		pfs_etrace("cant get pbd info, err=%d\n", err);
		ERR_RETVAL(EIO);
	}
	if (pi.pi_chunksize != PBD_CHUNK_SIZE ||
	    pi.pi_disksize != (uint64_t)fnsumck * PBD_CHUNK_SIZE) {
		pfs_etrace("pbd parameters mismatch, disksize %llu vs"
		    " %llu, chunksize %llu vs %llu\n",
		    (unsigned long long)pi.pi_disksize,
		    (unsigned long long)fnsumck * PBD_CHUNK_SIZE,
		    (unsigned long long)pi.pi_chunksize,
		    (unsigned long long)PBD_CHUNK_SIZE);
		ERR_RETVAL(EINVAL);
	}
	*nsumck = fnsumck;

	/*
	 * scan all BUSTs in metacache, if BUST[0] which represents the
	 * superblock is true, current chunk is regarded as formatted
	 * and valid.
	 */
	offset = lseek(fd, PBD_SECTOR_SIZE, SEEK_SET);
	if (offset != PBD_SECTOR_SIZE)
		ERR_RETVAL(errno);

	fnck = 0;
	for (ckid = 0; ckid < fnsumck; ckid++) {
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

		/*
		 * formatted chunk must be continuous.
		 */
		if (bust[0]) {
			fnck++;
			if (fnck != ckid + 1)
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
	*nck = fnck;

	return 0;
}

static bool
metacache_isvalid(int fd, uint32_t *nchunk, uint32_t *nsumck)
{
	int err;

	ioch_desc = pfsdev_open(cluster, pbdname, DEVFLG_RD);
	if (ioch_desc < 0) {
		pfs_etrace("cant open pbd %s\n", pbdname);
		return false;
	}

	err = metacache_check_leader(fd, ioch_desc);
	if (err < 0) {
		pfs_etrace("metacache paxos leader is invalid\n");
		goto out;
	}

	err = metacache_check_bust(fd, ioch_desc, nchunk, nsumck);
	if (err < 0) {
		pfs_etrace("metacache BUST is invalid\n");
		goto out;
	}

	pfsdev_close(ioch_desc);
	ioch_desc = -1;
	return true;

out:
	pfsdev_close(ioch_desc);
	ioch_desc = -1;
	return false;
}

static int
metacache_update(int fd, uint32_t *nchunk, uint32_t *nsumck)
{
	int err;
	uint32_t i, ckid, crc;
	pfs_mount_t *mnt;
	struct pbdinfo pi;
	ssize_t offset, wlen;
	bool bust[PFS_NBT_PERCHUNK];
	const ssize_t bustsz = PFS_NBT_PERCHUNK * sizeof(bool);

	err = ftruncate(fd, 0);
	if (err < 0) {
		pfs_etrace("truncate fd %d failed, err=%d, errno=%d\n",
		    fd, err, errno);
		return err;
	}

	err = pfs_mount(cluster, pbdname, 0, PFS_RD | PFS_TOOL);
	if (err < 0)
		return err;
	mnt = pfs_get_mount(pbdname);
	PFS_ASSERT(mnt != NULL && mnt->mnt_blksize == PFS_BLOCK_SIZE);

	err = pfsdev_info(mnt->mnt_ioch_desc, &pi);
	if (err < 0) {
		pfs_etrace("cant get pbd info, err=%d\n", err);
		ERR_GOTO(EIO, out);
	}
	PFS_ASSERT(pi.pi_chunksize == PBD_CHUNK_SIZE);

	*nchunk = mnt->mnt_nchunk;
	*nsumck = pi.pi_disksize / PBD_CHUNK_SIZE;
	if (*nsumck > *nchunk) {
		pfs_itrace("formatted nchunk %u is less than total nchunk %u,"
		    " maybe growfs is doing when creating this snapshot\n",
		    *nchunk, *nsumck);
	} else if (*nsumck < *nchunk) {
		pfs_etrace("nsumck %u is less than mnt_nchunk %u\n", *nsumck,
		    *nchunk);
		ERR_GOTO(EINVAL, out);
	}

	/*
	 * BUST SHOULD be written into local metacache before paxos leader.
	 */
	offset = lseek(fd, PBD_SECTOR_SIZE, SEEK_SET);
	if (offset != PBD_SECTOR_SIZE)
		ERR_GOTO(errno, out);
	for (ckid = 0; ckid < *nsumck; ckid++) {
		/*
		 * Only formatted chunk checks block used status.
		 */
		memset(bust, false, bustsz);
		if (ckid < *nchunk) {
			for (i = 0; i < PFS_NBT_PERCHUNK; i++)
				bust[i] = block_isused(mnt, ckid, i);
		}

		crc = crc32c((uint32_t)~1, (uint8_t *)bust, bustsz);
		wlen = write(fd, &crc, sizeof(crc));
		if (wlen != sizeof(crc))
			ERR_GOTO(EIO, out);

		wlen = write(fd, bust, bustsz);
		if (wlen != bustsz)
			ERR_GOTO(EIO, out);
	}

	/* cache paxos leader */
	memset(sectbuf, 0, PBD_SECTOR_SIZE);
	err = paxos_leader_read(mnt->mnt_ioch_desc, sectbuf, sizeof(sectbuf));
	if (err < 0)
		ERR_GOTO(EIO, out);
	wlen = pwrite(fd, sectbuf, PBD_SECTOR_SIZE, 0);
	if (wlen != PBD_SECTOR_SIZE)
		ERR_GOTO(EIO, out);

	pfs_itrace("update metafile successful\n");
	pfs_put_mount(mnt);
	pfs_umount(pbdname);
	return 0;

out:
	pfs_etrace("update metafile failed\n");
	pfs_put_mount(mnt);
	pfs_umount(pbdname);
	return err;
}

static int
metacache_init(uint32_t *nchunk, uint32_t *nsumck)
{
	int err, fd;

	fd = metacache_open();
	if (fd < 0)
		return fd;

	err = flock(fd, LOCK_EX);
	if (err < 0) {
		pfs_etrace("flock file for %s/pbd%s.metacache failed, err=%d, errno=%d\n", metapath, pbdname,
		    err, errno);
		ERR_GOTO(errno, out);
	}

	if (!metacache_isvalid(fd, nchunk, nsumck)) {
		pfs_itrace("metafile is invalid, update it\n");
		err = metacache_update(fd, nchunk, nsumck);
		if (err < 0)
			ERR_GOTO(EIO, out);
	}
	pfs_itrace("formatted nchunk %u, total nchunk %u\n", *nchunk, *nsumck);
	if (*nsumck < *nchunk)
		ERR_GOTO(EINVAL, out);

	/* unlock for parallel backup */
	(void)flock(fd, LOCK_UN);
	return fd;

out:
	(void)flock(fd, LOCK_UN);
	metacache_close(fd);
	return err;
}

static int metacache_load(int fd, int32_t ckid, bool bust[], ssize_t nblk)
{
	off_t offset, noffset;
	uint32_t crc, fcrc;
	ssize_t rlen;
	int err = 0;

	const ssize_t bustsz = PFS_NBT_PERCHUNK * sizeof(bool);
	PFS_ASSERT(nblk == PFS_NBT_PERCHUNK);

	PFS_ASSERT(fd >= 0);

	/* load BUST of current chunk */
	offset = PBD_SECTOR_SIZE + ckid * (sizeof(fcrc) + bustsz);
	noffset = lseek(fd, offset, SEEK_SET);
	if (noffset != offset)
		ERR_GOTO(errno, out);

	rlen = read(fd, &fcrc, sizeof(fcrc));
	if (rlen != sizeof(fcrc))
		ERR_GOTO(EIO, out);

	rlen = read(fd, bust, bustsz);
	if (rlen != bustsz)
		ERR_GOTO(EIO, out);

	crc = crc32c((uint32_t)~1, (uint8_t *)(bust), bustsz);
	if (crc != fcrc) {
		pfs_etrace("in metafile, chunk %d BUST crc is invalid %u vs"
		    " %u\n", ckid, crc, fcrc);
		ERR_GOTO(EINVAL, out);
	}

	return 0;
out:
	return err;
}

static void metacache_fini(int fd)
{
	metacache_close(fd);
}

static int backup_oss_header(pfs_ossfile_header_t* oss, int ckid, bool bust[], int32_t nchunk, int nsumck)
{
	int err;
	int i;
	uint32_t nusedblk = 0;

	/* init and backup ossfile header */
	for (i = 0; i < (int)PFS_NBT_PERCHUNK; i++) {
		if (bust[i])
			nusedblk++;
	}
	err = ossheader_init(oss, nchunk, nsumck, ckid, nusedblk);
	if (err < 0)
		ERR_RETVAL(EINVAL);

	ossheader_dump(oss);
	return 0;
}

static int backup_chunk_data(pfs_ossfile_header_t* oss, int ckid, bool bust[], bool force)
{
	int err;
	int i, n;
	uint32_t *ubt = NULL;

	if (oss->oss_nusedblk == 0) {
		if (!force) {
			pfs_etrace("No blocks are used in chunk %u, maybe it hasn't"
			    " be formatted. If you are sure to do this, add '-f'"
			    " to backup forcedly\n", ckid);
            ERR_GOTO(ENODATA, out);
		} else
			pfs_itrace("No blocks are used in chunk %u, forcedly backup\n",
			    ckid);
	}
	err = stream_output(oss, sizeof(*oss));
	if (err < 0)
		ERR_RETVAL(EIO);
	if (oss->oss_nusedblk == 0)
		return 0;

	/*
	 * backup used-block table.
	 * BUST must be scanned in descending order. When restoring a chunk,
	 * superblock is usually the last block to be written. Otherwise, if
	 * restore cmd has errors and retries, target chunk maybe regarded as
	 * formatted improperly.
	 */
	ubt = (uint32_t *)malloc(oss->oss_nusedblk * sizeof(uint32_t));
	if (ubt == NULL)
		ERR_RETVAL(ENOMEM);
	memset(ubt, 0, oss->oss_nusedblk * sizeof(uint32_t));
	for (n = 0, i = PFS_NBT_PERCHUNK - 1; i >= 0; i--) {
		if (bust[i])
			ubt[n++] = i;
	}
	PFS_ASSERT(n == (int)oss->oss_nusedblk);
	err = stream_output(ubt, oss->oss_nusedblk * sizeof(uint32_t));
	if (err < 0)
		ERR_GOTO(EIO, out);
	pfs_itrace("backup used block table(%u) done\n", oss->oss_nusedblk);

	/* backup all used blocks */
	if (ioch_desc < 0)
		ERR_GOTO(EINVAL, out);

	for (n = 0; n < (int)oss->oss_nusedblk; n++) {
		err = block_read(blkbuf, sizeof(blkbuf), oss, ioch_desc, ubt[n]);
		if (err < 0)
			goto out;
		err = stream_output(blkbuf, sizeof(blkbuf));
		if (err < 0) {
			pfs_etrace("Write chunk %u's %u blk(%u) to stdout failed,"
			    "err=%d, errno=%d\n", oss->oss_ckid, n, ubt[n],
			    err, errno);
			goto out;
		}
	}

	pfs_itrace("backup chunk %d successful, %u used blocks, backup file:"
	    " header(%lu) | ubt(%lu) | blkdata(%llu) Bytes\n",
	    ckid, oss->oss_nusedblk, sizeof(*oss),
	    oss->oss_nusedblk * sizeof(uint32_t),
	    (unsigned long long)oss->oss_blksize * oss->oss_nusedblk);

out:
	free(ubt);
	return err;
}

static int
chunk_backup_multi(int32_t startckid, int32_t endckid, bool force)
{
	PFS_ASSERT(startckid >= 0);
	PFS_ASSERT(endckid > startckid);

	int err = 0;
	uint32_t nchunk = 0, nsumck = 0;
	int32_t ck;

	bool bust[PFS_NBT_PERCHUNK];
	const ssize_t bustsz = PFS_NBT_PERCHUNK * sizeof(bool);
	pfs_ossfile_header_t oss;

	int metafd = metacache_init(&nchunk, &nsumck);
	if (metafd < 0)
		ERR_GOTO(EBADF, out);

	if (ioch_desc < 0)
		ioch_desc = pfsdev_open(cluster, pbdname, DEVFLG_RD);

	if (ioch_desc < 0)
		ERR_GOTO(EINVAL, out);

	for (ck = startckid; ck < endckid; ++ck) {
		if (ck >= (int)nsumck) {
			pfs_etrace("invalid chunk id %d, [nchunk %u, nsumck %u]\n", ck, nchunk, nsumck);
			ERR_GOTO(EINVAL, out);
		}

		memset(bust, false, bustsz);
		err = metacache_load(metafd, ck, bust, PFS_NBT_PERCHUNK);
		if (err < 0) {
			pfs_etrace("in metafile, load chunk %d BUST failed\n", ck);
			ERR_GOTO(EINVAL, out);
		}
		memset(&oss, 0, sizeof(oss));
		err = backup_oss_header(&oss, ck, bust, nchunk, nsumck);
		if (err < 0) {
			pfs_etrace("in backup chunk %d ossheader failed\n", ck);
			ERR_GOTO(EINVAL, out);
		}
		err = backup_chunk_data(&oss, ck, bust, force);
		if (err < 0) {
			pfs_etrace("in backup chunk %d data failed\n", ck);
			ERR_GOTO(EINVAL, out);
		}
		pfs_itrace("chunk_backup %s chunk %d success\n", pbdname, ck);
	}

out:
	if (ioch_desc >= 0) {
		pfsdev_close(ioch_desc);
		ioch_desc = -1;
	}

	if (metafd >= 0) {
		metacache_fini(metafd);
		metafd = -1;
	}

	return err;
}

static int restore_chunk_data(pfs_ossfile_header_t* oss, int ckid, bool force)
{
	int err;
	uint32_t i;
	uint32_t* ubt = NULL;

	/* read ubt from stream */
	PFS_ASSERT(oss->oss_nusedblk > 0);
	ubt = (uint32_t *)malloc(oss->oss_nusedblk * sizeof(uint32_t));
	if (ubt == NULL)
		ERR_GOTO(ENOMEM, out);
	err = stream_input(ubt, oss->oss_nusedblk * sizeof(uint32_t));
	if (err < 0)
		ERR_GOTO(EIO, out);

	/*
	 * restore blocks
	 * connection mode MUST be normal, because it's friendly to parallel
	 * restoring on one machine.
	 */

	/* Don't close ioch_desc after this func, because maybe restore many chunks */
	if (ioch_desc < 0)
		ERR_GOTO(EINVAL, out);

	/* check for each chunk */
	err = check_global_security(ioch_desc, pbdname, ckid, force, "chunk restore");
	if (err < 0)
		goto out;

	/*
	 * superblock is the last block of oss file.
	 */
	for (i = 0; i < oss->oss_nusedblk; i++) {
		memset(blkbuf, 0, sizeof(blkbuf));
		err = stream_input(blkbuf, sizeof(blkbuf));
		if (err < 0) {
			pfs_etrace("Read chunk %u's %u blk(%u) from stdin failed,"
			    "err=%d, errno=%d\n", oss->oss_ckid, i, ubt[i],
			    err, errno);
			goto out;
		}

		err = block_write(blkbuf, sizeof(blkbuf), oss, ioch_desc, ubt[i]);
		if (err < 0)
			goto out;
	}

	if (ckid == 0) {
		err = paxos_leader_reset(ioch_desc, pbdname);
		if (err < 0)
			goto out;
	}

	err = 0;
out:
	free(ubt);
	return err;
}

static
int restore_oss_header(pfs_ossfile_header_t* oss, int ckid)
{
	/* read header from stream */
	int err = stream_input(oss, sizeof(*oss));
	if (err < 0) {
		if (feof(stdin)) {
			err = 0;
		}

		return err;
	}

	if (oss->oss_checksum != crc32c_compute(oss, sizeof(*oss),
	    offsetof(struct pfs_ossfile_header, oss_checksum))) {
		pfs_etrace("ossfile header checksum %u is invalid\n",
		    oss->oss_checksum);
		ERR_RETVAL(EINVAL);
	}
	ossheader_dump(oss);
	PFS_ASSERT(oss->oss_magic == OSSFILE_MAGIC);
	PFS_ASSERT(oss->oss_version == OSSFILE_VERSION);
	PFS_ASSERT(oss->oss_ckid == (uint32_t)ckid);
	PFS_ASSERT(oss->oss_chunksize == PBD_CHUNK_SIZE);
	PFS_ASSERT(oss->oss_blksize == PFS_BLOCK_SIZE);
	PFS_ASSERT(oss->oss_fragsize == PFS_FRAG_SIZE);
	PFS_ASSERT(oss->oss_sectsize == PBD_SECTOR_SIZE);
	PFS_ASSERT(oss->oss_nusedblk <= PFS_NBT_PERCHUNK);

	return 0;
}

static int
chunk_restore_multi(int32_t startckid, int32_t endckid, bool force)
{
	PFS_ASSERT(startckid >= 0);
	PFS_ASSERT(endckid > startckid);

	int ck;
	int err = 0;
	pfs_ossfile_header_t oss;

	if (ioch_desc < 0)
		ioch_desc = pfsdev_open(cluster, pbdname, DEVFLG_RDWR);

	if (ioch_desc < 0)
		ERR_GOTO(EINVAL, out);

	for (ck = startckid; ck < endckid; ++ck) {
		memset(&oss, 0, sizeof(oss));
		err = restore_oss_header(&oss, ck);
		if (err != 0)
			ERR_GOTO(EINVAL, out);

		if (oss.oss_nusedblk == 0) {
			pfs_itrace("restore chunk %u successful, no used blocks\n", ck);
			continue;
		}

		pfs_itrace("chunk %d header restore done, %u blocks will be restored\n", ck, oss.oss_nusedblk);

		err = restore_chunk_data(&oss, ck, force);
		if (err != 0) {
			pfs_etrace("restore chunk %d with %u blks failed\n", ck, oss.oss_nusedblk);
			ERR_GOTO(EINVAL, out);
		}

		pfs_itrace("restore chunk %u with %u blks done\n", ck, oss.oss_nusedblk);
	}

out:
	if (ioch_desc >= 0) {
		pfsdev_close(ioch_desc);
		ioch_desc = -1;
	}

	return err;
}

int
cmd_chunk(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	opts_chunk_t *co_chunk = (opts_chunk_t *)co;

	if (argc != 1) {
		usage_chunk();
		exit(EINVAL);
	}
	cluster = co->co_common.cluster;
	pbdname = argv[0];

	switch (co_chunk->mode) {
	case MODE_BACKUP:
		pfs_trace_redirect(pbdname, 0);
		err = chunk_backup_multi(co_chunk->ckid, co_chunk->endckid, co_chunk->force);
		break;

	case MODE_RESTORE:
		pfs_trace_redirect(pbdname, 0);
		err = chunk_restore_multi(co_chunk->ckid, co_chunk->endckid, co_chunk->force);
		break;

	default:
		usage_chunk();
		err = -1;
		break;
	}
	return err;
}

PFSCMD_INFO(chunk, 0, PFS_RDWR, getopt_chunk, cmd_chunk, usage_chunk, "chunk operations");
