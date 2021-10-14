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
#include <sys/param.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pfs_api.h"
#include "pfs_devio.h"
#include "pfs_dir.h"
#include "pfs_impl.h"
#include "pfs_inode.h"
#include "pfs_log.h"
#include "pfs_meta.h"
#include "pfs_mount.h"
#include "pfs_paxos.h"
#include "pfs_trace.h"
#include "pfs_util.h"
#include "pfs_version.h"

#include "cmd_impl.h"


/*
 *   chunk layout
 * 	+===============+ <--------------------------------+
 * 	|  chunk info   |  1 page                          |
 * 	+---------------+                                  |
 * 	| 		|                                  |
 * 	~   block tag   ~  16 page                         |
 * 	|               |                                  |
 * 	+---------------+                                  |
 * 	|               |                                  |
 * 	~   direntry   	~  8 page
 * 	|		|
 * 	+---------------+
 * 	|               |                              first block
 * 	~    inode      ~  8 page
 * 	|		|
 * 	+---------------+                                  |
 * 	|               |                                  |
 * 	~		~                                  |
 * 	~     unused    ~  remaining 256 - 33 pages        |
 * 	~               ~                                  |
 * 	|               |                                  |
 * 	+===============+ <--------------------------------+
 * 	|               |
 * 	|               |
 * 	|               |
 * 	~          	~
 * 	~               ~                              other blocks
 * 	~               ~
 * 	|               |
 * 	|               |
 * 	|               |
 * 	+===============+ <--------------------------------- ending of chunk
 */

#define	DEFAULT_NUSER		30
#define	DEFAULT_SECTOR_SIZE	4096
#define	MIN_LOG_SIZE		(32UL << 20)
#define	MAX_LOG_SIZE		(1UL << 30)
#define	DEFAULT_JOURNAL_SIZE	MAX_LOG_SIZE

static int	ioch_desc = -1;	     /* io channel index */

static uint64_t	pbd_disksize;
static uint64_t	pbd_chunksize;

static uint32_t nobj_perchunk[MT_NTYPE] = {
	[MT_NONE] 	= 0,
	[MT_BLKTAG] 	= PFS_NBT_PERCHUNK,
	[MT_DIRENTRY] 	= PFS_NDE_PERCHUNK,
	[MT_INODE] 	= PFS_NIN_PERCHUNK
};

typedef struct opts_mkfs {
	opts_common_t	common;
	size_t		logsize;
	size_t		sectsize;
	int		numhosts;
	bool		force;	/* forcedly mkfs */
} opts_mkfs_t;

static struct option mkfs_long_opts[] = {
	{ "log-size",	optional_argument,	NULL,	'l' },
	{ "sector-size", optional_argument,	NULL,	's' },
	{ "num-users",	optional_argument,	NULL,	'u' },
	{ "force", optional_argument,		NULL,	'f' },
	{ 0 },
};

void
metaobj_init(pfs_metaobj_phy_t *mo, int mtype, uint32_t oid, uint64_t ckno)
{
	mo->mo_type = mtype;
	switch (mtype) {
	case MT_BLKTAG:
		/* The first block tag in a chunk is reserved for meta data */
		if (oid == 0)
			mo->mo_used = 1;
		break;

	case MT_DIRENTRY: {
		pfs_direntry_phy_t *de = MO2DE(mo);

		de->de_ino = INVALID_INO;
		de->de_dirino = INVALID_INO;
		de->de_extdeno = INVALID_EXTDENO;
		/* The first direntry in whole pbd is reserved for root dir */
		if (mo->mo_number == 0) {
			mo->mo_used = 1;
			de->de_ino = 0;
		}

		/* The second direntry is reserved for paxos file */
		if (mo->mo_number == 1) {
			mo->mo_used = 1;
			mo->mo_next = JOURNAL_FILE_MONO;
					/* next links to journal direntry */
			mo->mo_prev = 0;

			PFS_ASSERT(strlen(PFS_PAXOS_FILE) < sizeof(de->de_name));
			strncpy(de->de_name, PFS_PAXOS_FILE, sizeof(de->de_name));
			de->de_ino = 1;
			de->de_dirino = 0;
		}

		/* The third direntry is reserved for journal file */
		if (mo->mo_number == 2) {
			mo->mo_used = 1;
			mo->mo_next = 0;
			mo->mo_prev = PAXOS_FILE_MONO;
					/* prev links to paxos direntry */

			PFS_ASSERT(strlen(PFS_JOURNAL_FILE) < sizeof(de->de_name));
			strncpy(de->de_name, PFS_JOURNAL_FILE, sizeof(de->de_name));
			de->de_ino = 2;
			de->de_dirino = 0;
		}
		break;
	}

	case MT_INODE: {
		pfs_inode_phy_t *in = MO2IN(mo);

		in->in_deno = INVALID_DENO;
		/* The first inode is reserved for root directory */
		if (mo->mo_number == 0) {
			mo->mo_used = 1;
			mo->mo_head = PAXOS_FILE_MONO;
			mo->mo_tail = JOURNAL_FILE_MONO;

			in->in_type = PFS_INODET_DIR;
			in->in_nlink = 1;
			in->in_deno = 0;
			in->in_btime = gettimeofday_us();
		}

		/* The second inode is reserved for paxos file */
		if (mo->mo_number == 1) {
			mo->mo_used = 1;
			mo->mo_head = 0;
			mo->mo_tail = 0;

			in->in_type = PFS_INODET_FILE;
			in->in_nlink = 1;
			in->in_deno = 1;
			in->in_btime = INNER_FILE_BTIME;
		}

		/* The third inode is reserved for journal file */
		if (mo->mo_number == 2) {
			mo->mo_used = 1;
			mo->mo_head = 0;
			mo->mo_tail = 0;

			in->in_type = PFS_INODET_FILE;
			in->in_nlink = 1;
			in->in_deno = 2;
			in->in_btime = INNER_FILE_BTIME;
		}
		break;
	}

	default:
		PFS_ASSERT("unkown meta object type" == NULL);
		break;
	}

	/* generate checksum */
	mo->mo_checksum = crc32c_compute(mo, sizeof(*mo),
	    offsetof(struct pfs_metaobj_phy, mo_checksum));
}

/*
 * metaset_init:
 *
 * 	Init the metaset in a physical chunk. @sectbda is the first
 * 	page bda for the metaset. After init, a new page bda is returned.
 */
int
metaset_init(pfs_chunk_phy_t *phyck, int mtype, uint64_t *sectbda_ptr)
{
	int err;
	uint32_t fi, oi;
	uint32_t oid, nobj_perpage, opcs;
	pfs_metaset_phy_t *ms;
	pfs_metaobj_phy_t *mobuf;
	uint64_t sectbda = *sectbda_ptr;

	ms = &phyck->ck_physet[mtype];
	ms->ms_sectbda = sectbda;
	ms->ms_objsize = sizeof(pfs_metaobj_phy_t);
	ms->ms_nsect = nobj_perchunk[mtype] * ms->ms_objsize / PBD_SECTOR_SIZE;
	nobj_perpage = PBD_SECTOR_SIZE / ms->ms_objsize;
	opcs = ffs(roundup_power2(nobj_perchunk[mtype])) - 1;
	//opcs = (uint32_t)ceil(log2(nobj_perchunk[mtype]));

	oid = 0;
	mobuf = (pfs_metaobj_phy_t *)malloc(PBD_SECTOR_SIZE);
	if (mobuf == NULL) {
		pfs_etrace("Error in malloc memory when mkfs\n");
		exit(ENOMEM);
	}

	err = 0;
	for (fi = 0; fi < ms->ms_nsect; fi++) {
		memset(mobuf, 0, PBD_SECTOR_SIZE);
		for (oi = 0; oi < nobj_perpage; oi++) {
			mobuf[oi].mo_number =
			    MONO_MAKE(phyck->ck_number << opcs, oid);
			metaobj_init(&mobuf[oi], mtype, oid, phyck->ck_number);
			oid++;
		}
		err = pfsdev_pwrite(ioch_desc, mobuf, PBD_SECTOR_SIZE, sectbda);
		if (err < 0) {
			pfs_etrace("Error in pwrite when mkfs\n");
			goto out;
		}
		sectbda += PBD_SECTOR_SIZE;
	}

out:
	free(mobuf);
	if (err < 0)
		return err;

	printf("\t\tmetaset %8lx/%d: sectbda %#16lx, npage %8u, objsize %4u, nobj %4u, "
	    "oid range [%8lx, %8lx)\n", phyck->ck_number, mtype, ms->ms_sectbda,
	    ms->ms_nsect, ms->ms_objsize, nobj_perchunk[mtype],
	    MONO_MAKE(phyck->ck_number << opcs, 0),
	    MONO_MAKE(phyck->ck_number << opcs, nobj_perchunk[mtype]-1) + 1);

	*sectbda_ptr = sectbda;
	return 0;
}

static int
chunk_init(pfs_chunk_phy_t *phyck, uint32_t ckno)
{
	int err;
	pfs_bda_t sectbda;

	phyck->ck_number	= ckno;
	phyck->ck_magic		= chunk_magic_make(ckno);
	phyck->ck_chunksize	= pbd_chunksize;
	phyck->ck_blksize	= PFS_BLOCK_SIZE;
	phyck->ck_sectsize	= PBD_SECTOR_SIZE;
	phyck->ck_nchunk	= pbd_disksize / pbd_chunksize;

	printf("Init chunk %u\n", ckno);
	sectbda = pbd_chunksize * ckno + PBD_SECTOR_SIZE;
				/* first page for chunk info */

	err = metaset_init(phyck, MT_BLKTAG, &sectbda);
	if (err < 0) {
		pfs_etrace("Error in init blktag meta\n");
		return err;
	}

	err = metaset_init(phyck, MT_DIRENTRY, &sectbda);
	if (err < 0) {
		pfs_etrace("Error in init direntry meta\n");
		return err;
	}

	err = metaset_init(phyck, MT_INODE, &sectbda);
	if (err < 0) {
		pfs_etrace("Error in init inode meta\n");
		return err;
	}

	/* generate checksum */
	phyck->ck_checksum = crc32c_compute(phyck, sizeof(*phyck),
	    offsetof(struct pfs_chunk_phy, ck_checksum));

	printf("\n");
	return 0;
}

int
paxos_file_make(pfs_mount_t *mnt, int nuser, size_t logsize)
{
	int err = 0;
	int fd;
	char *data;
	ssize_t wlen;
	char filepath[PFS_MAX_PATHLEN];

	/*
	 * We need nuser + 2 pages for paxos consensus. The zeroth
	 * page is to describe the info about the paxos participant
	 * and also the journal info where particaipants will write
	 * and read to sync their pfs meta data. The remaining nuser
	 * pages are for each user to pose his/her proposal. The last
	 * page is the leader record.
	 */
	wlen = (nuser + 2) * PBD_SECTOR_SIZE;
	if (wlen > PFS_BLOCK_SIZE) {
		pfs_etrace("too many users %d\n", nuser);
		exit(EINVAL);
	}

	pbdpath_gen(mnt->mnt_pbdname, PFS_PAXOS_FILE, filepath,
			PFS_MAX_PATHLEN);
	err = fd = pfs_open(filepath, 0, 0);
	if (err < 0) {
		pfs_etrace("can't create file %s\n", filepath);
		exit(EINVAL);
	}

	data = (char *)calloc(1, PFS_BLOCK_SIZE);
	err = wlen = pfs_pwrite(fd, data, PFS_BLOCK_SIZE, 0);
	if (wlen <= 0) {
		pfs_etrace("can't fill %s with zero\n", PFS_PAXOS_FILE);
		exit(EIO);
	}
	/*
	 * pfs_leader_init opens .pfs-paxos again, so fd should
	 * be closed before that.
	 */
	pfs_close(fd);

	printf("init paxos lease\n");
	err = pfs_leader_init(mnt, nuser, DEFAULT_MAX_HOSTS, 0, logsize);
	if (err < 0) {
		pfs_etrace("init paxos file failed %d\n", err);
		exit(-err);
	}

	return 0;
}

static inline size_t
journal_file_size(uint32_t nchunk)
{
	size_t jsize;
	uint64_t nobj_perchunk;

	/* All objs in PBD can be modified in one tx */
	nobj_perchunk = PFS_NBT_PERCHUNK + PFS_NDE_PERCHUNK + PFS_NIN_PERCHUNK;
	jsize = nchunk * (nobj_perchunk * sizeof(pfs_logentry_phy_t)) * 2;

	/*
	 * jsize should be between [MIN_LOG_SIZE, MAX_LOG_SIZE],
	 * which is [32MB, 512MB]
	 */
	if (jsize < MIN_LOG_SIZE)
		jsize = MIN_LOG_SIZE;
	if (jsize > MAX_LOG_SIZE)
		jsize = MAX_LOG_SIZE;

	/* jsize roundup to 4KB */
	jsize = roundup(jsize, PBD_SECTOR_SIZE);
	return jsize;
}

int
journal_file_make(pfs_mount_t *mnt, size_t jsize)
{
	int fd;
	char *data;
	size_t offset, wsum;
	ssize_t wlen;
	char filepath[PFS_MAX_PATHLEN];

	if ((jsize & (512 - 1)) != 0) {
		pfs_etrace("Log file size %x must be 512Bytes aligned\n", jsize);
		exit(EINVAL);
	}

	pbdpath_gen(mnt->mnt_pbdname, PFS_JOURNAL_FILE, filepath,
	    PFS_MAX_PATHLEN);
	fd = pfs_open(filepath, 0, 0);
	if (fd < 0) {
		pfs_etrace("cant open file %s\n", filepath);
		exit(-fd);
	}

	data = (char *)calloc(1, PFS_BLOCK_SIZE);
	for (wsum = 0, offset = 0; wsum < jsize; wsum += wlen, offset += wlen) {
		wlen = MIN(jsize - wsum, PFS_BLOCK_SIZE);
		wlen = pfs_pwrite(fd, data, wlen, offset);
		if (wlen < 0)
			exit(EIO);
	}
	free(data);
	pfs_close(fd);
	return 0;
}

bool
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

int
check_global_security(int iochd, const char *pbdname, uint32_t ckid, bool force,
    const char *caller)
{
	ssize_t rlen;
	char buf[PBD_SECTOR_SIZE];

	rlen = pfsdev_pread(iochd, buf, sizeof(buf), ckid*PBD_CHUNK_SIZE/* bda*/);
	if (rlen < 0) {
		pfs_etrace("%s cant read chunk %u header, err=%d\n", caller,
		    ckid, (int)rlen);
		return rlen;
	}

	if (chunk_isvalid((const pfs_chunk_phy_t *)buf, ckid)) {
		if (force == false) {
			pfs_etrace("%s isn't allowed because that chunk %u"
			    " maybe already formatted. If you are sure to do %s,"
			    " run '%s -f' instead.\n", caller, ckid, caller, caller);
			exit(EBUSY);
			return -EBUSY;
		}
		pfs_itrace("%s runs forcedly, although PBD %s chunk %u is already"
		    " formatted\n", caller, pbdname, ckid);
	} else {
		pfs_itrace("%s PBD %s isn't formatted\n", caller, pbdname);
	}

	return 0;
}

static int
get_pbdsize(const char *pbdname)
{
	int err;
	struct pbdinfo pi;

	err = pfsdev_info(ioch_desc, &pi);
	if (err < 0) {
		pfs_etrace("cant get pbd info, err=%d\n", err);
		return -EIO;
	}
	pbd_disksize = pi.pi_disksize;
	pbd_chunksize = pi.pi_chunksize;
	pfs_itrace("disk size %#llx, chunk size %#llx\n",
	    (unsigned long long)pbd_disksize,
	    (unsigned long long)pbd_chunksize);
	if (pbd_chunksize != PBD_CHUNK_SIZE) {
		pfs_etrace("unmatched chunk size: pls %#llx vs pfs %#llx\n",
		    (unsigned long long)pbd_chunksize,
		    (unsigned long long)PBD_CHUNK_SIZE);
		return -EIO;
	}
	return 0;
}

static int
verify_args(int64_t oldcknum, int64_t newcknum)
{
	int err, i;
	char buf[PBD_SECTOR_SIZE];
	pfs_chunk_phy_t *phyck = (pfs_chunk_phy_t *)buf;
	pfs_metaset_phy_t *ms;

	if (oldcknum <= 0 || oldcknum >= newcknum) {
		pfs_etrace("invalid args: oldchnum %ld, newchnum %ld\n",
		    oldcknum, newcknum);
		ERR_RETVAL(EINVAL);
	}

	if (pbd_chunksize * newcknum != pbd_disksize) {
		pfs_etrace("newcknum %ld doesn't match disksize %lu\n",
		    newcknum, pbd_disksize);
		ERR_RETVAL(EINVAL);
	}

	/*
	 * Read the first chunk's header.
	 */
	memset(buf, 0, PBD_SECTOR_SIZE);
	err = pfsdev_pread(ioch_desc, buf, PBD_SECTOR_SIZE, 0);
	if (err < 0) {
		pfs_etrace("Error in read the first chunk header, err=%d\n", err);
		return err;
	}

	pfs_meta_check_chunk(phyck);
	if ((int64_t)phyck->ck_nchunk != oldcknum) {
		pfs_etrace("old pbd chunk number mismatch, %u vs %ld\n",
		    phyck->ck_nchunk, oldcknum);
		return -EINVAL;
	}

	/*
	 * Make sure that metaobj numbers are same in
	 * existing chunks and new chunks.
	 */
	for (i = 0; i < MT_NTYPE; i++) {
		if (i == MT_NONE)
			continue;

		ms = &phyck->ck_physet[i];
		nobj_perchunk[i] = ms->ms_nsect *
		   (PBD_SECTOR_SIZE / ms->ms_objsize);
		pfs_itrace("new chunk's metaobj %d number %d\n", i,
		    nobj_perchunk[i]);
	}

	return 0;
}

void
usage_mkfs()
{
	printf("pfs mkfs [options] pbdname\n"
	    "  -h, --help:              show this help message\n"
	    "  -l, --log-size=size:     set log size in byte\n"
	    "  -u, --num-users=num:     set user number [1, %d]\n"
	    "  -s, --sector-size=size:  set sector size (default is 4096)\n"
	    "  -f, --force:             mkfs forcedly (default is disabled)\n"
	    "mkfs should be executed by root\n", DEFAULT_MAX_HOSTS);
}

int
getopt_mkfs(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_mkfs_t *co_mkfs = (opts_mkfs_t *)co;

	co_mkfs->logsize = DEFAULT_JOURNAL_SIZE;
	co_mkfs->sectsize = DEFAULT_SECTOR_SIZE;
	co_mkfs->numhosts = DEFAULT_NUSER;
	co_mkfs->force = false;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hl:s:u:f", mkfs_long_opts, NULL)) != -1) {
		switch (opt) {
		case 'l':
			co_mkfs->logsize = strtoul(optarg, NULL, 10);
			break;

		case 's':
			co_mkfs->sectsize = strtoul(optarg, NULL, 10);
			break;

		case 'u':
			co_mkfs->numhosts = strtoul(optarg, NULL, 10);
			break;

		case 'f':
			co_mkfs->force = true;
			break;

		case'h':
		default:
			return -1;
		}
	}

	if (co_mkfs->numhosts <= 0 || co_mkfs->numhosts > DEFAULT_MAX_HOSTS)
		return -1;

	return optind;
}

int
pfs_make()
{
	int err;
	char buf[PBD_SECTOR_SIZE];
	uint32_t i, nchunk;

	nchunk = pbd_disksize / pbd_chunksize;
	for (i = 0; i < nchunk; i++) {
		memset(buf, 0, PBD_SECTOR_SIZE);
		err = chunk_init((pfs_chunk_phy_t *)buf, i);
		if (err < 0) {
			pfs_etrace("Error in init chunk %u\n", i);
			return err;
		}
		err = pfsdev_pwrite(ioch_desc, buf, PBD_SECTOR_SIZE, i * pbd_chunksize);
		if (err < 0) {
			pfs_etrace("Error in pwrite chunk %u header\n", i);
			return err;
		}
	}

	printf("Inited filesystem(%lu bytes), %u chunks, %u blktags,"
	    " %u direntries, %u inodes per chunk\n",
	    pbd_disksize, nchunk,
	    PFS_NBT_PERCHUNK, PFS_NDE_PERCHUNK, PFS_NIN_PERCHUNK);
	return 0;
}

int
cmd_mkfs(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	const char *pbdname;
	pfs_mount_t *mnt;
	uint32_t nchunk;
	opts_mkfs_t *co_mkfs = (opts_mkfs_t *)co;

	if (argc != 1) {
		usage_mkfs();
		exit(EINVAL);
	}
	pbdname = argv[0];

	/*
	 * check whether another mkfs is running locally,
	 * the lock will be released when process exits.
	 */
	err = paxos_hostid_local_lock(pbdname, 0, __func__);
	if (err < 0)
		goto out;

	ioch_desc = pfsdev_open(co->co_common.cluster, pbdname,
	    DEVFLG_RDWR | DEVFLG_REQ_SAFE);
	if (ioch_desc < 0) {
		usage_mkfs();
		exit(EINVAL);
	}

	err = get_pbdsize(pbdname);
	if (err < 0)
		goto out;
	/* check whether PBD can be formatted */
	err = check_global_security(ioch_desc, pbdname, 0, co_mkfs->force, "mkfs");
	if (err < 0)
		goto out;

	err = pfs_make();
	if (err < 0)
		goto out;
	pfsdev_close(ioch_desc);
	ioch_desc = -1;

	err = pfs_mount(co->co_common.cluster, pbdname, 1, MNTFLG_TOOL|MNTFLG_RDWR);
	if (err < 0)
		goto out;
	mnt = pfs_get_mount(pbdname);
	PFS_VERIFY(mnt != NULL);

	if (co_mkfs->logsize == 0) {
		nchunk = pbd_disksize / pbd_chunksize;
		co_mkfs->logsize = journal_file_size(nchunk);
	}
	if (co_mkfs->logsize < MIN_LOG_SIZE || co_mkfs->logsize > MAX_LOG_SIZE) {
		pfs_itrace("Warning: journal size %lu isn't in range [%lu, %lu]\n",
		    co_mkfs->logsize, MIN_LOG_SIZE, MAX_LOG_SIZE);
	}
	pfs_itrace("journal file size 0x%lx, %lu bytes\n", co_mkfs->logsize,
	    co_mkfs->logsize);

	printf("making paxos file\n");
	err = paxos_file_make(mnt, co_mkfs->numhosts, co_mkfs->logsize);
	if (err < 0)
		goto umount;
	printf("making journal file\n");
	err = journal_file_make(mnt, co_mkfs->logsize);
	if (err < 0)
		goto umount;

umount:
	pfs_put_mount(mnt);
	(void)pfs_umount(pbdname);

out:
	if (ioch_desc >= 0)
		pfsdev_close(ioch_desc);

	if (err == 0) {
		printf("pfs mkfs succeeds!\n");
		return 0;
	} else {
		printf("pfs mkfs failed!\n");
		return err;
	}
}

PFSCMD_INFO(mkfs, 0, PFS_RDWR, getopt_mkfs, cmd_mkfs, usage_mkfs, "make filesystem");

/*
 * grow a filesystem.
 * Before growfs running, PBD has grew to new size. growfs should format new
 * chunks.
 *
 * growfs procedure:
 * 1. format new chunks' superblocks.
 * 2. modify nchunk in the first chunk header.
 */

typedef struct opts_growfs {
	opts_common_t	common;
	int64_t		oldcknum;	/* grow fs, old chunk number */
	int64_t		newcknum;	/* grow fs, new chunk number */
	bool		force;
} opts_growfs_t;

static struct option growfs_long_opts[] = {
	{ "oldcknum",	required_argument,	NULL,	'o' },
	{ "newcknum",	required_argument,	NULL,	'n' },
	{ "force",	optional_argument,	NULL,	'f' },
	{ 0 },
};

void
usage_growfs()
{
	printf("pfs growfs [-o|--oldcknum=n1] [-n|--newcknum=n2] [-f|--force] pbdname\n"
	    "  -h, --help:             show this help message\n"
	    "  -o, --oldcknum:         old chunk number(%luGB/chunk)\n"
	    "  -n, --newcknum:         new chunk number\n"
	    "  -f, --force:            growfs forcedly (default is disabled)\n",
	    (unsigned long)(PBD_CHUNK_SIZE >> 30));
}

int
getopt_growfs(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_growfs_t *co_growfs = (opts_growfs_t *)co;

	co_growfs->oldcknum = -1;
	co_growfs->newcknum = -1;
	co_growfs->force = false;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "ho:n:f", growfs_long_opts, NULL)) != -1) {
		switch (opt) {
		case 'o':
			co_growfs->oldcknum = strtol(optarg, NULL, 10);
			break;

		case 'n':
			co_growfs->newcknum = strtol(optarg, NULL, 10);
			break;

		case 'f':
			co_growfs->force = true;
			break;

		case'h':
		default:
			return -1;
		}
	}

	if (co_growfs->oldcknum < 0 || co_growfs->newcknum < 0)
		return -1;
	else
		return optind;
}

static int
pfs_grow(int64_t oldcknum, int64_t newcknum)
{
	int err;
	int64_t i;
	char buf[PBD_SECTOR_SIZE];
	pfs_chunk_phy_t *phyck = (pfs_chunk_phy_t *)buf;

	/* Format new chunks in [oldcknum, newcknum) */
	for (i = oldcknum; i < newcknum; i++) {
		memset(buf, 0, PBD_SECTOR_SIZE);
		err = chunk_init((pfs_chunk_phy_t *)buf, i);
		if (err < 0) {
			pfs_etrace("Error in init chunk %ld\n", i);
			return err;
		}
		err = pfsdev_pwrite(ioch_desc, buf, PBD_SECTOR_SIZE, i * pbd_chunksize);
		if (err < 0) {
			pfs_etrace("Error in pwrite chunk %ld header\n", i);
			return err;
		}
	}

	/*
	 * old chunks are in [0, oldcknum-1].
	 * MUST modify old chunk header in descending order.
	 */
	for (i = oldcknum - 1; i >= 0; i--) {
		memset(buf, 0, PBD_SECTOR_SIZE);
		err = pfsdev_pread(ioch_desc, buf, PBD_SECTOR_SIZE, i * pbd_chunksize);
		if (err < 0) {
			pfs_etrace("Error in read chunk %ld, err=%d\n", i, err);
			return err;
		}

		pfs_meta_check_chunk(phyck);
		phyck->ck_nchunk = newcknum;
		phyck->ck_checksum = crc32c_compute(phyck, sizeof(*phyck),
		    offsetof(struct pfs_chunk_phy, ck_checksum));

		err = pfsdev_pwrite(ioch_desc, buf, PBD_SECTOR_SIZE, i * pbd_chunksize);
		if (err < 0) {
			pfs_etrace("Error in write chunk %ld, err=%d\n", i, err);
			return err;
		}
	}

	return 0;
}

int
cmd_growfs(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	const char *pbdname;
	opts_growfs_t *co_growfs = (opts_growfs_t *)co;

	if (argc != 1) {
		usage_growfs();
		exit(EINVAL);
	}
	pbdname = argv[0];

	pfs_trace_redirect(pbdname, 0);
	/*
	 * growfs can run when DB is running, so it can't lock the whole
	 * file like mkfs. growfs will lock the region after normal paxos
	 * regions.
	 */
	err = paxos_hostid_local_lock(pbdname, DEFAULT_MAX_HOSTS + 1, __func__);
	if (err < 0)
		goto out;

	/*
	 * MySQL and this growfs may run on the same machine, so we can't use
	 * safe mode.
	 */
	ioch_desc = pfsdev_open(co->co_common.cluster, pbdname, DEVFLG_RDWR);
	if (ioch_desc < 0) {
		usage_growfs();
		exit(EINVAL);
	}

	err = get_pbdsize(pbdname);
	if (err < 0)
		goto out;
	err = verify_args(co_growfs->oldcknum, co_growfs->newcknum);
	if (err < 0)
		goto out;
	err = check_global_security(ioch_desc, pbdname, co_growfs->oldcknum,
	    co_growfs->force, "growfs");
	if (err < 0)
		goto out;

	err = pfs_grow(co_growfs->oldcknum, co_growfs->newcknum);

out:
	if (ioch_desc >= 0)
		(void)pfsdev_close(ioch_desc);

	if (err == 0) {
		printf("pfs growfs succeeds!\n");
		return 0;
	} else {
		printf("pfs growfs failed!\n");
		return err;
	}
}

PFSCMD_INFO(growfs, 0, PFS_RDWR, getopt_growfs, cmd_growfs, usage_growfs, "grow filesystem");
