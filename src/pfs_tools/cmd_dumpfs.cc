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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>

#include "pfs_impl.h"
#include "pfs_api.h"
#include "pfs_inode.h"
#include "pfs_meta.h"
#include "pfs_devio.h"
#include "pfs_dir.h"
#include "pfs_mount.h"
#include "cmd_impl.h"

static int		ioch_desc;
static char 		dumpfs_buf[PBD_SECTOR_SIZE];

#define PBDNAME_MAX_LEN	256

static const char* motype_name[] = {
	[MT_NONE] 	= "none",
	[MT_BLKTAG]	= "blktag",
	[MT_DIRENTRY]	= "dentry",
	[MT_INODE]	= "inode",
};

static uint64_t	free_obj[MT_NTYPE] = {
	[MT_NONE]	= 0,
	[MT_BLKTAG] 	= 0,
	[MT_DIRENTRY] 	= 0,
	[MT_INODE] 	= 0
};

static uint64_t	used_obj[MT_NTYPE] = {
	[MT_NONE]	= 0,
	[MT_BLKTAG] 	= 0,
	[MT_DIRENTRY] 	= 0,
	[MT_INODE] 	= 0
};

void
calc_object_cnt(int objtype, pfs_metaset_phy_t *ms)
{
	int err;
	uint64_t i, j;
	pfs_metaobj_phy_t *mo, *mobuf;
	uint64_t nobj_persect;

	err = 0;
	nobj_persect = PBD_SECTOR_SIZE / ms->ms_objsize;

	mobuf = (pfs_metaobj_phy_t *)malloc(PBD_SECTOR_SIZE);
	for (i = 0; i < ms->ms_nsect; i++) {
		err = pfsdev_pread(ioch_desc, mobuf, PBD_SECTOR_SIZE,
		    ms->ms_sectbda + PBD_SECTOR_SIZE * i);
		if (err < 0) {
			pfs_etrace("read failed\n");
			break;
		}
		for (j = 0; j < nobj_persect; j++) {
			mo = &mobuf[j];
			if (mo->mo_used == 0)
				free_obj[objtype]++;
			else
				used_obj[objtype]++;
		}
	}
	free(mobuf);
}

void
chunk_dump_one(pfs_chunk_phy_t *ck, int level)
{
        fprintf(stdout, "chunk %lu: \n", ck->ck_number);
        DUMP_FIELD("%#lx", 	level, ck, ck_magic);
        DUMP_FIELD("%lu", 	level, ck, ck_chunksize);
        DUMP_FIELD("%lu", 	level, ck, ck_blksize);
        DUMP_FIELD("%lu", 	level, ck, ck_sectsize);
        DUMP_FIELD("%lu", 	level, ck, ck_number);
        DUMP_FIELD("%u", 	level, ck, ck_nchunk);
        DUMP_FIELD("%u", 	level, ck, ck_checksum);
        DUMP_FIELD("%u", 	level, ck, ck_physet[MT_BLKTAG].ms_nsect);
        DUMP_FIELD("%u", 	level, ck, ck_physet[MT_DIRENTRY].ms_nsect);
        DUMP_FIELD("%u", 	level, ck, ck_physet[MT_INODE].ms_nsect);
        DUMP_FIELD("%#lx", 	level, ck, ck_physet[MT_BLKTAG].ms_sectbda);
        DUMP_FIELD("%#lx", 	level, ck, ck_physet[MT_DIRENTRY].ms_sectbda);
        DUMP_FIELD("%#lx", 	level, ck, ck_physet[MT_INODE].ms_sectbda);

	calc_object_cnt(MT_BLKTAG, &ck->ck_physet[MT_BLKTAG]);
	calc_object_cnt(MT_INODE, &ck->ck_physet[MT_INODE]);
	calc_object_cnt(MT_DIRENTRY, &ck->ck_physet[MT_DIRENTRY]);
}

int
chunk_dump(int chunkid)
{
	uint64_t chunksize = PBD_CHUNK_SIZE;
	int err, i, nchunk;
	pfs_chunk_phy_t *ck;

	i = (chunkid >= 0) ? chunkid : 0;
	do {
		ck = (pfs_chunk_phy_t *)dumpfs_buf;
		memset(ck, 0, PBD_SECTOR_SIZE);
		err = pfsdev_pread(ioch_desc, ck, PBD_SECTOR_SIZE, i * chunksize);
		if (err < 0 || ck->ck_chunksize != chunksize) {
			pfs_etrace("read %d chunk header @ %ld len %ld failed,"
			    " err = %d\n", i, i * chunksize, PBD_SECTOR_SIZE);
			return err;
		}
		nchunk = ck->ck_nchunk;
		chunk_dump_one(ck, 2);
	} while (chunkid < 0 && ++i < nchunk);

	printf("type\tfree\tused\ttotal\n");
	for (int i = MT_BLKTAG; i < MT_NTYPE; i++)
		printf("%s\t%lu\t%lu\t%lu\n", motype_name[i], free_obj[i],
		    used_obj[i], free_obj[i] + used_obj[i]);
	return 0;
}

enum {
	DUMP_CHUNK	= 1,
	DUMP_META	= 2,
};

typedef struct opts_dumpfs {
	opts_common_t	common;
	int		mode;
	int		metatype;
	int		chunkid;
	int		objid;
} opts_dumpfs_t;

static struct option long_opts_dumpfs[] = {
	{ "meta",		no_argument,		NULL,	'm' },
	{ "type",		required_argument,	NULL,	't' },
	{ "chunk",		required_argument,	NULL,	'c' },
	{ "object",		required_argument,	NULL,	'o' },
	{ 0 },
};

void
usage_dumpfs()
{
	printf("pfs dumpfs [-h] | [-m ] [-t type] [-c chunkid] [-o objid] pbdname\n"
	    "  -h:    show help\n"
	    "  -m, --meta:      dump meta data\n"
	    "  -t, --type:      meta data type\n"
	    "  -c, --chunk:     chunk id\n"
	    "  -o, --objid:     metaobject id\n");
}

int
getopt_dumpfs(int argc, char *argv[], cmd_opts *co)
{
	int opt;
	opts_dumpfs_t *co_dumpfs = (opts_dumpfs_t *)co;

	co_dumpfs->mode = DUMP_CHUNK;
	co_dumpfs->metatype = -1;
	co_dumpfs->chunkid = -1;
	co_dumpfs->objid = -1;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hmt:c:o:", long_opts_dumpfs, NULL)) != -1) {
		switch (opt) {
		case 'm':
			co_dumpfs->mode = DUMP_META;
			break;

		case 't':
			co_dumpfs->metatype = strtol(optarg, NULL, 0);
			break;

		case 'c':
			co_dumpfs->chunkid = strtol(optarg, NULL, 0);
			break;

		case 'o':
			co_dumpfs->objid = strtol(optarg, NULL, 0);
			break;

		case 'h':
		default:
			return -1;
		}
	}

	return optind;
}

int
cmd_dumpfs(int argc, char *argv[], cmd_opts *co)
{
	opts_dumpfs_t *co_dumpfs = (opts_dumpfs_t *)co;

	if (argc != 1)
		return -1;

	switch (co_dumpfs->mode) {
	case DUMP_CHUNK:
		ioch_desc = pfsdev_open(co->co_common.cluster, argv[0], DEVFLG_RD);
		if (ioch_desc < 0) {
			pfs_etrace("cant open pfsdev %s\n", argv[0]);
			return -1;
		}
		chunk_dump(co_dumpfs->chunkid);
		pfsdev_close(ioch_desc);
		break;

	case DUMP_META:
	{
		pfs_mount_t *mnt;
		int err;

		err = pfs_mount(co->co_common.cluster, argv[0], 0,
		    PFS_RD|PFS_TOOL);
		if (err) {
			pfs_etrace("cant not mount %s\n", argv[0]);
			return -1;
		}
		mnt = pfs_get_mount(argv[0]);
		PFS_VERIFY(mnt != NULL);
		pfs_dump_meta(mnt, co_dumpfs->metatype, co_dumpfs->chunkid,
		    co_dumpfs->objid);
		pfs_put_mount(mnt);
		pfs_umount(argv[0]);
		break;
	}

	}
	return 0;
}

PFSCMD_INFO(dumpfs, 0, PFS_RD, getopt_dumpfs, cmd_dumpfs, usage_dumpfs, "dump pbd info or data");
