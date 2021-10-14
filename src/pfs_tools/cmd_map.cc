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
#include <getopt.h>
#include <stdio.h>

#include "cmd_impl.h"
#include "pfs_api.h"
#include "pfs_impl.h"

typedef struct opts_map {
	opts_common_t	common;
	off_t		offset;		/* file offset */
} opts_map_t;

static struct option long_opts[] = {
	{ "offset", optional_argument,		NULL,	'o' },
	{ 0 },
};

void
usage_map()
{
	printf("pfs map [options] pbdpath\n"
	    "  -o, --offset:             offset(default is -1)\n"
	    "dump the block index of specified file\n"
	    "-------------------------\n"
	    "blkidx:  block index in current file\n"
	    "offset:  block offset in current file\n"
	    "btno:    blktag number, 0 represents file hole\n"
	    "blkno:   bock number, range in [0, %d * nchunk)\n"
	    "chunk:   block's chunk number, starts from 0\n"
	    "bda:     block absoulte device address in disk, bda = blkno * %d\n"
	    "cka:     block relative address in the chunk, cka = bda - chunk * %ld\n",
	    PFS_NBT_PERCHUNK, PFS_BLOCK_SIZE, (long)PBD_CHUNK_SIZE);
}

int
getopt_map(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_map_t *co_map = (opts_map_t *)co;

	co_map->offset = -1;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "ho:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'o':
			co_map->offset = strtol(optarg, NULL, 10);
			break;

		case'h':
		default:
			return -1;
		}
	}

	return optind;
}

int
cmd_map(int argc, char *argv[], cmd_opts_t *co)
{
	int err, i, count, fd = -1;
	opts_map_t *co_map = (opts_map_t *)co;
	const char *pbdpath = NULL;
	fmap_entry_t *fmap, *fmapv = NULL;
	struct stat st;
	uint64_t bda;
	off_t off;

	if (argc != 1) {
		usage_map();
		exit(EINVAL);
	}
	pbdpath = argv[0];

	fd = pfs_open(pbdpath, O_RDONLY, 0644);
	if (fd < 0)
		return fd;

	err = pfs_fstat(fd, &st);
	if (err < 0)
		goto out;

	if (!S_ISREG(st.st_mode)) {
		pfs_etrace("%s is a directory\n", pbdpath);
		ERR_GOTO(EISDIR, out);
	}

	if (co_map->offset >= st.st_size) {
		pfs_etrace("offset %ld >= filesize %ld\n", co_map->offset,
		    st.st_size);
		ERR_GOTO(EINVAL, out);
	}

	if (co_map->offset >= 0) {
		off = co_map->offset;
		count = 1;
	} else {
		off = 0;
		count = howmany(st.st_size, st.st_blksize);
	}

	fmapv = (fmap_entry_t *)malloc(count * sizeof(fmap_entry_t));
	if (fmapv == NULL)
		ERR_GOTO(ENOMEM, out);
	memset(fmapv, 0, count * sizeof(fmap_entry_t));

	for (i = 0; i < count; i++) {
		fmapv[i].f_off = off;
		off += st.st_blksize;
	}

	err = pfs_fmap(fd, fmapv, count);
	if (err < 0) {
		pfs_etrace("fmap failed, err=%d, errno=%d\n", err, errno);
		goto out;
	}

	printf("filesize(B): %-8ld\tblksize(B): %-8ld\n", st.st_size, (long int)st.st_blksize);
	printf("------------------\n");
	printf("blkidx\t\toffset\t\tbtno\t\tbtholeoff\t\tblkno\t\tchunk\t\tbda\t\tcka\n");
	for (i = 0; i < count; i++) {
		fmap = &fmapv[i];
		bda = fmap->f_blkno * st.st_blksize +
		    (fmap->f_off & (st.st_blksize - 1));

		printf("%-8ld\t%-8ld\t%-8ld\t%-8d\t\t%-8ld\t%-8ld\t%-8lu\t%-8ld\n",
		    fmap->f_off / st.st_blksize, fmap->f_off, fmap->f_btno,
		    fmap->f_bthoff, fmap->f_blkno, fmap->f_ckid, bda,
		    (long)(bda - fmap->f_ckid * PBD_CHUNK_SIZE));
	}

	pfs_close(fd);
	free(fmapv);
	return 0;

out:
	if (fd >= 0)
		pfs_close(fd);

	free(fmapv);
	return err;
}

PFSCMD_INFO(map, CMDF_MOUNT, PFS_RD, getopt_map, cmd_map, usage_map, "dump a file's block index");
