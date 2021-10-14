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

#include <unistd.h>

#include <sys/param.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

#include "cmd_impl.h"
#include "pfs_impl.h"
#include "pfs_api.h"
#include "pfs_mount.h"

typedef struct opts_info {
	opts_common_t	common;
	int		depth;	/* anode's depth */
} opts_info_t;

void
usage_info()
{
	printf("pfs info [options] pbdname\n"
	    "	-d:	info dump depth, start from 1\n");
}

int
getopt_info(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_info_t *co_info = (opts_info_t *)co;

	co_info->depth = 1;
	optind = 1;
	while ((opt = getopt(argc, argv, "hd:")) != -1) {
		switch (opt) {
		case 'd':
			co_info->depth = atoi(optarg);
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}


int
cmd_info(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	const char *pbdname;
	opts_info_t *co_info = (opts_info_t *)co;
	pfs_mount_t *mnt;

	if (argc < 1)
	       return -1;
	if (co_info->depth <= 0)
	       return -1;

	pbdname = argv[0];

	mnt = pfs_get_mount(pbdname);
	if (mnt == NULL) {
		pfs_etrace("cant get mount %s\n", pbdname);
		ERR_RETVAL(ENODEV);
	}

	err = pfs_meta_info(mnt, co_info->depth, NULL);

	pfs_put_mount(mnt);
	return err;
}

PFSCMD_INFO(info, CMDF_MOUNT, PFS_RD, getopt_info, cmd_info, usage_info, "show pfs meta info");
