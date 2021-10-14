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

#include "pfs_impl.h"
#include "pfs_api.h"
#include "pfs_meta.h"
#include "pfs_mount.h"
#include "cmd_impl.h"


typedef struct opts_usedinfo {
	opts_common_t	common;
	int		type;
	int		beginchunk;
	int		endchunk;
} opts_usedinfo_t;

void
usage_usedinfo()
{
	printf("pfs usedinfo [-h] -t [b | i | d] [-b begin_chunk] "
	    "[-e end_chunk] pbdname\n"
	    "  -h:    show help\n"
	    "  -t:    used blktag, inode, direntry\n"
	    "  -b:    begin chunk\n"
	    "  -e:    end chunk\n");
}

int
getopt_usedinfo(int argc, char *argv[], cmd_opts *co)
{
	int opt;
	opts_usedinfo_t *co_usedinfo = (opts_usedinfo_t *)co;

	co_usedinfo->type = -1;
	co_usedinfo->beginchunk = -1;
	co_usedinfo->endchunk = -1;

	optind = 1;
	while ((opt = getopt(argc, argv, "ht:b:e:")) != -1) {
		switch (opt) {
		case 't':
			co_usedinfo->type =
				optarg[0] == 'b' ? MT_BLKTAG :
				optarg[0] == 'i' ? MT_INODE :
				optarg[0] == 'd' ? MT_DIRENTRY : -1;
			break;

		case 'b':
			co_usedinfo->beginchunk = atoi(optarg);
			break;

		case 'e':
			co_usedinfo->endchunk = atoi(optarg);
			break;

		case 'h':
		default:
			return -1;
		}
	}

	return optind;
}

int
cmd_usedinfo(int argc, char *argv[], cmd_opts *co)
{
	opts_usedinfo_t *co_usedinfo = (opts_usedinfo_t *)co;
	pfs_mount_t *mnt;
	int ckid[2];

	if (argc != 1 || co_usedinfo->type < 0)
		return -1;

	mnt = pfs_get_mount(argv[0]);
	ckid[0] = co_usedinfo->beginchunk;
	ckid[1] = co_usedinfo->endchunk;
	pfs_dump_used(mnt, co_usedinfo->type, ckid);

	pfs_put_mount(mnt);
	return 0;
}

PFSCMD_INFO(usedinfo, CMDF_MOUNT, PFS_RD, getopt_usedinfo, cmd_usedinfo,
    usage_usedinfo, "dump pbd info or data");
