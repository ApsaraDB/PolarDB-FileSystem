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

#include "cmd_impl.h"
#include "pfs_impl.h"
#include "pfs_api.h"

typedef struct opts_du {
	opts_common_t	common;
	bool		all;	// show all files, not just directories
	int		depth;	// show depth, start from 0, remained value -1 means max-depth
} opts_du_t;

void
usage_du()
{
	printf("pfs du [options] pbdpath\n"
	    "	-a:	show all files, not just directories\n"
	    "	-d:	max depth, start from 0\n");
}

int
getopt_du(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_du_t *co_du = (opts_du_t *)co;

	co_du->all = false;
	co_du->depth = -1;
	optind = 1;
	while ((opt = getopt(argc, argv, "hd:a")) != -1) {
		switch (opt) {
		case 'd':
			co_du->depth = atoi(optarg);
			if (co_du->depth < 0) {
				fprintf(stderr, "du: invalid depth %d\n", co_du->depth);
				return -EINVAL;
			}
			break;

		case 'a':
			co_du->all = true;
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

int
cmd_du(int argc, char *argv[], cmd_opts_t *co)
{
	int 		err;
	const char 	*pbdpath;
	opts_du_t* 	co_du = (opts_du_t *)co;

	if (argc != 1)
		return -1;

	pbdpath = argv[0];
	err = pfs_du(pbdpath, co_du->all, co_du->depth, NULL);
	return err;
}

PFSCMD_INFO(du, CMDF_MOUNT, PFS_RD, getopt_du, cmd_du, usage_du, "display disk usage statistics");
