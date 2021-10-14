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

#include "cmd_impl.h"
#include "pfs_impl.h"
#include "pfs_api.h"

typedef struct opts_mkdir {
	opts_common_t	common;
	bool		parents;	/* make parent directories as needed */
} opts_mkdir_t;

void
usage_mkdir()
{
	printf("pfs mkdir [options] pbdpath\n"
	    "	-p:	make parent directories as needed\n");
}

int
getopt_mkdir(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_mkdir_t *co_mkdir = (opts_mkdir_t *)co;

	co_mkdir->parents = false;

	optind = 1;
	while ((opt = getopt(argc, argv, "hp")) != -1) {
		switch (opt) {
		case 'p':
			co_mkdir->parents = true;
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

static char *
findroot(char *pbdpath)
{
	char *ptr = pbdpath;
	uint32_t nslash = 0;

	for (; *ptr != '\0' && nslash < 2; ptr++) {
		if (*ptr == '/')
			nslash++;
	}

	if (nslash == 2)
		return ptr;
	else
		return NULL;
}

int
do_mkdir(char *path, bool parents)
{
	int err;
	char *ptr;

	if (parents == false) {
		return pfs.mkdir(path, 0);
	} else {
		ptr = findroot(path);
		if (ptr == NULL)
			return -EINVAL;

		for (; ptr && *ptr != '\0'; ptr++) {
			if (*ptr == '/') {
				*ptr = '\0';
				err = pfs.mkdir(path, 0);
				*ptr = '/';

				if (err < 0 && errno != EEXIST) 
					return err;
			}
		}

		err = pfs.mkdir(path, 0);
		if (err < 0)
			return (errno == EEXIST ? 0 : err);
		else
			return 0;
	}
}

int
cmd_mkdir(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];
	opts_mkdir_t *co_mkdir = (opts_mkdir_t *)co;

	if (argc != 1)
	       return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	err = do_mkdir(pbdpath, co_mkdir->parents);
	if (err < 0)
	       return -1;

	return 0;
}

PFSCMD_INFO(mkdir, CMDF_MOUNT_EX, PFS_RDWR, getopt_mkdir, cmd_mkdir, usage_mkdir, "create dir");
