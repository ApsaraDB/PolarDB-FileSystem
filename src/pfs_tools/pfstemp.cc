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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "pfs_api.h"
#include "pfs_trace.h"
#include "pfs_mount.h"

static void
usage(void)
{
    printf("usage: sudo ./pfstemp pbdname\n");
}


int
main(int argc, char *argv[])
{
	char pbdname[PFS_MAX_PATHLEN] = {'\0'};
	char path[4096];
	int i, ret = 0;
	const char *filename[] = {
		"vim",
		"vimdiff",
		"gcc",
		NULL,
	};

	if (argc < 2) {
		usage();
		return -1;
	}

	strncpy(pbdname, argv[1], PFS_MAX_PATHLEN);
	ret = pfs_mount("polarstore", pbdname, 1, PFS_RDWR);
	if (ret < 0) {
		pfs_etrace("Error in mount pbd %s\n", pbdname);
		return 0;
	}

	for (i = 0; filename[i]; i++) {
		snprintf(path, sizeof(path), "/%s/%s", pbdname, filename[i]);
		pfs_open(path, 0, 0);
	}

	while (1) {
		pfs_dbgtrace("sleeping 2 seconds\n");
		sleep(2);
	}
	return 0;
}
