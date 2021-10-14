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

#include "cmd_impl.h"
#include "pfs_impl.h"
#include "pfs_api.h"
#include "pfs_mount.h"

void
usage_flushlog()
{
	printf("pfs flushlog pbdname\n");
}

int
cmd_flushlog(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	pfs_mount_t *mnt;
	const char *pbdname;

	if (argc != 1)
	       return -1;

	pbdname = argv[0];
	mnt = pfs_get_mount(pbdname);
	PFS_ASSERT(mnt != NULL);
	err = pfs_mount_flush(mnt);
	pfs_put_mount(mnt);

	return (err < 0 ? -1 : 0);
}

PFSCMD_INFO(flushlog, CMDF_MOUNT, PFS_RDWR, getopt_none, cmd_flushlog, usage_flushlog, "flush log to pbd");
