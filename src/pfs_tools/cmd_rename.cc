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

#include "cmd_impl.h"
#include "pfs_api.h"

void
usage_rename()
{
	printf(
	    "  rename directory or file"                                "\n"
	    "  $ pfs rename /1/mydir /1/mydir_newname"                	"\n");
}

int
cmd_rename(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	char oldpbdpath[PFS_MAX_PATHLEN] = {0};
	char newpbdpath[PFS_MAX_PATHLEN] = {0};

	if (argc != 2)
	       return -1;

	pbdpath_copy(oldpbdpath, argv[0], sizeof(oldpbdpath));
	pbdpath_copy(newpbdpath, argv[1], sizeof(newpbdpath));

	err = pfs.rename(oldpbdpath, newpbdpath);
	if (err < 0)
		return -1;

	return 0;
}

PFSCMD_INFO(rename, CMDF_MOUNT_EX, PFS_RDWR, getopt_none, cmd_rename, usage_rename, "rename file");
