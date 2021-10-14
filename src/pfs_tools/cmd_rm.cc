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
#include <libgen.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <time.h>

#include "cmd_impl.h"
#include "pfs_impl.h"
#include "pfs_api.h"
#include "pfs_namei.h"

typedef struct opts_rm {
	opts_common_t	common;
	bool		recursive;	/* remove directories recursively */
	bool		enable_wildcard;
} opts_rm_t;

void
usage_rm()
{
	printf("pfs rm [options] path\n"
	    "	-r:	remove directories recursively\n"
	    "	-w:	enable wildcard\n");
}

int
getopt_rm(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_rm_t *co_rm = (opts_rm_t *)co;

	co_rm->recursive = false;
	co_rm->enable_wildcard = false;

	optind = 1;
	while ((opt = getopt(argc, argv, "hrw")) != -1) {
		switch (opt) {
		case 'r':
			co_rm->recursive = true;
			break;

		case 'w':
			co_rm->enable_wildcard = true;
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

static bool
isrootdir(const char *path)
{
	char pbdname[PFS_MAX_PBDLEN] = {'\0'};
	char savepath[PFS_MAX_PATHLEN] = {'\0'};

	pbdpath_split(path, pbdname, sizeof(pbdname),
	    savepath, sizeof(savepath));

	if (strlen(savepath) == 1 && savepath[0] == '/')
		return true;
	else
		return false;
}

static int
do_rm(const char *path, bool recursive)
{
	int err;
	int nprint;
	char entry[PFS_MAX_PATHLEN] = {'\0'};
	DIR *dir;
	struct dirent *de;
	struct dirent debuf;
	struct stat st;

	err = pfs.stat(path, &st);
	if (err < 0)
		return err;
	if (S_ISREG(st.st_mode)) {
		/* special skip journal and paxos */
		if (st.st_ino == PAXOS_FILE_MONO ||
		    st.st_ino == JOURNAL_FILE_MONO) {
			fprintf(stderr, "rm: cannot remove paxos/journal file\n");
			return -1;
		}

		return pfs.unlink(path);
	}

	if (recursive == false) {
		fprintf(stderr, "rm: %s is a directory\n", path);
		return -1;
	}

	if (isrootdir(path)) {
		fprintf(stderr, "rm: %s is the root directory\n", path);
		return -1;
	}

	dir = pfs.opendir(path);
	if (dir == NULL)
		return -1;

	while ((err = pfs.readdir_r(dir, &debuf, &de)) == 0 && de) {
		memset(entry, 0, sizeof(entry));
		nprint = snprintf(entry, PFS_MAX_PATHLEN, "%s/%s", path,
		    de->d_name);
		if (nprint >= PFS_MAX_PATHLEN) {
			err = -ENAMETOOLONG;	//XXX: should continue?
			goto close_dir;
		}

		err = do_rm(entry, recursive);
		if (err < 0)
			goto close_dir;
	}

close_dir:
	pfs.closedir(dir);
	if (err == 0)
		err = pfs.rmdir(path);

	err = err < 0 ? -1 : 0;
	return err;
}

static int
do_rm_wildcard(const char *path, bool recursive)
{
	char pbdname[PFS_MAX_PBDLEN];
	char abspath[PFS_MAX_PATHLEN];
	char abspath2[PFS_MAX_PATHLEN];
	char dirpath[PFS_MAX_PATHLEN];
	char *dname, *bname;
	user_action_t action;

	pbdpath_split(path, pbdname, sizeof(pbdname), abspath, sizeof(abspath));
	pbdpath_copy(abspath2, abspath, sizeof(abspath2));
	dname = dirname(abspath);
	bname = basename(abspath2);
	pbdpath_gen(pbdname, dname, dirpath, sizeof(dirpath));

	memset(&action, 0, sizeof(action));
	action.user_func = (void*)&do_rm;
	action.user_nargs = 1;
	action.user_arg0 = recursive ? 1 : 0;
	return pbdpath_traverse(dirpath, bname, &action);
}

int
cmd_rm(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];
	opts_rm_t *co_rm = (opts_rm_t *)co;

	if (argc < 1 || argc > PFS_MAX_BATCH_FILES)
		return -1;

	err = 0;
	for (int i = 0; i < argc; ++i) {
		pbdpath_copy(pbdpath, argv[i], sizeof(pbdpath));

		if (!co_rm->enable_wildcard) {
			err |= do_rm(pbdpath, co_rm->recursive);
		} else {
			err |= do_rm_wildcard(pbdpath, co_rm->recursive);
		}
	}
	if (err < 0)
		return -1;
	return 0;
}

PFSCMD_INFO(rm, CMDF_MOUNT_EX, PFS_RDWR, getopt_rm, cmd_rm, usage_rm, "remove file or dir");
