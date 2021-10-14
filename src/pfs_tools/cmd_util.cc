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

#include <errno.h>
#include <stdio.h>
#include <fnmatch.h>
#include <dirent.h>

#include "pfs_api.h"
#include "pfs_namei.h"
#include "pfs_trace.h"
#include "pfs_util.h"

#include "cmd_impl.h"

void
pbdpath_copy(char *dst, const char *src, size_t len)
{
	if (strncpy_safe(dst, src, len) < 0) {
		fprintf(stderr, "too long pbdpath\n");
		exit(ENAMETOOLONG);
	}
}

void
pbdpath_gen(const char *pbdname, const char *filepath, char *buf, size_t len)
{
	if (snprintf(buf, len, "/%s/%s", pbdname, filepath) >= (int)len) {
		pfs_etrace("too long path %s/%s\n", pbdname, filepath);
		exit(ENAMETOOLONG);
	}
}

void
pbdpath_join(const char *pbdpath, const char *filepath, char *buf, size_t len)
{
	if (snprintf(buf, len, "%s/%s", pbdpath, filepath) >= (int)len) {
		pfs_etrace("too long path %s/%s\n", pbdpath, filepath);
		exit(ENAMETOOLONG);
	}
}

/*
 * pbdpath_split
 *
 * Split valid pbdpath into pbdname & path
 * Caller should guarantee that buffer is large enough
 */
void
pbdpath_split(const char *pbdpath, char *pbdnamebuf, size_t nbuflen,
    char *pathbuf, size_t pbuflen)
{
	nameinfo_t ni;

	if (pfs_namei_init(&ni, pbdpath, 0) != 0) {
		pfs_etrace("invalid pbdpath %s\n", pbdpath);
		exit(EINVAL);
	}

	if (strncpy_safe(pbdnamebuf, ni.ni_pbd, nbuflen) < 0) {
		pfs_etrace("too long pbdname %s\n", ni.ni_pbd);
		exit(ENAMETOOLONG);
	}
	if (pathbuf == NULL)
		return;

	if (strncpy_safe(pathbuf, ni.ni_path, pbuflen) < 0) {
		pfs_etrace("too long path %s\n", ni.ni_path);
		exit(ENAMETOOLONG);
	}
}

int
pbdpath_traverse(const char *pbdpath, const char *filter, const user_action_t *action)
{
	int err, err2;
	char filepath[PFS_MAX_PATHLEN];
	struct dirent *de;
	struct dirent debuf;
	DIR *dir;

	dir = pfs.opendir(pbdpath);
	if (dir == NULL)
		return -1;

	err2 = 0;
	while ((err = pfs.readdir_r(dir, &debuf, &de)) == 0 && de) {
		PFS_ASSERT(de->d_name[0] != '\0');

		if (filter && fnmatch(filter, de->d_name, FNM_NOESCAPE) != 0)
			continue;

		/* special skip journal and paxos */
		if (de->d_ino == PAXOS_FILE_MONO ||
		    de->d_ino == JOURNAL_FILE_MONO) {
			pfs_itrace("skip paxos/journal file during path traversal\n");
			continue;
		}

		pbdpath_join(pbdpath, de->d_name, filepath, sizeof(filepath));
		switch (action->user_nargs) {
			case 0: {
				typedef int (*user_func_t)(const char*);
				user_func_t f = (user_func_t )action->user_func;
				err2 |= f(filepath);
				break;
			}

			case 1: {
				typedef int (*user_func_t)(const char*, int);
				user_func_t f = (user_func_t )action->user_func;
				err2 |= f(filepath, action->user_arg0);
				break;
			}

			case 2: {
				typedef int (*user_func_t)(const char*, int, int);
				user_func_t f = (user_func_t )action->user_func;
				err2 |= f(filepath, action->user_arg0, action->user_arg1);
				break;
			}

			default:
				fprintf(stderr, "wrong nargs %d, should <= 2\n", action->user_nargs);
				break;
		}
	}

	pfs.closedir(dir);

	err = (err != 0 || err2 != 0) ? -1 : 0;
	return err;
}
