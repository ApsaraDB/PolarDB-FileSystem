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
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>

#include "cmd_impl.h"
#include "pfs_impl.h"
#include "pfs_api.h"
#include "pfs_mount.h"
#include "pfs_trace.h"
#include "pfs_namei.h"

typedef struct opts_cp {
	opts_common_t	common;
	bool		recursive;      /* copy directories recursively */
	bool		force;
	const char	*cluster;	/* src or dst, only one, for cp between local and pbd */
	const char	*src_cluster;	/* src cluster for cp between pbd */
	const char	*dst_cluster;	/* dst cluster for cp between pbd */
	int		src_hostid;	/* src_hostid for cp between pbd */
	int		dst_hostid;	/* dst_hostid for cp between pbd */
} opts_cp_t;

static int 	do_copy(const char *srcpath, const char *dstpath,
		    bool firstcopy, const opts_cp_t *co_cp);

static struct option long_opts_cp[] = {
	{ "recursive",		optional_argument,	NULL,	'r' },
	{ "force",		optional_argument,	NULL,	'f' },
	{ "src_cluster",	optional_argument,	NULL,	'S' },
	{ "dst_cluster",	optional_argument,	NULL,	'D' },
	{ "src_hostid",		optional_argument,	NULL,	's' },
	{ "dst_hostid",		optional_argument,	NULL,	'd' },
	{ 0 },
};

void
usage_cp()
{
	printf("pfs cp [options] srcpath dstpath\n"
	    "  -r, --recursive          copy directories recursively\n"
	    "  -f, --force              force copy; overwrite existent file\n"
	    "  -S, --src_cluster        source cluster name\n"
	    "  -D, --dst_cluster        destination cluster name\n"
	    "  -s, --src_hostid         source cluster hostid for cp between pbd\n"
	    "  -d, --dst_hostid         destination cluster hostid for cp between pbd\n");
}

int
getopt_cp(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_cp_t *co_cp = (opts_cp_t *)co;

	co_cp->recursive = false;
	co_cp->force = false;
	co_cp->cluster = NULL;
	co_cp->src_cluster = NULL;
	co_cp->dst_cluster = NULL;
	co_cp->src_hostid = 0;
	co_cp->dst_hostid = 0;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hrfS:D:s:d:", long_opts_cp, NULL)) != -1) {
		switch (opt) {
		case 'r':
			co_cp->recursive = true;
			co_cp->force = true;
			break;

		case 'f':
			co_cp->force = true;
			break;

		case 'S':
			co_cp->cluster = optarg;
			co_cp->src_cluster = optarg;
			break;

		case 'D':
			co_cp->cluster = optarg;
			co_cp->dst_cluster = optarg;
			break;

		case 's':
			co_cp->src_hostid = atoi(optarg);
			break;

		case 'd':
			co_cp->dst_hostid = atoi(optarg);
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

static int
get_pbdname(const char *pbdpath, char *pbdname, size_t nlen)
{
	if (PFS_PATH_ISVALID(pbdpath) == false) {
		return -1;
	}

	pbdpath_split(pbdpath, pbdname, nlen, NULL, 0);
	return 0;
}

static int
splice_path(const char *srcpath, const char *dstpath, char *newpath,
    int newlen)
{
	const char *basename = NULL;

	basename = strrchr(srcpath, '/');
	if (basename == NULL)
		basename = srcpath - 1;
	basename++;	/* skip '/' */
	if (snprintf(newpath, newlen, "%s/%s", dstpath, basename) >= newlen) {
		pfs_etrace("too long name %s/%s", dstpath, basename);
		return -ENAMETOOLONG;
	}
	return 0;
}

int
extract_pbdname(const char *srcpath, const char *dstpath, char *pbdname)
{
	int err1, err2;
	char srcpbdname[PFS_MAX_PBDLEN] = {'\0'};
	char dstpbdname[PFS_MAX_PBDLEN] = {'\0'};

	err1 = get_pbdname(srcpath, srcpbdname, sizeof(srcpbdname));
	err2 = get_pbdname(dstpath, dstpbdname, sizeof(dstpbdname));
	if (err1 < 0 && err2 < 0) {
		pfs_etrace("cp: can't find any pbdname\n");
		return -1;
	}

	if (srcpbdname[0] != '\0' && dstpbdname[0] != '\0' &&
	    strncmp(srcpbdname, dstpbdname, PFS_MAX_PBDLEN) != 0) {
		pfs_etrace("cp: different pbdnames are found\n");
		return -1;
	}

	memset(pbdname, 0, PFS_MAX_PBDLEN);
	if (dstpbdname[0] != '\0') {
		if (strncpy_safe(pbdname, dstpbdname, sizeof(dstpbdname)) < 0)
			return -1;
		return MNTFLG_RD|MNTFLG_WR|MNTFLG_LOG;	// dst is in pfs
	}
	if (srcpbdname[0] != '\0') {
		if (strncpy_safe(pbdname, srcpbdname, sizeof(srcpbdname)) < 0)
			return -1;
		return MNTFLG_RD|MNTFLG_LOG;		// src is in pfs
	}
	return 0;		// neither dst nor src is pfs
}

int
copy_file(const char *srcpath, const char *dstpath)
{
	int err;
	int srcfd, dstfd;
	ssize_t ncp;

	srcfd = dstfd = -1;

	srcfd = MYSQLAPI_OPEN(srcpath, O_RDONLY, 0644);
	if (srcfd < 0) {
		pfs_etrace("cp: open file %s failed, errinfo=%s\n", srcpath,
		    strerror(errno));
		err = srcfd;
		goto finish_cp;
	}

	dstfd = MYSQLAPI_OPEN(dstpath, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (dstfd < 0) {
		pfs_etrace("cp: open file %s failed, errinfo=%s\n", dstpath,
		    strerror(errno));
		err = dstfd;
		goto finish_cp;
	}

	ncp = do_write(srcfd, dstfd, 0, -1);
	if (ncp < 0) {
		pfs_etrace("cp: copy file from %s to %s failed, errinfo=%s\n",
			srcpath, dstpath, strerror(errno));
		err = ncp;
	} else {
		printf("copy file from %s to %s succeeded\n", srcpath, dstpath);
		err = 0;
	}

finish_cp:
	if (srcfd >= 0)
		MYSQLAPI_CLOSE(srcfd);
	if (dstfd >= 0)
		MYSQLAPI_CLOSE(dstfd);

	err = err < 0 ? -1 : 0;
	return err;
}

static int
copy_dir(const char *srcpath, const char *dstpath, const opts_cp_t *co_cp)
{
	int err;
	char newsrc[PFS_MAX_PATHLEN] = {'\0'};
	char newdst[PFS_MAX_PATHLEN] = {'\0'};
	DIR *dir;
	struct dirent *de;
	struct dirent debuf;

	dir = MYSQLAPI_OPENDIR(srcpath);
	if (dir == NULL)
	       return -1;

	while ((err = MYSQLAPI_READDIR_R(dir, &debuf, &de)) == 0 && de) {
		/*
		 * XXX: skip both directory and hidden files?
		 */
		if (strncmp(de->d_name, ".", 1) == 0 ||
		    strncmp(de->d_name, "..", 2) == 0)
			continue;

		pbdpath_join(srcpath, de->d_name, newsrc, PFS_MAX_PATHLEN);
		pbdpath_join(dstpath, de->d_name, newdst, PFS_MAX_PATHLEN);

		err = do_copy(newsrc, newdst, false, co_cp);
		if (err < 0)
			break;
	}
	MYSQLAPI_CLOSEDIR(dir);

	err = err < 0 ? -1 : 0;
	return err;
}

static int
do_copy(const char *srcpath, const char *dstpath, bool firstcopy,
    const opts_cp_t *co_cp)
{
	int err;
	struct stat srcst, dstst;
	char dstpath2[PFS_MAX_PATHLEN];

	err = MYSQLAPI_STAT(srcpath, &srcst);
	if (err < 0) {
		pfs_etrace("do_copy failed to stat src %s: %s\n", srcpath,
		    strerror(errno));
		return err;
	}

again:
	/*
	 * ENOENT error is OK, since we can create a new
	 * file or directory with @dstpath. How to create
	 * is delayed until the mode of srcpath is known.
	 */
	err = MYSQLAPI_STAT(dstpath, &dstst);
	if (err < 0 && errno != ENOENT) {
		pfs_etrace("failed to stat dst %s: %s\n", dstpath,
		    strerror(errno));
		return err;
	}

	if (!S_ISDIR(srcst.st_mode)) {
		if (err == 0) {
			if (S_ISDIR(dstst.st_mode)) {
				err = splice_path(srcpath, dstpath, dstpath2,
				    PFS_MAX_PATHLEN);
				if (err < 0)
					return err;
				dstpath = dstpath2;
			} else if (co_cp->force == false) {
				pfs_etrace("can't overwrite %s with %s\n",
				    dstpath, srcpath);
				return -1;
			}
		} else {
			;	/* delegate create to do_copy_file */
		}
		err = copy_file(srcpath, dstpath);
	} else {
		if (co_cp->recursive == false) {
			pfs_etrace("cp: omitting directory %s\n", srcpath);
			return -EISDIR;
		}

		if (err == 0) {
			if (S_ISDIR(dstst.st_mode)) {
				if (firstcopy) {
					err = splice_path(srcpath, dstpath,
					    dstpath2, PFS_MAX_PATHLEN);
					if (err < 0)
						return err;
					dstpath = dstpath2;
					firstcopy = false;
					goto again;	/* stat dst again */
				}
			} else {
				pfs_etrace("can't cp dir %s to file %s\n",
				    srcpath, dstpath);
				return -1;
			}
		} else {
			err = MYSQLAPI_MKDIR(dstpath, 0755);
			if (err < 0) {
				pfs_etrace("failed to mkdir %s: %s\n",
				    dstpath, strerror(errno));
				return err;
			}
		}
		err = copy_dir(srcpath, dstpath, co_cp);
	}
	return err;
}

int
cp_between_pbd(const char *srcpath, const char *dstpath, const opts_cp_t *co_cp)
{
	int err;
	char src_pbdname[PFS_MAX_PBDLEN] = {'\0'};
	char dst_pbdname[PFS_MAX_PBDLEN] = {'\0'};
	const char *src_cluster = NULL;
	const char *dst_cluster = NULL;
	bool src_mounted = false;
	bool cluster_equal = false;

	src_cluster = co_cp->src_cluster;
	dst_cluster = co_cp->dst_cluster;

	if (strcmp(src_cluster, dst_cluster) == 0)
		cluster_equal = true;

	if (cluster_equal && strncmp(srcpath, dstpath, PFS_MAX_PATHLEN) == 0) {
		pfs_etrace("cp: can't copy ‘%s:%s’ into itself\n", src_cluster, srcpath);
		return -1;
	}

	err = get_pbdname(srcpath, src_pbdname, sizeof(src_pbdname));
	if (err < 0) {
		pfs_etrace("cp: src ‘%s’ can't find any pbdname\n", srcpath);
		return -1;
	}

	err = get_pbdname(dstpath, dst_pbdname, sizeof(dst_pbdname));
	if (err < 0) {
		pfs_etrace("cp: dst ‘%s’ can't find any pbdname\n", dstpath);
		return -1;
	}

	err = pfs_mount(dst_cluster, dst_pbdname, co_cp->dst_hostid, PFS_TOOL | PFS_RDWR);
	if (err < 0) {
		pfs_etrace("dst cant mount %s\n", dst_pbdname);
		return -1;
	}

	if (!cluster_equal || strcmp(src_pbdname, dst_pbdname) != 0) {
		err = pfs_mount(src_cluster, src_pbdname, co_cp->src_hostid, PFS_TOOL | PFS_RD);
		if (err < 0) {
			pfs_etrace("src cant mount %s\n", src_pbdname);
			goto finish_mount;
		}

		src_mounted = true;
	}

	err = do_copy(srcpath, dstpath, true, co_cp);

finish_mount:
	pfs_umount(dst_pbdname);
	if (src_mounted)
		pfs_umount(src_pbdname);

	return err;
}

static int
cmd_cp(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	int flags;
	char srcpath[PFS_MAX_PATHLEN] = {'\0'};
	char dstpath[PFS_MAX_PATHLEN] = {'\0'};
	char pbdname[PFS_MAX_PBDLEN] = {'\0'};
	opts_cp_t *co_cp = (opts_cp_t *)co;

	if (argc != 2)
	       return -1;

	pbdpath_copy(srcpath, argv[0], sizeof(srcpath));
	pbdpath_copy(dstpath, argv[1], sizeof(dstpath));

	/* deal cp file/dir between pbd */
	if (co_cp->src_cluster && co_cp->dst_cluster)
		return cp_between_pbd(srcpath, dstpath, co_cp);

	/*
	 * deal cp local between pbd
	 * mount pbd
	 * check src's type
	 */
	if (strncmp(srcpath, dstpath, sizeof(srcpath)) == 0) {
		pfs_etrace("cp: can't copy ‘%s’ into itself\n", srcpath);
		return -1;
	}

	flags = extract_pbdname(srcpath, dstpath, pbdname);
	if (flags < 0)
	       return -1;

	err = pfs_mount(co_cp->cluster, pbdname, co->co_common.hostid, PFS_TOOL | flags);
	if (err < 0) {
		pfs_etrace("cant mount %s\n", pbdname);
	       return -1;
	}

	err = do_copy(srcpath, dstpath, true, co_cp);

	pfs_umount(pbdname);

	return err;
}

PFSCMD_INFO(cp, 0, PFS_RDWR, getopt_cp, cmd_cp, usage_cp, "copy file or dir");
