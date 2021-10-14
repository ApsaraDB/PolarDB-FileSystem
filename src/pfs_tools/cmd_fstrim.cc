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
#include <getopt.h>

#include "pfs_api.h"
#include "pfs_mount.h"

#include "cmd_impl.h"

typedef struct opts_fstrim {
	opts_common_t	common;
	int64_t		beginid;	/* beginning ckid, default value is 0. */
	int64_t		endid;		/* end ckid, -1 means the last,
					   discard range is [begin, end).*/
	bool		all;		/* discard all unused blocks, no matter
					   whether it is discarded. */
	bool		quiet;		/* no warning tips. */
} opts_fstrim_t;

static struct option long_opts[] = {
	{ "beginid", optional_argument,		NULL,	'b' },
	{ "endid", optional_argument,		NULL,	'e' },
	{ "all", optional_argument,		NULL,	'a' },
	{ "quiet", optional_argument,		NULL,	'q' },
	{ 0 },
};

void
usage_fstrim()
{
	printf("pfs fstrim [options] pbdname\n"
	    "  -b, --beginid:           beginning chunk id to discard (default is the first chunk)\n"
	    "  -e, --endid:             end chunk id to discard (default is the last chunk)\n"
	    "  -a, --all:               discard all unused blocks (default is disabled)\n"
	    "  -q, --quiet:             don't show warning tips (default is disabled)\n"
	    "discard unused blocks of chunks in [beginckid, endckid),\n"
	    "fstrim must be the ONLY ONE writer of current filesystem,\n"
	    "hostid must be set explicitly by '-H'.\n");
}

int
getopt_fstrim(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_fstrim_t *co_fstrim = (opts_fstrim_t *)co;

	co_fstrim->beginid = 0;
	co_fstrim->endid = -1;
	co_fstrim->all = false;
	co_fstrim->quiet = false;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hb:e:aq", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'b':
			co_fstrim->beginid = strtol(optarg, NULL, 10);
			break;

		case 'e':
			co_fstrim->endid = strtol(optarg, NULL, 10);
			break;

		case 'a':
			co_fstrim->all = true;
			break;

		case 'q':
			co_fstrim->quiet = true;
			break;

		case'h':
		default:
			return -1;
		}
	}
	return optind;
}

int
cmd_fstrim(int argc, char *argv[], cmd_opts_t *co)
{
#define WARNTIME	3
	int err;
	const char *pbdname;
	pfs_mount_t *mnt;
	opts_fstrim_t *co_fstrim = (opts_fstrim_t *)co;

	if (argc != 1) {
		usage_fstrim();
		exit(EINVAL);
	}
	pbdname = argv[0];
	pfs_trace_redirect(pbdname, 0);

	if (!co_fstrim->quiet) {
		printf("Make sure that fstrim is the ONLY ONE writer on"
		    " current device %s. sleep %ds.\n", pbdname, WARNTIME);
		sleep(WARNTIME);
	}

	/*
	 * TODO:
	 * In a POLARDB cluster, only one node attaches PBD with
	 * Read/Write permission. To make sure fstrim is the only
	 * one writer of cluster, it uses iochannel 0 as same as
	 * MySQL. Meanwhile, user must set hostid explicitly.
	 */
	err = pfs_mount(co->co_common.cluster, pbdname, co->co_common.hostid,
	    PFS_RDWR | PFS_TOOL | MNTFLG_DISCARD_BYFORCE);
	if (err < 0)
		return err;

	mnt = pfs_get_mount(pbdname);
	PFS_VERIFY(mnt != NULL);

	err = pfs_mount_fstrim(mnt, co_fstrim->beginid, co_fstrim->endid,
	    co_fstrim->all);
	if (err < 0)
		ERR_GOTO(EIO, umount);
	err = 0;

umount:
	pfs_put_mount(mnt);
	pfs_umount(pbdname);
	return err;
}

PFSCMD_INFO(fstrim, 0, PFS_RDWR, getopt_fstrim, cmd_fstrim, usage_fstrim, "trim filesystem");
