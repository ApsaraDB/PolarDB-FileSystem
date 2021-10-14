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

#include <sys/param.h>
#include <getopt.h>

#include "pfs_api.h"
#include "pfs_file.h"
#include "pfs_log.h"
#include "pfs_mount.h"
#include "pfs_paxos.h"
#include "pfs_impl.h"
#include "cmd_impl.h"

#define	MODULAR_ADD(a, b, modulus)		\
	((a + b) % modulus)

#define	MODULAR_SUB(a, b, modulus)		\
	((a >= b) ? (a - b) : (a + modulus - b))

#define	MODULAR_CUT(off, len, modulus)		\
	((off + len > modulus) ? (modulus - off) : len)

static const pfs_logentry_phy_t	emptyle = {0};

typedef struct opts_dumple {
	opts_common_t	common;
	bool		all;
	int64_t		txid;
	int		motype;
	uint64_t	mono;
} opts_dumple_t;

typedef struct dumple_filt {
	opts_dumple_t	*opts;
	int		nmatch;
	int		ntotal;
} dumple_filt_t;

static struct option long_opts_dumple[] = {
	{ "txid",	required_argument,	NULL,	't' },
	{ "btno",	required_argument,	NULL,	'b' },
	{ "deno",	required_argument,	NULL,	'd' },
	{ "inno",	required_argument,	NULL,	'i' },
	{ 0 },
};

void
usage_dumple()
{
	printf("pfs dumple [-h] | [-t <txid> ] [-b | -d | -i mono] pbdname\n"
	    "  -h:            show help\n"
	    "  -a, --all      check all log entries in journal, instead of the valid range\n"
	    "  -t, --txid:    select log entries of specific txid\n"
	    "  -b, --btno:    select log entries of specific blktag\n"
	    "  -d, --deno:    select log entries of specific direntry\n"
	    "  -i, --ino:     select log entries of specific inode\n");
}

int
getopt_dumple(int argc, char *argv[], cmd_opts *co)
{
	int opt;
	opts_dumple_t *co_dumple = (opts_dumple_t *)co;

	co_dumple->all = false;
	co_dumple->txid = -1;
	co_dumple->motype = MT_NONE;
	co_dumple->mono = 0;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hat:b:d:i:", long_opts_dumple, NULL)) != -1) {
		switch (opt) {
		case 'a':
			co_dumple->all = true;
			break;

		case 't':
			co_dumple->txid = strtoll(optarg, NULL, 0);
			break;

		case 'b':
			co_dumple->motype = MT_BLKTAG;
			co_dumple->mono = strtoull(optarg, NULL, 0);
			break;

		case 'd':
			co_dumple->motype = MT_DIRENTRY;
			co_dumple->mono = strtoull(optarg, NULL, 0);
			break;

		case 'i':
			co_dumple->motype = MT_INODE;
			co_dumple->mono = strtoull(optarg, NULL, 0);
			break;

		case 'h':
		default:
			return -1;
		}
	}

	return optind;
}

#define PFS_FD_MAKE(fd) 					\
	(int)((unsigned int)(fd) | (1U << PFS_FD_VALIDBIT))

static int
file_open(pfs_mount_t *mnt, pfs_ino_t ino)
{
	int err, fd;

	/* open file without path lookup */
	fd = pfs_file_open_impl(mnt, ino, 0, NULL, INNER_FILE_BTIME);
	err = fd < 0 ? fd : 0;
	if (err < 0) {
		pfs_etrace("failed to open inode %ld: %d\n",
		    ino, err);
		return err;
	}

	return PFS_FD_MAKE(fd);
}

static int
journal_dump(pfs_mount_t *mnt, uint64_t tailoff, uint64_t headoff, uint64_t logsize,
    bool (*filtfn)(pfs_logentry_phy_t*, void*), dumple_filt_t *filtargs)
{
	int			fd, nle, err;
	uint64_t		off;
	ssize_t			rlen, left;
	size_t			bufsize;
	pfs_logentry_phy_t	*lebuf;
	pfs_logentry_phy_t	*le;

	PFS_ASSERT(tailoff < logsize && headoff < logsize);

	fd = file_open(mnt, JOURNAL_FILE_MONO);
	if (fd < 0)
		return fd;

	err = 0;
	bufsize = PFS_FRAG_SIZE;
	le = lebuf = (pfs_logentry_phy_t *)malloc(bufsize);
	memset(lebuf, 0, bufsize);
	nle = 0;
	for (off = tailoff; ; le++) {
		if (le == &lebuf[nle]) {
			left = MODULAR_SUB(headoff, off, logsize);
			if (left == 0)
				break;
			/* reload log entries into buffer */
			rlen = MIN(MODULAR_CUT(off, bufsize, logsize), left);
			rlen = pfs_pread(fd, lebuf, rlen, off);
			if (rlen < 0) {
				err = rlen;
				break;
			}
			le = lebuf;
			nle = rlen / sizeof(pfs_logentry_phy_t);
			off = MODULAR_ADD(off, rlen, logsize);
		}

		if (filtfn(le, filtargs)) {
			pfs_log_dump(le, 1, 0);
		}
	}

	pfs_close(fd);
	free(lebuf);
	return err;
}

static int
journal_locate(pfs_mount_t *mnt, uint64_t *tailoff, uint64_t *headoff,
    uint64_t *logsize)
{
	int err, fd;
	char buf[PBD_SECTOR_SIZE];
	pfs_leader_record_t *lr;

	fd = file_open(mnt, PAXOS_FILE_MONO);
	if (fd < 0)
		return fd;

	err = pfs_pread(fd, buf, sizeof(buf), 0);
	if (err < 0) {
		pfs_close(fd);
		return err;
	}
	lr = (pfs_leader_record_t *)buf;

	pfs_itrace("journal status: size %lu, offset [%lu, %lu), txid [%ld, %ld)\n",
	    lr->log_size, lr->tail_offset, lr->head_offset,
	    lr->tail_txid, lr->head_txid);

	*headoff = lr->head_offset;
	*tailoff = lr->tail_offset;
	*logsize = lr->log_size;

	pfs_close(fd);
	return 0;
}

static bool
dumple_filter(pfs_logentry_phy_t *le, void *args)
{
	dumple_filt_t *filtargs = (dumple_filt_t *)args;
	opts_dumple_t *co_dumple = filtargs->opts;
	pfs_metaobj_phy_t *mo = &le->le_obj_val;

	filtargs->ntotal++;
	if (memcmp(&emptyle, le, sizeof(*le)) == 0)
		return false;

	/* filter when condition specified but not matched */
	if (co_dumple->txid != -1 &&
	    !(co_dumple->txid == le->le_txid))
		return false;
	if (co_dumple->motype != MT_NONE &&
	    !(co_dumple->motype == mo->mo_type &&
	    co_dumple->mono == mo->mo_number))
		return false;
	filtargs->nmatch++;
	return true;
}

static int
dumple_execute(pfs_mount_t *mnt, opts_dumple_t *co_dumple)
{
	int err;
	uint64_t tailoff, headoff, logsize;
	dumple_filt_t filtargs;

	err = journal_locate(mnt, &tailoff, &headoff, &logsize);
	if (err < 0)
		return err;

	memset(&filtargs, 0, sizeof(filtargs));
	filtargs.opts = co_dumple;
	filtargs.ntotal = 0;
	filtargs.nmatch = 0;
	if (co_dumple->all) {
		/*
		 * To dump the whole journal, reset @tailoff and
		 * dump it twice, since the journal is a ring buffer.
		 */
		tailoff = MODULAR_ADD(headoff, sizeof(pfs_logentry_phy_t), logsize);
		err = journal_dump(mnt, headoff, tailoff, logsize,
		    dumple_filter, &filtargs);
		if (err < 0)
			return err;
	}
	err = journal_dump(mnt, tailoff, headoff, logsize,
	    dumple_filter, &filtargs);
	if (err < 0)
		return err;

	pfs_itrace("number of log entries hit: %d / %d (%s)\n",
	    filtargs.nmatch, filtargs.ntotal,
	    co_dumple->all ? "all in journal" : "valid");
	return 0;
}

int
cmd_dumple(int argc, char *argv[], cmd_opts *co)
{
	opts_dumple_t	*co_dumple = (opts_dumple_t *)co;
	pfs_mount_t	*mnt;
	char		*pbdname;
	int		err;

	if (argc != 1)
		return -1;
	pbdname = argv[0];

	mnt = pfs_get_mount(pbdname);
	if (mnt == NULL) {
		pfs_etrace("failed to get mount %s\n", pbdname);
		return -1;
	}

	err = dumple_execute(mnt, co_dumple);

	pfs_put_mount(mnt);

	return err;
}

/* mount without log thread, in case of meta corruption */
PFSCMD_INFO(dumple, CMDF_MOUNT, PFS_RD ^ MNTFLG_LOG, getopt_dumple, cmd_dumple, usage_dumple, "dump log entries");
