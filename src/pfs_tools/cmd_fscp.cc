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

#include <sys/stat.h>
#include <sys/param.h>

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <malloc.h>

#include "cmd_impl.h"
#include "pfs_api.h"
#include "pfs_devio.h"
#include "pfs_dir.h"
#include "pfs_impl.h"
#include "pfs_mount.h"
#include "pfs_paxos.h"
#include "pfs_trace.h"
#include "pfs_util.h"

/*
 * In PFS, metainfo are stored in two positions, superblocks and log file.
 * The former has stale metainfo, the last has incremental metainfo. PFS should
 * combine both metainfo in superblocks and log file to get correct metainfo.
 *
 * As mentioned above, fscp copies a file system as follows:
 * 	(1) Get used blocks in src PBD
 * 	    mount src PBD with READONLY and get all used blocks.
 * 	(2) Copy used blocks to dst PBD by I/O workers
 * 	    multiple I/O workers are started and each one transfers used blocks
 * 	    of one chunk at one time. The number of workers shouldn't be bigger
 * 	    than valid chunks in PBD.
 * 	(3) Modify leader record of .pfs-paxos in dst PBD
 * 	    checksum should be set to dst pbdname, otherwise disk
 * 	    paxos would fail when verify_leader()
 */

typedef struct opts_fscp {
	opts_common_t   	common;
	int			nworker;
	int			nfrag;	/* pending frag number when copying a block */
	const char		*src_cluster;
	const char		*dst_cluster;
	bool crc_check;
} opts_fscp_t;

enum {
	TASK_INVALID	= 0,
	TASK_NORMAL	= 1,
	TASK_POSION	= 2,
};

typedef struct fscp_info fscp_info_t;
typedef struct iotask {
	TAILQ_ENTRY(iotask)	t_next;
	int			t_type;
	int			t_ckid;
	oidvect_t		*t_ov;
} iotask_t;
TAILQ_HEAD(task_qhead, iotask);

#define NFRAG_MIN	8	/* min pending fragment number */
#define NFRAG_MAX	(PFS_BLOCK_SIZE / PFS_FRAG_SIZE) /* max pending
							    fragment number */
#define NWORKER_MIN	2	/* min worker number*/
#define NWORKER_MAX	36	/* max worker number */
typedef struct fscp_info {
	uint64_t		i_disksize;
	uint64_t		i_chunksize;

	const char		*i_src_cluster;
	const char		*i_src_pbd;
	const char		*i_dst_cluster;
	const char		*i_dst_pbd;
	int  			i_src_iochd;
	int  			i_dst_iochd;
	int			i_dst_local_fd;		/* local paxos lock */

	pthread_mutex_t		i_task_mtx;
	pthread_cond_t		i_task_cond;
	struct task_qhead	i_task_queue;

	int			i_nfrag;		/* pending fragment number */
	int64_t			i_nblkcopy;
	int64_t			i_nckcopy;

	int			i_nworker;
	pthread_t		i_workers[NWORKER_MAX];
	bool i_crc_check;
} fscp_info_t;

static struct option long_opts_fscp[] = {
	{ "help",		optional_argument,	NULL,	'h' },
	{ "nworker",		optional_argument,	NULL,	'w' },
	{ "nfrag",		optional_argument,	NULL,	'n' },
	{ "crc_check",		no_argument,		NULL,	'c' },
	{ "src_cluster",	optional_argument,	NULL,	'S' },
	{ "dst_cluster",	optional_argument,	NULL,	'D' },
	{ 0 },
};

void
usage_fscp()
{
	printf("pfs fscp [-w ioworkernum] [-n nfragment] [-c ] [-S|--src_cluster=src_cluster] [-D|--dst_cluster=dst_cluster]"
	" src_pbdname dst_pbdname\n"
	"  -h, --help:             show this help message\n"
	"  -w, --nworker:          I/O worker number @ [%d, %d]\n"
	"  -n, --nfrag:            pending fragments number when copying a block @ [%d, %d]\n"
	"  -S, --src_cluster:      source cluster name\n"
	"  -D, --dst_cluster:      destination cluster name\n"
	"  -c, --crc_check:        it will compare src pbd block and dest pbd "
				"block crc num. if crc check failed, we must check "
				"the error! crc check enhanced fscp reliability,"
				"but it will increase fscp time cost.\n\n"
	"copy the whole file system from src to dst, one I/O worker transfers one chunk.\n",
	 NWORKER_MIN, NWORKER_MAX, NFRAG_MIN, NFRAG_MAX);
}

int
getopt_fscp(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_fscp_t *co_fscp = (opts_fscp_t*)co;

	co_fscp->nworker = NWORKER_MIN;
	co_fscp->nfrag = NFRAG_MIN;
	co_fscp->src_cluster = CL_DEFAULT;
	co_fscp->dst_cluster = CL_DEFAULT;
	co_fscp->crc_check = false;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "hw:n:cS:D:", long_opts_fscp, NULL)) != -1) {
		switch (opt) {
		case 'w':
			co_fscp->nworker = atoi(optarg);
			if (co_fscp->nworker > NWORKER_MAX)
				co_fscp->nworker = NWORKER_MAX;
			if (co_fscp->nworker < NWORKER_MIN)
				co_fscp->nworker = NWORKER_MIN;
			break;

		case 'n':
			co_fscp->nfrag = atoi(optarg);
			if (co_fscp->nfrag > (int)NFRAG_MAX)
				co_fscp->nfrag = NFRAG_MAX;
			if (co_fscp->nfrag < NFRAG_MIN)
				co_fscp->nfrag = NFRAG_MIN;
			break;

		case 'S':
			co_fscp->src_cluster = optarg;
			break;

		case 'D':
			co_fscp->dst_cluster = optarg;
			break;

		case 'c':
			co_fscp->crc_check = true;
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

static bool
skip_block_hole(pfs_bda_t iobda, int holeoff)
{
	int32_t blkoff = iobda % PFS_BLOCK_SIZE;
	if (blkoff >= holeoff)
		return true;

	return false;
}

static int
frag_read(int iochd, pfs_bda_t fragbda, void *buf, int nfrag, int holeoff)
{
	int err, waiterr;
	char *data;
	pfs_bda_t iobda;

	err = waiterr = 0;
	data = (char *)buf;
	iobda = fragbda;
	bool waitio = false;
	for (; nfrag > 0; nfrag--) {
		if (skip_block_hole(iobda, holeoff)) {
			break;
		}

		err = pfsdev_pread_flags(iochd, data, PFS_FRAG_SIZE, iobda,
		    IO_NOWAIT);
		waitio = true;
		if (err < 0) {
			pfs_etrace("read from %d @ %ld, %d failed, err=%d\n",
			    iochd, iobda, PFS_FRAG_SIZE, err);
			break;
		}
		data += PFS_FRAG_SIZE;
		iobda += PFS_FRAG_SIZE;
	}

	if (waitio) {
		waiterr = pfsdev_wait_io(iochd);
		if (err < 0 || waiterr < 0)
			return -EIO;
	}
	return 0;
}

static int
frag_write(int iochd, pfs_bda_t fragbda, void *buf, int nfrag, int32_t holeoff)
{
	int err, waiterr;
	char *data;
	pfs_bda_t iobda;

	err = waiterr = 0;
	data = (char *)buf;
	iobda = fragbda;
	bool waitio = false;
	for (; nfrag > 0; nfrag--) {
		if (skip_block_hole(iobda, holeoff)) {
			break;
		}

		err = pfsdev_pwrite_flags(iochd, data, PFS_FRAG_SIZE, iobda,
		    IO_NOWAIT);
		waitio = true;
		if (err < 0) {
			pfs_etrace("write to %d @ %ld, %d failed, err=%d\n",
			    iochd, iobda, PFS_FRAG_SIZE, err);
			break;
		}
		data += PFS_FRAG_SIZE;
		iobda += PFS_FRAG_SIZE;
	}

	if (waitio) {
		waiterr = pfsdev_wait_io(iochd);
		if (err < 0 || waiterr < 0)
			return -EIO;
	}
	return 0;
}

static int
frag_copy(fscp_info_t *cpinfo, pfs_bda_t fragbda, void *buf, int nfrag, int32_t holeoff)
{
	int err;

	err = frag_read(cpinfo->i_src_iochd, fragbda, buf, nfrag, holeoff);
	if (err < 0)
		return err;

	err = frag_write(cpinfo->i_dst_iochd, fragbda, buf, nfrag, holeoff);
	if (err < 0)
		return err;

	return 0;
}

static int
block_copy(fscp_info_t *cpinfo, pfs_blkno_t blkno, void *iobuf, size_t buflen, int32_t holeoff)
{
	int i, err, nfrag, fragperblk;
	pfs_bda_t fragbda;

	fragbda = blkno * PFS_BLOCK_SIZE;
	fragperblk = PFS_BLOCK_SIZE / PFS_FRAG_SIZE;
	for (i = 0; i < fragperblk; i += nfrag) {
		nfrag = MIN(fragperblk - i, cpinfo->i_nfrag);
		PFS_ASSERT((size_t)nfrag * PFS_FRAG_SIZE <= buflen);

		err = frag_copy(cpinfo, fragbda, iobuf, nfrag, holeoff);
		if (err < 0)
			return err;
		fragbda += (int64_t)nfrag * PFS_FRAG_SIZE;
	}

	__sync_add_and_fetch(&cpinfo->i_nblkcopy, 1);
	printf("%lu blocks have been copied, %ld chunks are done\r",
	    cpinfo->i_nblkcopy, cpinfo->i_nckcopy);
	fflush(stdout);
	return 0;
}

static int
chunk_copy(fscp_info_t *cpinfo, int ckid, oidvect_t *pov)
{
	int i, err;
	int64_t oid;
	pfs_blkno_t blkno;
	void *iobuf;
	int32_t holeoff;

	iobuf = malloc(PFS_FRAG_SIZE * cpinfo->i_nfrag);
	PFS_ASSERT(iobuf != NULL);

	for (i = oidvect_begin(pov); i < oidvect_end(pov); i++) {
		oid = oidvect_get(pov, i);
		holeoff = oidvect_get_holeoff(pov, i);
		blkno = (int64_t)ckid * PFS_NBT_PERCHUNK + oid;
		err = block_copy(cpinfo, blkno, iobuf,
		    cpinfo->i_nfrag * PFS_FRAG_SIZE, holeoff);
		if (err < 0) {
			pfs_etrace("copy %lld blk in chunk %d failed, err=%d\n",
			    blkno, ckid, err);
			free(iobuf);
			return err;
		}
	}
	free(iobuf);

	__sync_add_and_fetch(&cpinfo->i_nckcopy, 1);
	printf("%lu blocks have been copied, %ld chunks are done\r",
	    cpinfo->i_nblkcopy, cpinfo->i_nckcopy);
	fflush(stdout);

	/*
	 * If copying a large PBD, we can track progress by log file.
	 */
	pfs_itrace("%lu blocks have been copied, %ld chunks are done\n",
	    cpinfo->i_nblkcopy, cpinfo->i_nckcopy);
	return 0;
}

static int
chunk_crc_check(fscp_info_t *cpinfo, int ckid, oidvect_t *pov)
{
	int64_t oid;
	pfs_blkno_t blkno;
	void *src_iobuf;
	void *dst_iobuf;
	int32_t holeoff;
	int32_t i, j, err, nfrag, fragperblk, crc_len;
	pfs_bda_t fragbda;

	src_iobuf = malloc(PFS_BLOCK_SIZE);
	dst_iobuf = malloc(PFS_BLOCK_SIZE);
	PFS_ASSERT(src_iobuf != NULL);
	PFS_ASSERT(dst_iobuf != NULL);

	err = 0;
	fragperblk = PFS_BLOCK_SIZE / PFS_FRAG_SIZE;
	for (i = oidvect_begin(pov); i < oidvect_end(pov); i++) {
		oid = oidvect_get(pov, i);
		holeoff = oidvect_get_holeoff(pov, i);
		blkno = (int64_t)ckid * PFS_NBT_PERCHUNK + oid;
		fragbda = blkno * PFS_BLOCK_SIZE;

		for (j = 0; j < fragperblk; j += nfrag) {
			nfrag = MIN(fragperblk - j, cpinfo->i_nfrag);

			err = frag_read(cpinfo->i_src_iochd, fragbda, src_iobuf,
			    nfrag, holeoff);
			if (err < 0)
				goto out;
			err = frag_read(cpinfo->i_dst_iochd, fragbda, dst_iobuf,
			    nfrag, holeoff);
			if (err < 0)
				goto out;

			fragbda += (int64_t)nfrag * PFS_FRAG_SIZE;
		}

		if (holeoff > 0) {
			crc_len = (uint32_t)holeoff > PFS_BLOCK_SIZE ?
			    PFS_BLOCK_SIZE : holeoff;

			uint32_t src_crc = crc32c_compute(src_iobuf, crc_len, 0);
			uint32_t dst_crc = crc32c_compute(dst_iobuf, crc_len, 0);

			if (src_crc != dst_crc) {
				pfs_etrace("crc check failed! src_crc=%u, dst_crc=%u,\
				    oid=%ld, blkno=%ld, holeoff=%d",
				    src_crc, dst_crc,oid, blkno, holeoff);
				exit(-1);
			}
			printf("crc check pass! crc=%u, ckid=%d, oid=%ld, blkno=%ld,\
			    holeoff=%d\r", src_crc, ckid, oid, blkno, holeoff);
			fflush(stdout);
		}
	}

out:
	free(src_iobuf);
	src_iobuf = NULL;
	free(dst_iobuf);
	dst_iobuf = NULL;
	return err;
}

static void
iotask_enqueue(fscp_info_t *cpinfo, iotask_t *task)
{
	mutex_lock(&cpinfo->i_task_mtx);
	TAILQ_INSERT_TAIL(&cpinfo->i_task_queue, task, t_next);
	cond_signal(&cpinfo->i_task_cond);
	mutex_unlock(&cpinfo->i_task_mtx);
}

static iotask_t*
iotask_dequeue(fscp_info_t *cpinfo)
{
	iotask_t *task = NULL;

	mutex_lock(&cpinfo->i_task_mtx);
	while (TAILQ_EMPTY(&cpinfo->i_task_queue))
		cond_wait(&cpinfo->i_task_cond, &cpinfo->i_task_mtx);
	task = TAILQ_FIRST(&cpinfo->i_task_queue);
	TAILQ_REMOVE(&cpinfo->i_task_queue, task, t_next);
	mutex_unlock(&cpinfo->i_task_mtx);

	return task;
}

static void *
ioworker_main(void *arg)
{
	int err;
	iotask_t *task;
	fscp_info_t *cpinfo = (fscp_info_t *)arg;

	for (;;) {
		task = iotask_dequeue(cpinfo);
		if (task->t_type == TASK_POSION) {
			free(task);
			break;
		}

		PFS_ASSERT(task->t_type == TASK_NORMAL);
		PFS_ASSERT(task->t_ckid >= 0);
		PFS_ASSERT(task->t_ov != NULL);
		err = chunk_copy(cpinfo, task->t_ckid, task->t_ov);
		if (err < 0) {
			pfs_etrace("copy chunk %d failed, err=%d\n",
			    task->t_ckid, err);
			exit(EIO);
		}

		if (cpinfo->i_crc_check) {
			err = chunk_crc_check(cpinfo, task->t_ckid, task->t_ov);
			if (err < 0) {
				pfs_etrace("chunk crc check %d failed, err=%d\n",
				    task->t_ckid, err);
				exit(EIO);
			}
		}

		oidvect_fini(task->t_ov);
		task->t_ov = NULL;
		free(task);
	}

	return NULL;
}

static void
start_all_workers(fscp_info_t *cpinfo)
{
	int i, err;

	for (i = 0; i < cpinfo->i_nworker; i++) {
		err = pthread_create(&cpinfo->i_workers[i], NULL, ioworker_main,
		    cpinfo);
		PFS_ASSERT(err == 0);
	}

	printf("start %u I/O workers\n", cpinfo->i_nworker);
	fflush(stdout);
}

static void
stop_all_workers(fscp_info_t *cpinfo)
{
	int i, err;
	iotask_t* posion_task;

	if (cpinfo->i_nworker == 0)
		return;

	/* send posion to worker threads */
	for (i = 0; i < cpinfo->i_nworker; ++i) {
		if (cpinfo->i_workers[i] == 0)
			continue;
		posion_task = (iotask_t*)malloc(sizeof(*posion_task));
		if (posion_task == NULL)
			exit(ENOMEM);

		memset(posion_task, 0, sizeof(*posion_task));
		posion_task->t_type = TASK_POSION;
		posion_task->t_ckid = -1;
		iotask_enqueue(cpinfo, posion_task);
	}

	for (i = 0; i < cpinfo->i_nworker; ++i) {
		if (cpinfo->i_workers[i] == 0)
			continue;
		err = pthread_join(cpinfo->i_workers[i], NULL);
		PFS_ASSERT(err == 0);
		cpinfo->i_workers[i] = 0;
	}

	printf("\nstop %d I/O workers\n", cpinfo->i_nworker);
	cpinfo->i_nworker = 0;
}

static void
fscpinfo_init(fscp_info_t *cpinfo, const char *src, const char *dst,
    opts_fscp_t *co_fscp)
{
	int i;

	memset(cpinfo, 0, sizeof(*cpinfo));

	cpinfo->i_disksize = 0;
	cpinfo->i_chunksize = 0;
	cpinfo->i_src_cluster = co_fscp->src_cluster;
	cpinfo->i_src_pbd = src;
	cpinfo->i_dst_cluster = co_fscp->dst_cluster;
	cpinfo->i_dst_pbd = dst;
	cpinfo->i_src_iochd = -1;
	cpinfo->i_dst_iochd = -1;
	cpinfo->i_dst_local_fd = -1;
	cpinfo->i_nblkcopy = 0;
	cpinfo->i_nckcopy = 0;
	cpinfo->i_nfrag = co_fscp->nfrag;
	cpinfo->i_crc_check = co_fscp->crc_check;

	mutex_init(&cpinfo->i_task_mtx);
	cond_init(&cpinfo->i_task_cond, NULL);
	TAILQ_INIT(&cpinfo->i_task_queue);

	cpinfo->i_nworker = co_fscp->nworker;
	for (i = 0; i < NWORKER_MAX; i++)
		cpinfo->i_workers[i] = 0;
}

static void
fscpinfo_fini(fscp_info_t *cpinfo)
{
	mutex_destroy(&cpinfo->i_task_mtx);
	cond_destroy(&cpinfo->i_task_cond);
	PFS_ASSERT(TAILQ_EMPTY(&cpinfo->i_task_queue) == true);

	if (cpinfo->i_dst_local_fd >= 0) {
		close(cpinfo->i_dst_local_fd);
		cpinfo->i_dst_local_fd = -1;
	}

	if (cpinfo->i_dst_iochd >= 0) {
		(void)pfsdev_close(cpinfo->i_dst_iochd);
		cpinfo->i_dst_iochd = -1;
	}
	cpinfo->i_dst_cluster = NULL;
	cpinfo->i_dst_pbd = NULL;

	if (cpinfo->i_src_iochd >= 0) {
		(void)pfsdev_close(cpinfo->i_src_iochd);
		cpinfo->i_src_iochd = -1;
	}
	cpinfo->i_src_cluster = NULL;
	cpinfo->i_src_pbd = NULL;

	cpinfo->i_disksize = 0;
	cpinfo->i_chunksize = 0;
	cpinfo->i_nblkcopy = 0;
	cpinfo->i_nckcopy = 0;
	cpinfo->i_nfrag = 0;
}

static int
get_pbdsize(const char *cluster, const char *pbdname, struct pbdinfo *info)
{
	int err, iochd;

	/* open pbd and get disk size from device */
	iochd = pfsdev_open(cluster, pbdname, DEVFLG_RD);
	if (iochd < 0) {
		pfs_etrace("cant open pbd %s, err=%d\n", pbdname, iochd);
		return iochd;
	}

	err = pfsdev_info(iochd, info);
	if (err < 0) {
		pfs_etrace("cant get pbd %s info, err=%d\n", pbdname, err);
		(void)pfsdev_close(iochd);
		return err;
	}
	PFS_ASSERT(info->pi_chunksize == PBD_CHUNK_SIZE);

	(void)pfsdev_close(iochd);
	return 0;
}

static int
check_pbdsize(fscp_info_t *cpinfo)
{
	int err;
	struct pbdinfo src_pi;
	struct pbdinfo dst_pi;

	/* open pbd and get disk size from device */
	err = 0;
	err = get_pbdsize(cpinfo->i_src_cluster, cpinfo->i_src_pbd, &src_pi);
	err |= get_pbdsize(cpinfo->i_dst_cluster, cpinfo->i_dst_pbd, &dst_pi);
	if (err < 0) {
		usage_fscp();
		return err;
	}

	pfs_itrace("src %s disk size=%#llx, chunk size=%#llx\n",
	    cpinfo->i_src_pbd, (unsigned long long)src_pi.pi_disksize,
	    (unsigned long long)src_pi.pi_chunksize);

	pfs_itrace("dst %s disk size=%#llx, chunk size=%#llx\n",
	    cpinfo->i_dst_pbd, (unsigned long long)dst_pi.pi_disksize,
	    (unsigned long long)dst_pi.pi_chunksize);

	if (src_pi.pi_chunksize != dst_pi.pi_chunksize) {
		pfs_etrace("chunk size of src=%#llx and dst=%#llx not equal!\n",
		    (unsigned long long)dst_pi.pi_chunksize,
		    (unsigned long long)src_pi.pi_chunksize);
		return -EINVAL;
	}
	if (src_pi.pi_disksize > dst_pi.pi_disksize) {
		pfs_etrace("src disk can't be bigger than dst disk.\n");
		return -EINVAL;
	} else if (src_pi.pi_disksize < dst_pi.pi_disksize) {
		pfs_itrace("src disk is smaller than dst disk, run 'growfs' on"
		    " dst after 'fscp'\n");
	}

	cpinfo->i_chunksize = src_pi.pi_chunksize;
	cpinfo->i_disksize = src_pi.pi_disksize;
	printf("copy info: disk size %#llx, chunk size %#llx, nchunk %ld\n",
	       (unsigned long long)cpinfo->i_disksize,
	       (unsigned long long)cpinfo->i_chunksize,
	       cpinfo->i_disksize / cpinfo->i_chunksize);

	return 0;
}

static int
list_used_blocks(fscp_info_t *cpinfo, oidvect_t **ov_array, int *nov)
{
	int i, err, nck;
	pfs_mount_t *mnt;
	oidvect_t *pov;

	/* get all used blocks */
	err = pfs_mount(cpinfo->i_src_cluster, cpinfo->i_src_pbd, 0,
	    PFS_TOOL | PFS_RD);
	if (err < 0) {
		pfs_etrace("mount %s failed, err=%d\n", cpinfo->i_src_pbd, err);
		return err;
	}
	mnt = pfs_get_mount(cpinfo->i_src_pbd);
	PFS_ASSERT(mnt != NULL);

	nck = mnt->mnt_nchunk;
	pov = (oidvect_t *)malloc(nck * sizeof(oidvect_t));
	if (pov == NULL)
		exit(ENOMEM);

	memset(pov, 0, nck * sizeof(oidvect_t));
	for (i = 0; i < nck; i++) {
		oidvect_init(&pov[i]);
		err = pfs_list_used(mnt, MT_BLKTAG, i, &pov[i]);
		PFS_ASSERT(err == 0);
	}

	pfs_put_mount(mnt);
	err = pfs_umount(cpinfo->i_src_pbd);
	PFS_ASSERT(err == 0);

	*ov_array = pov;
	*nov = nck;
	return err;
}

static int
fscp(fscp_info_t *cpinfo)
{
	int err, i, nov, stderrfd;
	oidvect_t *ov_array = NULL;
	iotask_t *task;
	int64_t nblk = 0;

	err = check_pbdsize(cpinfo);
	if (err < 0)
		goto out;

	cpinfo->i_dst_local_fd = paxos_hostid_local_lock(cpinfo->i_dst_pbd, 0,
	    __func__);
	if (cpinfo->i_dst_local_fd < 0) {
		err = cpinfo->i_dst_local_fd;
		goto out;
	}

	/*
	 * stderr is closed if list_used_blocks() returns. So duplicate
	 * it firstly.
	 */
	stderrfd = dup(STDERR_FILENO);
	err = list_used_blocks(cpinfo, &ov_array, &nov);
	dup2(stderrfd, STDERR_FILENO);
	if (err < 0)
		goto out;
	printf("[1] get used blocks list in %s(%d chunks) successfully\n",
	    cpinfo->i_src_pbd, nov);

	/* redirect stderr to dst log */
	pfs_trace_redirect(cpinfo->i_dst_pbd, 0);

	cpinfo->i_src_iochd = pfsdev_open(cpinfo->i_src_cluster, cpinfo->i_src_pbd,
	    DEVFLG_RD);
	if (cpinfo->i_src_iochd < 0)
		ERR_GOTO(EIO, out);
	cpinfo->i_dst_iochd = pfsdev_open(cpinfo->i_dst_cluster, cpinfo->i_dst_pbd,
	    DEVFLG_RDWR|DEVFLG_REQ_SAFE);
	if (cpinfo->i_dst_iochd < 0)
		ERR_GOTO(EIO, out);

	/*
	 * One I/O worker copies one chunk, so worker number shouldn't be
	 * bigger than chunk number.
	 */
	cpinfo->i_nworker = MIN(cpinfo->i_nworker, nov);
	start_all_workers(cpinfo);
	for (i = 0; i < nov; i++) {
		nblk += oidvect_end(&ov_array[i]) - oidvect_begin(&ov_array[i]);
		task = (iotask_t *)malloc(sizeof(*task));
		if (task == NULL)
			exit(ENOMEM);
		memset(task, 0, sizeof(*task));

		task->t_type = TASK_NORMAL;
		task->t_ckid = i;
		task->t_ov = &ov_array[i];
		iotask_enqueue(cpinfo, task);
	}
	printf("[2] send %d chunk copy tasks, %ld used blks\n", nov, nblk);

	stop_all_workers(cpinfo);
	PFS_ASSERT(cpinfo->i_nblkcopy == nblk);
	free(ov_array);
	ov_array = NULL;

	err = paxos_leader_reset(cpinfo->i_dst_iochd, cpinfo->i_dst_pbd);
	if (err < 0) {
		pfs_etrace("modify pfs_leader_record of %s failed, err=%d\n",
		    cpinfo->i_dst_pbd, err);
		goto out;
	}
	printf("[3] update %s paxos leader successfully\n", cpinfo->i_dst_pbd);

out:
	if (cpinfo->i_src_iochd >= 0) {
		(void)pfsdev_close(cpinfo->i_src_iochd);
		cpinfo->i_src_iochd = -1;
	}

	if (cpinfo->i_dst_iochd >= 0) {
		(void)pfsdev_close(cpinfo->i_dst_iochd);
		cpinfo->i_dst_iochd = -1;
	}

	if (ov_array) {
		for (i = 0; i < nov; i++)
			oidvect_fini(&ov_array[i]);
		free(ov_array);
		ov_array = NULL;
	}

	if (cpinfo->i_dst_local_fd >= 0) {
		close(cpinfo->i_dst_local_fd);
		cpinfo->i_dst_local_fd = -1;
	}

	return err;
}

int
cmd_fscp(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	fscp_info_t cpinfo;
	opts_fscp_t *co_fscp = (opts_fscp_t *)co;

	if (argc < 2) {
		usage_fscp();
		return -1;
	}

	/*
	 * PFSTool's memory does't shrink after umount. According to glibc
	 * malloc, heap can be trimmed only if memory is freed at the top
	 * end. Objects of mount are at the bottom of heap and oidvectors
	 * are at the top. So even umount is done, the free memory of those
	 * objects can't be given back to system.
	 *
	 * There are lots of 4KB memory allocations during mount, so adjust
	 * malloc option M_MMAP_THRESHOLD to 4KB.
	 */
	err = mallopt(M_MMAP_THRESHOLD, 4096);
	if (err != 1) {
		pfs_etrace("set M_MMAP_THRESHOLD to 4096 failed, err = %d\n", err);
	}

	fscpinfo_init(&cpinfo, argv[0], argv[1], co_fscp);
	err = fscp(&cpinfo);
	fscpinfo_fini(&cpinfo);

	if (err == 0) {
		printf("pfs fscp successfully\n");
		return 0;
	} else {
		printf("pfs fscp failed!\n");
		return -1;
	}
}

PFSCMD_INFO(fscp, 0, PFS_RDWR, getopt_fscp, cmd_fscp, usage_fscp, "transfer pfs pbd data");
