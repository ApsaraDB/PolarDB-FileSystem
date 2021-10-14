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

#include <sys/types.h>
#include <sys/time.h>

#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>

#include "pfs_impl.h"
#include "pfs_api.h"
#include "pfs_util.h"
#include "pfs_mount.h"
#include "pfs_dir.h"
#include "pfs_file.h"
#include "pfs_paxos.h"
#include "pfs_trace.h"
#include "pfs_option.h"


#define	PFS_MAX_DISKS		4

#define	DBLOCK_CHECKSUM_LEN	48

/*
 * Macros to substitute for functions in original code.
 */

#define	leader_record_in(a, b)	(*(b) = *(a))
#define	leader_record_out(a, b)	(*(b) = *(a))

#define	request_record_in(a, b)	(*(a) = *(b))
#define	request_record_out(a, b) (*(b) = *(a))

#define	cpu_to_le32(a)		(a)

static inline int
direct_align(size_t sector_size)
{
	if (sector_size == 512)
		return 1024 * 1024;

	if (sector_size == 4096)
		return 4 * 1024 * 1024;

	return -EINVAL;
}

static uint64_t
monotime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

int
get_rand(int a, int b)
{
#if notyet
#endif
	return -1;
}

static uint32_t
roundup_power_of_two(uint32_t val)
{
	val--;
	val |= val >> 1;
	val |= val >> 2;
	val |= val >> 4;
	val |= val >> 8;
	val |= val >> 16;
	val++;
	return val;
}

static int
pfs_write_paxos_sector(pfs_mount_t *mnt, int sector, void *buf)
{
	pfs_file_t *file = mnt->mnt_paxos_file;
	off_t offset = sector * mnt->mnt_sectsize;
	int rv;

	rv = pfs_file_pwrite(file, buf, mnt->mnt_sectsize, offset);
	if (rv < 0) {
		pfs_etrace("paxos writes from offset %lld failed, rv=%d\n",
		    (long long)offset, rv);
		if (rv == -ETIMEDOUT)
			rv = PFS_AIO_TIMEOUT;
	}
	return rv;
}

static int
pfs_read_paxos_sectors(pfs_mount_t *mnt, int start_sector, int nsector, void *buf)
{
	pfs_file_t *file = mnt->mnt_paxos_file;
	off_t offset = start_sector * mnt->mnt_sectsize;
	int rv;

	/* read IO doesn't have any time limited */
	rv = pfs_file_pread(file, buf, nsector * mnt->mnt_sectsize, offset);
	if (rv < 0) {
		pfs_etrace("paxos reads from offset %lld failed, rv=%d\n",
		    (long long)offset, rv);
	}
	return rv;
}

static int
write_leader(pfs_mount_t *mnt, struct pfs_leader_record *lr)
{
	size_t sector_size = mnt->mnt_sectsize;
	struct pfs_leader_record *lr_end;
	uint32_t checksum = 0;
	int rv;

	rv = pfs_mem_memalign((void **)&lr_end, sector_size, sector_size,
	    M_PAXOS_SECTOR);
	if (rv)
		return -rv;
	memset(lr_end, 0, sector_size);

	leader_record_out(lr, lr_end);

	/*
	 * N.B. must compute checksum after the data has been byte swapped.
	 */
	checksum = leader_checksum(lr_end);
	lr->checksum = checksum;
	lr_end->checksum = cpu_to_le32(checksum);

	rv = pfs_write_paxos_sector(mnt, 0, lr_end);
	pfs_mem_free(lr_end, M_PAXOS_SECTOR);
	return rv;
}

int
read_leader(pfs_mount_t *mnt, struct pfs_leader_record *lr, uint32_t *checksum)
{
	size_t sector_size = mnt->mnt_sectsize;
	struct pfs_leader_record *lr_end;
	int rv;

	rv = pfs_mem_memalign((void **)&lr_end, sector_size, sector_size,
	    M_PAXOS_SECTOR);
	if (rv)
		return -rv;
	memset(lr_end, 0, sector_size);

	/* 0 = leader record is first sector */
	rv = pfs_read_paxos_sectors(mnt, 0, 1, lr_end);
	/* N.B. checksum is computed while the data is in ondisk format. */
	if (checksum)
		*checksum = leader_checksum(lr_end);
	leader_record_in(lr_end, lr);
	pfs_mem_free(lr_end, M_PAXOS_SECTOR);
	return rv;
}

static int
verify_leader(pfs_mount_t *mnt, struct pfs_leader_record *lr, uint32_t checksum)
{
	struct pfs_leader_record leader_rr;
	int result;

	if (lr->magic == PFS_LEADER_CLEAR)
		return PFS_LEADER_EMAGIC;

	if (lr->magic != PFS_LEADER_MAGIC) {
		pfs_etrace("verify_leader wrong magic %x", lr->magic);
		result = PFS_LEADER_MAGIC;
		goto fail;
	}

	if ((lr->version & 0xFFFF0000) != PFS_LEADER_VERSION_PRIMARY) {
		pfs_etrace("verify_leader wrong version %x",
		    lr->version);
		result = PFS_LEADER_EVERSION;
		goto fail;
	}

	if (lr->sector_size != mnt->mnt_sectsize) {
		pfs_etrace("verify_leader wrong sector size %d %u",
		    lr->sector_size, mnt->mnt_sectsize);
		result = PFS_LEADER_ESECTORSIZE;
		goto fail;
	}

	if (lr->num_hosts < mnt->mnt_host_id) {
		pfs_etrace("verify_leader num_hosts too small %llu %llu",
		    (unsigned long long)lr->num_hosts,
		    (unsigned long long)mnt->mnt_host_id);
		result = PFS_LEADER_ENUMHOSTS;
		goto fail;
	}

	if (lr->checksum != checksum) {
		pfs_etrace("verify_leader wrong checksum %x %x",
		    lr->checksum, checksum);
		result = PFS_LEADER_ECHECKSUM;
		goto fail;
	}

	return PFS_OK;

 fail:
	return result;
}

static int
_leader_read_one(pfs_mount_t *mnt, struct pfs_leader_record *leader_ret)
{
	struct pfs_leader_record leader;
	uint32_t checksum = 0;
	int rv;

	memset(&leader, 0, sizeof(struct pfs_leader_record));
	rv = read_leader(mnt, &leader, &checksum);
	if (rv < 0)
		return rv;
	rv = verify_leader(mnt, &leader, checksum);

	/* copy what we read even if verify finds a problem */
	memcpy(leader_ret, &leader, sizeof(struct pfs_leader_record));
	return rv;
}

int
pfs_leader_read(pfs_mount_t *mnt, pfs_leader_record_t *leader_ret)
{
	int rv;

	/* _leader_read_num works fine for the single disk case, but
	   we can cut out a bunch of stuff when we know there's one disk */

	rv = _leader_read_one(mnt, leader_ret);

	return rv;
}

int
pfs_leader_write(pfs_mount_t *mnt, pfs_leader_record_t *nl)
{

	int rv = write_leader(mnt, nl);
	if (rv < 0) {
		pfs_etrace("write_leader failed：%d\n", rv);
	}

	pfs_dbgtrace("log txid (%lld, %lld] offset (%llu, %llu] %lld\n",
	    (long long)nl->tail_txid,
	    (long long)nl->head_txid,
	    (unsigned long long)nl->tail_offset,
	    (unsigned long long)nl->head_offset,
	    (long long)nl->head_lsn);

	return PFS_OK;
}

/*
 * The caller must make sure that both num_hosts and max_hosts
 * are not negative. A negative value will cause an implicit
 * conversion which results in an undefined behavior.
 */
int
pfs_leader_init(pfs_mount_t *mnt, int num_hosts, int max_hosts, int write_clear,
    size_t logsize)
{
	char *iobuf = NULL;
	struct pfs_leader_record leader;
	struct pfs_leader_record leader_end;
	uint32_t checksum = 0;
	int iobuf_len;
	int sector_size;
	int align_size;
	int num_disks = 1;
	int rv, d, fd = -1;

	if (!num_hosts)
		num_hosts = DEFAULT_MAX_HOSTS;
	if (!max_hosts)
		max_hosts = DEFAULT_MAX_HOSTS;

	if (max_hosts > DEFAULT_MAX_HOSTS)
		return -E2BIG;

	if (num_hosts > DEFAULT_MAX_HOSTS)
		return -EINVAL;

	if (num_hosts > max_hosts)
		return -EINVAL;

	sector_size = mnt->mnt_sectsize;
	align_size = direct_align(sector_size);
	if (align_size < 0)
		return align_size;

	if (sector_size * (2 + max_hosts) > align_size)
		return -E2BIG;

	iobuf_len = align_size;
	rv = pfs_mem_memalign((void **)&iobuf, getpagesize(), iobuf_len,
	    M_PAXOS_SECTOR);
	if (rv)
		return -rv;
	memset(iobuf, 0, iobuf_len);

	memset(&leader, 0, sizeof(leader));
	if (write_clear) {
		leader.magic = PFS_LEADER_CLEAR;
	} else {
		leader.magic = PFS_LEADER_MAGIC;
	}

	leader.version = PFS_LEADER_VERSION_PRIMARY | PFS_LEADER_VERSION_SECONDARY;
	leader.sector_size = sector_size;
	leader.num_hosts = num_hosts;
	leader.max_hosts = max_hosts;
	leader.tail_txid = 0;
	leader.head_txid = 0;	/* intial null tx range is (0, 0] */
	leader.head_lsn = 0;
	leader.log_size = logsize;
	leader.checksum = 0; /* set after leader_record_out */
	leader_record_out(&leader, &leader_end);

	/*
	 * N.B. must compute checksum after the data has been byte swapped.
	 */
	checksum = leader_checksum(&leader_end);
	leader.checksum = checksum;
	leader_end.checksum = cpu_to_le32(checksum);
	memcpy(iobuf, &leader_end, sizeof(struct pfs_leader_record));

	PFS_ASSERT(mnt->mnt_paxos_file == NULL);
	fd = pfs_file_open_impl(mnt, PAXOS_FILE_MONO, 0, &mnt->mnt_paxos_file,
	    INNER_FILE_BTIME);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = 0;
	for (num_disks = 1, d = 0; d < num_disks; d++) {
		rv |= pfs_file_pwrite(mnt->mnt_paxos_file, iobuf, iobuf_len, 0);
		if (rv < 0)
			goto out;
	}
	rv = 0;

out:
	if (fd >= 0) {
		fd = -1;
		pfs_file_close(mnt->mnt_paxos_file);
		mnt->mnt_paxos_file = NULL;
	}

	if (iobuf) {
		pfs_mem_free(iobuf, M_PAXOS_SECTOR);
		iobuf = NULL;
	}
	return (rv < 0) ? rv : 0;
}

int
pfs_leader_load(pfs_mount_t *mnt)
{
	struct pfs_leader_record lr;
	int error, fd;
	uint32_t checksum = 0;

	fd = pfs_file_open_impl(mnt, PAXOS_FILE_MONO, 0,
	    &mnt->mnt_paxos_file, INNER_FILE_BTIME);
	error = (fd < 0) ? fd : 0;
	if (error < 0)
		return error;

	error = read_leader(mnt, &lr, &checksum);
	if (error < 0)
		return error;
	error = verify_leader(mnt, &lr, checksum);
	if (error < 0)
		return error;
	mnt->mnt_num_hosts = lr.num_hosts;

	if (mnt->mnt_host_id > mnt->mnt_num_hosts)
		ERR_RETVAL(EINVAL);
	if ((mnt->mnt_flags & (PFS_TOOL|MNTFLG_PFSD)) != 0 && mnt->mnt_host_id == 0)
		mnt->mnt_host_id = mnt->mnt_num_hosts;
	PFS_ASSERT(mnt->mnt_host_id > 0);
	/* For pfsd, paxos_hostid_local_lock is moved up to SDK side */
	if (!pfs_ispfsd(mnt) && pfs_writable(mnt)) {
		fd = paxos_hostid_local_lock(mnt->mnt_lockspace_name,
		   mnt->mnt_host_id, __func__);
		if (fd < 0)
			return fd;
		mnt->mnt_hostid_fd = fd;
	}

	mnt->mnt_host_generation = 0;
	mnt->mnt_log.log_leader = lr;
	return PFS_OK;
}

void
pfs_leader_unload(pfs_mount_t *mnt)
{
	if (mnt->mnt_hostid_fd >= 0) {
		/* For pfsd, paxos_hostid_local_unlock is moved up to SDK side*/
		PFS_ASSERT(!pfs_ispfsd(mnt));
		paxos_hostid_local_unlock(mnt->mnt_hostid_fd);
		mnt->mnt_hostid_fd = -1;
	}
	if (mnt->mnt_paxos_file) {
		pfs_file_close(mnt->mnt_paxos_file);
		mnt->mnt_paxos_file = NULL;
	}
}

#define FLK_LEN	1024
/*
 * Host id is requried for disk paxos. If more than one instances
 * claim to the same host id, the result is unpredictable. We ensure
 * different instances use different host ids on one node and in this
 * way prevent havoc, since currently only one node is allowed to read
 * and write.
 */
int
paxos_hostid_local_lock(const char *pbdname, int hostid, const char* caller)
{
	char pathbuf[PFS_MAX_PATHLEN];
	struct flock flk;
	mode_t omask;
	ssize_t size;
	int err, fd;

	size = snprintf(pathbuf, sizeof(pathbuf),
	    "/var/run/pfs/%s-paxos-hostid", pbdname);
	if (size >= (ssize_t)sizeof(pathbuf))
		ERR_RETVAL(ENAMETOOLONG);

	omask = umask(0000);
	err = fd = open(pathbuf, O_CREAT | O_RDWR | O_CLOEXEC, 0666);
	(void)umask(omask);
	if (err < 0) {
		pfs_etrace("cant open file %s, err=%d, errno=%d\n",
		    pathbuf, err, errno);
		ERR_RETVAL(EACCES);
	}

	/*
	 * Writer with host N will try to lock FLK_LEN*[N, N+1) region
	 * of access file. If the writer is a mkfs/growfs which's hostid
	 * is 0, then both l_start and l_len are zero, the whole file will
	 * be locked according to fcntl(2).
	 */
	memset(&flk, 0, sizeof(flk));
	flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = hostid * FLK_LEN;
	flk.l_len = hostid > 0 ? FLK_LEN : 0;
	err = fcntl(fd, F_SETLK, &flk);
	if (err < 0) {
		pfs_etrace("cant lock file %s [%d, %d), err=%d, errno=%d\n",
		    pathbuf, flk.l_start, flk.l_start + flk.l_len, err,
		    errno);
		(void)close(fd);
		ERR_RETVAL(EACCES);
	}

	return fd;
}

void
paxos_hostid_local_unlock(int fd)
{
	/*
	 * locks are automatically released if fd is closed.
	 */
	if (fd < 0)
		return;
	(void)close(fd);
}
