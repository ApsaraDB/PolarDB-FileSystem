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
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "pfs_mount.h"

#include "pfsd_common.h"
#include "pfsd_sdk_file.h"

#define FLK_LEN	1024
#define MOUNT_PREPARE_TIMEOUT_MS (30 * 1000)

int
pfsd_paxos_hostid_local_lock(const char *pbdname, int hostid, const char *caller)
{
	char pathbuf[PFS_MAX_PATHLEN];
	struct flock flk;
	mode_t omask;
	ssize_t size;
	int err, fd;

	size = snprintf(pathbuf, sizeof(pathbuf),
	    "/var/run/pfs/%s-paxos-hostid", pbdname);
	if (size >= (ssize_t)sizeof(pathbuf)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	omask = umask(0000);
	err = fd = open(pathbuf, O_CREAT | O_RDWR | O_CLOEXEC, 0666);
	(void)umask(omask);
	if (err < 0) {
		PFSD_CLIENT_ELOG("cant open file %s, err=%d, errno=%d",
			pathbuf, err, errno);
		errno = EACCES;
		return -1;
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
		PFSD_CLIENT_ELOG("%s cant lock file %s [%ld, %ld), err=%d,"
		   " errno=%d", caller, pathbuf, flk.l_start,
		   flk.l_start + flk.l_len, err, errno);
		(void)close(fd);
		errno = EACCES;
		return -1;
	}

	return fd;
}

void
pfsd_paxos_hostid_local_unlock(int fd)
{
	if (fd >= 0)
		close(fd);
}

typedef struct {
	int meta_lock_fd;
	int hostid_lock_fd;
}mountargs_t;

void*
pfs_mount_prepare(const char *cluster, const char *pbdname, int host_id,
    int flags)
{
	int fd = -1;
	mountargs_t *result = NULL;
	if (!cluster || !pbdname) {
		PFSD_CLIENT_ELOG("invalid cluster(%p) or pbdname(%p)",
		    cluster, pbdname);
		errno = EINVAL;
		return NULL;
	}
	PFSD_CLIENT_LOG("begin prepare mount cluster(%s), PBD(%s), hostid(%d),"
	    "flags(0x%x)", cluster, pbdname, host_id, flags);

	if ((flags & MNTFLG_WR) == 0) {
		errno = 0;
		return NULL;
	}

	result = PFSD_MALLOC(mountargs_t);
	if (result == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	result->hostid_lock_fd = -1;
	result->meta_lock_fd = -1;

	if ((flags & MNTFLG_TOOL) == 0) {
		/*
		* Don't conflict with growfs.
		* growfs can run when DB is running, so it can't lock the whole
		* file like mkfs. growfs will lock the region after normal paxos
		* regions.
		*/
		int timeout_ms = MOUNT_PREPARE_TIMEOUT_MS;
		while (timeout_ms >= 0) {
			fd = pfsd_paxos_hostid_local_lock(pbdname,
			    DEFAULT_MAX_HOSTS + 1, __func__);
			if (fd >= 0)
				break;

			PFSD_CLIENT_ELOG("can't got locallock when prepare"
			    " mount PBD(%s), hostid(%d) %s", pbdname, host_id,
			    strerror(errno));
			if (errno != EACCES)
				goto err_handle;

			usleep(10 * 1000);
			timeout_ms -= 10;
		}

		if (fd < 0) {
			errno = ETIMEDOUT;
			goto err_handle;
		}

		result->meta_lock_fd = fd;
	}

	if ((flags & PFS_TOOL) != 0 && host_id == 0) {
		fd = pfsd_paxos_hostid_local_lock(pbdname, DEFAULT_MAX_HOSTS + 2,
		    __func__);
	} else {
		fd = pfsd_paxos_hostid_local_lock(pbdname, host_id, __func__);
	}

	if (fd < 0) {
		PFSD_CLIENT_ELOG("fail got locallock when prepare mount PBD(%s),"
		   " hostid(%d) %s", pbdname, host_id, strerror(errno));
		goto err_handle;
	}

	result->hostid_lock_fd = fd;
	PFSD_CLIENT_LOG("pfs_mount_prepare success for %s hostid %d", pbdname,
	    host_id);
	return result;

err_handle:
	pfsd_paxos_hostid_local_unlock(result->hostid_lock_fd);
	pfsd_paxos_hostid_local_unlock(result->meta_lock_fd);
	PFSD_FREE(result);
	if (errno == 0)
		errno = EINVAL;
	PFSD_CLIENT_ELOG("pfs_mount_prepare failed for %s hostid %d, err %s",
	    pbdname, host_id, strerror(errno));
	return NULL;
}

void
pfs_mount_atfork_child(void* handle)
{
	mountargs_t* result = (mountargs_t*)handle;
	if (result) {
		/**
		 * Here we leak a fd to avoid mkfs operation
		 */
		//pfsd_paxos_hostid_local_unlock(result->hostid_lock_fd);
		PFSD_FREE(result);
		result = NULL;
	}
}

void
pfs_mount_post(void *handle, int err)
{
	mountargs_t *result = (mountargs_t*)handle;

	if (result->meta_lock_fd >= 0) {
		pfsd_paxos_hostid_local_unlock(result->meta_lock_fd);
		result->meta_lock_fd = -1;
	}

	if (err < 0) {
		pfsd_paxos_hostid_local_unlock(result->hostid_lock_fd);
		PFSD_FREE(result);
	}
	PFSD_CLIENT_LOG("pfs_mount_post err : %d", err);
}

void*
pfs_remount_prepare(const char *cluster, const char *pbdname, int host_id,
    int flags)
{
	int fd = -1;
	mountargs_t *result = NULL;
	if (!pbdname || !cluster) {
		PFSD_CLIENT_ELOG("invalid cluster(%p) or pbdname(%p)",
		    cluster, pbdname);
		errno = EINVAL;
		return NULL;
	}
	if ((flags & MNTFLG_TOOL) != 0 || (flags & MNTFLG_WR) == 0 ) {
		PFSD_CLIENT_ELOG("invalid remount flags(%#x)", flags);
		errno = EINVAL;
		return NULL;
	}
	PFSD_CLIENT_LOG("remount cluster(%s), PBD(%s), hostid(%d),flags(%#x)",
	    cluster, pbdname, host_id, flags);
	result = PFSD_MALLOC(mountargs_t);
	if (result == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	result->hostid_lock_fd = -1;
	result->meta_lock_fd = -1;

	fd = pfsd_paxos_hostid_local_lock(pbdname, host_id, __func__);
	if (fd < 0) {
		goto err_handle;
	}
	result->hostid_lock_fd = fd;
	return result;
err_handle:
	pfsd_paxos_hostid_local_unlock(result->hostid_lock_fd);
	PFSD_FREE(result);
	return NULL;
}

void
pfs_remount_post(void *handle, int err)
{
	mountargs_t *result = (mountargs_t*)handle;
	if(err < 0) {
		PFSD_CLIENT_ELOG("remount failed %d", err);
		pfsd_paxos_hostid_local_unlock(result->hostid_lock_fd);
		PFSD_FREE(result);
	}
}

void
pfs_umount_prepare(const char *pbdname, void *handle)
{
	mountargs_t *result = (mountargs_t*)handle;
	if (result->meta_lock_fd >= 0) {
		pfsd_paxos_hostid_local_unlock(result->meta_lock_fd);
		result->meta_lock_fd = -1;
	}
	PFSD_CLIENT_LOG("pfs_umount_prepare. pbdname:%s", pbdname);
}

void
pfs_umount_post(const char *pbdname, void *handle)
{
	mountargs_t *result = (mountargs_t*)handle;
	assert (result->meta_lock_fd < 0);

	pfsd_paxos_hostid_local_unlock(result->hostid_lock_fd);
	PFSD_FREE(result);
	pfsd_file_cleanup();
	PFSD_CLIENT_LOG("pfs_umount_post. pbdname:%s", pbdname);
}

