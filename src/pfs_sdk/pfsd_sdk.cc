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
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include "pfsd_common.h"
#include "pfsd_proto.h"
#include "pfsd_shm.h"
#include "pfsd_sdk_file.h"
#include "pfsd_sdk.h"
#include "pfsd_sdk_mount.h"

#include "pfsd_chnl.h"
#include "pfsd_chnl_shm.h"

/* init once */
static pthread_mutex_t s_init_mtx = PTHREAD_MUTEX_INITIALIZER;
static int s_inited = 0;

/* connect id */
static int s_connid = -1;

/* about hostid */
static void *s_mount_local_info = NULL;

static char s_pbdname[PFS_MAX_NAMELEN];
static int s_mnt_flags = 0;
static int s_mnt_hostid = -1;
int s_mount_epoch = 0;

static int s_mode = PFSD_SDK_PROCESS;
static char s_svraddr[PFS_MAX_PATHLEN];
static int s_timeout_ms = 20 * 1000;
static int s_remount_timeout_ms = 2000 * 1000;

#define RESET_CONN() do { \
	s_connid = -1;\
	s_inited = 0;\
	s_pbdname[0] = 0;\
	s_mnt_flags = 0;\
	s_mount_epoch = 0;\
	s_mnt_hostid = -1;\
} while (0)

/* Don't check it for multi process.
 * After remount, s_mnt_flags will be modified.
 * But it's not shared.
 */
#define CHECK_WRITABLE() do { \
	if (s_mode == PFSD_SDK_THREADS && !pfsd_writable(s_mnt_flags)) { \
		errno = EROFS; \
		return -1; \
	} \
} while(0)

#define CHECK_MOUNT(pbdname) do { \
	if (strncmp(s_pbdname, pbdname, sizeof(s_pbdname)) != 0) { \
		PFSD_CLIENT_ELOG("No such device %s, exists %s", pbdname, s_pbdname);\
		errno = ENODEV; \
		return -1; \
	} \
} while(0)

void
pfsd_set_mode(int mode)
{
	if (mode == PFSD_SDK_THREADS || mode == PFSD_SDK_PROCESS)
		s_mode = mode;
	else
		PFSD_CLIENT_ELOG("Wrong mode %d, expect 0(threads), 1(processes)", mode);
}

void
pfsd_set_svr_addr(const char *svraddr, size_t len)
{
	if (len >= PFS_MAX_PATHLEN) {
		PFSD_CLIENT_ELOG("Too long path %s", svraddr);
		return;
	}

	strncpy(s_svraddr, svraddr, len);
}

void
pfsd_set_connect_timeout(int timeout_ms)
{
	if (timeout_ms <= 0)
		return;
	if (timeout_ms > 24 * 3600 * 1000)
		return;

	s_timeout_ms = timeout_ms;
}

static void
pfsd_mount_atfork_child_init()
{
	pfs_mount_atfork_child(s_mount_local_info);
}

/* when child process is ready */
void
pfsd_atfork_child_post()
{
	/* init rand seed for each process */

	struct timeval now;
	gettimeofday(&now, NULL);
	srand((unsigned)((now.tv_sec + now.tv_usec) ^ getpid()));

	pfsd_sdk_file_init();
	pfsd_mount_atfork_child_init();
}

int
pfsd_sdk_init(int mode, const char *svraddr, int timeout_ms,
    const char *cluster, const char *pbdname, int host_id, int flags)
{

	pfsd_chnl_shm_client_init(); /* ! forced link pfsd_chnl_shm.o in libpfsd.a */

	int conn_id;
	void *mp = NULL;

	if (cluster == NULL)
		cluster = "polarstore";

	pthread_mutex_lock(&s_init_mtx);
	if (s_inited == 1) {
		PFSD_CLIENT_LOG("sdk may be init by other threads");
		pthread_mutex_unlock(&s_init_mtx);
		return 0;
	}

	if (flags & MNTFLG_TOOL) {
		char logfile[1024] = "";
		(void)snprintf(logfile, sizeof(logfile), "/var/log/pfs-%s.log", pbdname);
		int fd = open(logfile, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0666);
		if (fd < 0) {
			fprintf(stderr, "cant open logfile %s\n", logfile);
		} else  {
			if (dup2(fd, STDERR_FILENO) < 0) {
				fprintf(stderr, "cant dup fd %d to stderr\n", fd);
				close(fd);
				fd = -1;
			}
			chmod(logfile, 0666);
			close(fd);
		}
	}

	s_pbdname[0] = '\0';
	s_mnt_flags = 0;
	pfsd_sdk_file_init();

	if (s_svraddr[0] == '\0') {
		strncpy(s_svraddr, PFSD_USER_PID_DIR, PFS_MAX_PATHLEN);
	}

	srand(time(NULL));

	/* local hostid lock */
	errno = 0;
	mp = pfs_mount_prepare(cluster, pbdname, host_id, flags);
	if (mp == NULL && errno != 0) {
		PFSD_CLIENT_ELOG("pfs_mount_prepare failed, maybe hostid %d used, err %s", host_id, strerror(errno));
		goto failed;
	}

	conn_id = pfsd_chnl_connect(svraddr, cluster, timeout_ms, pbdname, host_id, flags);
	PFSD_CLIENT_LOG("pfsd_chnl_connect %s", conn_id > 0 ? "success" : "failed");
	if (conn_id <= 0)
		goto failed;

	strncpy(s_pbdname, pbdname, sizeof(s_pbdname));
	s_mnt_flags = flags;
	s_mnt_hostid = host_id;

	s_connid = conn_id;
	s_mount_local_info = mp;

	if (mode == PFSD_SDK_PROCESS) {
		static bool registered_at_fork = false;
		if (!registered_at_fork) {
			pthread_atfork(NULL, NULL, pfsd_atfork_child_post);
			registered_at_fork = true;
		}
	}

	if (mp)
		pfs_mount_post(mp, 0);

	s_inited = 1;
	pthread_mutex_unlock(&s_init_mtx);
	return 0;

failed:
	if (mp)
		pfs_mount_post(mp, -1);

	s_mount_local_info = NULL;
	RESET_CONN();

	pthread_mutex_unlock(&s_init_mtx);
	return -1;
}

#define CHECK_STALE(rsp) do {\
	if (rsp->error == ESTALE) { \
		PFSD_CLIENT_LOG("Stale request, rsp type %d!!!", rsp->type); \
		rsp->error = 0; \
		pfsd_chnl_update_meta(s_connid, req->mntid); \
		pfsd_chnl_buffer_free(s_connid, req, rsp, NULL, pfsd_tolong(ch)); \
		goto retry;\
	} \
} while(0)\

int
pfsd_mount(const char *cluster, const char *pbdname, int hostid, int flags)
{
	return pfsd_sdk_init(s_mode, s_svraddr, s_timeout_ms, cluster, pbdname, hostid, flags);
}

int
pfsd_umount_force(const char *pbdname)
{
	PFSD_CLIENT_LOG("pbdname %s", pbdname);
	CHECK_MOUNT(pbdname);

	if (s_mount_local_info)
		pfs_umount_prepare(pbdname, s_mount_local_info);

	int err = pfsd_chnl_close(s_connid, true);
	if (err == 0) {
		RESET_CONN();

		if (s_mount_local_info) {
			pfs_umount_post(pbdname, s_mount_local_info);
			s_mount_local_info = NULL;
		}
		PFSD_CLIENT_LOG("umount success for %s", pbdname);
	} else {
		PFSD_CLIENT_ELOG("umount failed for %s", pbdname);
	}

	return err;
}

int
pfsd_umount(const char *pbdname)
{
	PFSD_CLIENT_LOG("pbdname %s", pbdname);
	CHECK_MOUNT(pbdname);

	if (s_mount_local_info)
		pfs_umount_prepare(pbdname, s_mount_local_info);

	int err = pfsd_chnl_close(s_connid, false);
	if (err == 0) {
		RESET_CONN();

		if (s_mount_local_info) {
			pfs_umount_post(pbdname, s_mount_local_info);
			s_mount_local_info = NULL;
		}
		PFSD_CLIENT_LOG("umount success for %s", pbdname);
	} else {
		PFSD_CLIENT_ELOG("umount failed for %s", pbdname);
	}

	return err;
}

int
pfsd_remount(const char *cluster, const char *pbdname, int hostid, int flags)
{
	void *mp;
	int res;

	CHECK_MOUNT(pbdname);

	if (hostid != s_mnt_hostid) {
		PFSD_CLIENT_ELOG("pfs_remount with diff hostid %d, expect %d", hostid, s_mnt_hostid);
		errno = EINVAL;
		return -1;
	}

	if (s_mnt_flags & MNTFLG_WR) {
		PFSD_CLIENT_ELOG("pfs_remount no need, already rw mount: %#x", s_mnt_flags);
		errno = EINVAL;
		return -1;
	}

	if (cluster == NULL)
		cluster = "polarstore";

	errno = 0;
	mp = pfs_remount_prepare(cluster, pbdname, hostid, flags);
	if (mp == NULL && errno != 0) {
		PFSD_CLIENT_ELOG("pfs_remount_prepare failed, maybe hostid %d used, err %s", hostid, strerror(errno));
		goto failed;
	}
	/* reconnect, use same connid */
	res = pfsd_chnl_reconnect(s_connid, cluster, s_remount_timeout_ms, pbdname, hostid, flags);
	if (res == 0) {
		s_mnt_flags = flags;
		free(s_mount_local_info);
		s_mount_local_info = mp;
	} else {
		goto failed;
	}

	if (mp)
		pfs_remount_post(mp, 0);

	return 0;

failed:
	if (mp)
		pfs_remount_post(mp, -1);

	return -1;
}

int
pfsd_abort_request(pid_t pid)
{
	if (s_connid <= 0) {
		PFSD_CLIENT_ELOG("SDK not inited successful\n");
		errno = ENODEV;
		return -1;
	}
	return pfsd_chnl_abort(s_connid, pid);
}

int
pfsd_mount_growfs(const char *pbdname)
{
	CHECK_MOUNT(pbdname);

	int err = 0;
	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, 0, (void**)&req, 0, (void**)&rsp,
	    NULL, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return -1;
	}

	PFSD_CLIENT_LOG("growfs for %s", pbdname);

	/* fill request */
	req->type = PFSD_REQUEST_GROWFS;
	strncpy(req->g_req.g_pbd, pbdname, PFS_MAX_PBDLEN);

	pfsd_chnl_send_recv(s_connid, req, 0, rsp, 0, NULL, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	if (rsp->error != 0) {
		errno = rsp->error;
		err = -1;
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, NULL, pfsd_tolong(ch));
	return err;
}

int
pfsd_rename(const char *oldpbdpath, const char *newpbdpath)
{
	if (oldpbdpath == NULL || newpbdpath == NULL) {
		errno = EINVAL;
		PFSD_CLIENT_ELOG("NULL args");
		return -1;
	}

	char oldpath[PFS_MAX_PATHLEN], newpath[PFS_MAX_PATHLEN];

	oldpbdpath = pfsd_name_init(oldpbdpath, oldpath, sizeof oldpath);
	if (oldpbdpath == NULL) {
		PFSD_CLIENT_ELOG("wrong oldpbdpath %s", oldpbdpath);
		return -1;
	}

	newpbdpath = pfsd_name_init(newpbdpath, newpath, sizeof newpath);
	if (newpbdpath == NULL) {
		PFSD_CLIENT_ELOG("wrong newpbdpath %s", oldpbdpath);
		return -1;
	}

	int err = 0;

	char oldpbd[PFS_MAX_NAMELEN];
	char newpbd[PFS_MAX_NAMELEN];
	if (pfsd_sdk_pbdname(oldpbdpath, oldpbd) != 0 ||
		pfsd_sdk_pbdname(newpbdpath, newpbd) != 0) {
		PFSD_CLIENT_ELOG("wrong pbdpath:  old %s, new %s", oldpbdpath, newpbdpath);
		errno = EINVAL;
		return -1;
	}

	/* Don't support rename between different PBD */
	if (strncmp(oldpbd, newpbd, PFS_MAX_NAMELEN) != 0) {
		PFSD_CLIENT_ELOG("Rename must in same pbd: [%s] != [%s]", oldpbd, newpbd);
		errno = EXDEV;
		return -1;
	}

	CHECK_MOUNT(newpbd);
	CHECK_WRITABLE();

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *buf = NULL;
	pfsd_response_t *rsp = NULL;
	int64_t iolen = 2 * PFS_MAX_PATHLEN;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, iolen, (void**)&req, 0, (void**)&rsp,
	    (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_RENAME;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, oldpath, PFS_MAX_PATHLEN);
	strncpy((char*)buf+PFS_MAX_PATHLEN, newpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, iolen,
	    rsp, 0, buf, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	if (rsp->error != 0) {
		PFSD_CLIENT_ELOG("rename %s -> %s error: %d", oldpbdpath, newpbdpath, rsp->error);
		errno = rsp->error;
		err = -1;
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));
	return err;
}

int
pfsd_open(const char *pbdpath, int flags, mode_t mode)
{
	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL)
		return -1;

	char pbdname[PFS_MAX_NAMELEN];
	if (pfsd_sdk_pbdname(pbdpath, pbdname) != 0) {
		errno = EINVAL;
		return -1;
	}

	CHECK_MOUNT(pbdname);

	if (flags & (O_CREAT | O_TRUNC)) {
		CHECK_WRITABLE();
	}

	pfsd_file_t *file = pfsd_alloc_file();
	if (file == NULL) {
		errno = ENOMEM;
		return -1;
	}

	int fd = pfsd_alloc_fd(file);
	if (fd == -1) {
		errno = EMFILE;
		pfsd_free_file(file);
		return -1;
	}
	file->f_flags = flags;

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	pfsd_response_t *rsp = NULL;
	unsigned char *buf = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		pfsd_close_file(file);
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_OPEN;
	req->o_req.o_flags = flags;
	req->o_req.o_mode = mode;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN, rsp, 0, buf,
	    pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	file->f_inode = rsp->o_rsp.o_ino;
	file->f_common_pl = rsp->common_pl_rsp;
	if (file->f_inode == -1) {
		pfsd_close_file(file);
		errno = rsp->error;
		fd = -1;
		if (errno != ENOENT)
			PFSD_CLIENT_ELOG("open %s failed %s", pbdpath,
			    strerror(errno));
	} else {
		file->f_offset = rsp->o_rsp.o_off;

		if (flags & O_CREAT)
			PFSD_CLIENT_LOG("open %s with inode %ld, fd %d",
			    pbdpath, file->f_inode, fd);
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));

	if (fd < 0)
		return -1;

	return PFSD_FD_MAKE(fd);
}

int
pfsd_creat(const char *pbdpath, mode_t mode)
{
	return pfsd_open(pbdpath, O_CREAT | O_TRUNC | O_WRONLY, mode);
}

#define PFSD_SDK_GET_FILE(fd) do {\
	if (!PFSD_FD_ISVALID(fd)) {\
		errno = EBADF; \
		return -1; \
	}\
	fd = PFSD_FD_RAW(fd); \
	file = pfsd_get_file(fd, false); \
	if (file == NULL) { \
		PFSD_CLIENT_ELOG("bad fd %d", fd);\
		errno = EBADF; \
		return -1; \
	} \
} while(0)

#define PFSD_SDK_GET_FILE_WR(fd) do {\
	if (!PFSD_FD_ISVALID(fd)) {\
		errno = EBADF; \
		return -1; \
	}\
	fd = PFSD_FD_RAW(fd); \
	file = pfsd_get_file(fd, true); \
	if (file == NULL) { \
		PFSD_CLIENT_ELOG("bad fd %d", fd);\
		errno = EBADF; \
		return -1; \
	} \
} while(0)


#define OFFSET_FILE_POS     (-1)    /* offset is current file position */
#define OFFSET_FILE_SIZE    (-2)    /* offset is file size */

ssize_t
pfsd_read(int fd, void *buf, size_t len)
{
	return pfsd_pread(fd, buf, len, OFFSET_FILE_POS);
}

ssize_t
pfsd_pread(int fd, void *buf, size_t len, off_t off)
{
	if (buf == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (len > PFSD_MAX_IOSIZE) {
		/* may shorten read */
		PFSD_CLIENT_LOG("pread len %lu is too big for fd %d, cast to 4MB.", len, fd);
		len = PFSD_MAX_IOSIZE;
	}

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *rbuf = NULL;
	ssize_t ss = -1;
	pfsd_response_t *rsp = NULL;

	pfsd_file_t *file = NULL;

	PFSD_SDK_GET_FILE(fd);

	off_t off2 = off;
	if (off == OFFSET_FILE_POS)
		off2 = file->f_offset;

	if (off2 < 0) {
		errno = EINVAL;
		pfsd_put_file(file);
		return -1;
	}

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, 0, (void**)&req, len,
	    (void**)&rsp, (void**)&rbuf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		pfsd_put_file(file);
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_READ;
	req->r_req.r_ino = file->f_inode;
	req->r_req.r_len = len;
	req->r_req.r_off = off2;
	req->common_pl_req = file->f_common_pl;

	pfsd_chnl_send_recv(s_connid, req, 0, rsp, len, buf, pfsd_tolong(ch),
	    0);
	CHECK_STALE(rsp);

	if (rsp->r_rsp.r_len > 0)
		memcpy(buf, rbuf, rsp->r_rsp.r_len);

	ss = rsp->r_rsp.r_len;
	if (ss < 0) {
		errno = rsp->error;
		PFSD_CLIENT_ELOG("pread fd %d ino %ld error: %s", fd,
		    file->f_inode, strerror(errno));
	} else {
		if (off == -1)
			__sync_add_and_fetch(&file->f_offset, ss);
	}

	pfsd_put_file(file);
	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));
	return ss;
}

ssize_t
pfsd_write(int fd, const void *buf, size_t len)
{
	return pfsd_pwrite(fd, buf, len, OFFSET_FILE_POS);
}

ssize_t
pfsd_pwrite(int fd, const void *buf, size_t len, off_t off)
{
	if (buf == NULL) {
		errno = EINVAL;
		return -1;
	}

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *wbuf = NULL;
	pfsd_response_t *rsp = NULL;
	ssize_t ss = -1;

	pfsd_file_t *file = NULL;

	CHECK_WRITABLE();
	PFSD_SDK_GET_FILE(fd);

	if (len == 0) {
		pfsd_put_file(file);
		return 0;
	}

	if (len > PFSD_MAX_IOSIZE) {
		PFSD_CLIENT_ELOG("pwrite len %lu is too big for fd %d.", len, fd);
		errno = EFBIG;
		pfsd_put_file(file);
		return -1;
	}

	off_t off2 = off;
	if (file->f_flags & O_APPEND)
		off2 = OFFSET_FILE_SIZE;
	else if (off == OFFSET_FILE_POS)
		off2 = file->f_offset;

	if (off2 < 0 && off2 != OFFSET_FILE_SIZE) {
		PFSD_CLIENT_ELOG("pwrite wrong off2 %lu for fd %d.", off2, fd);
		pfsd_put_file(file);
		errno = EINVAL;
		return -1;
	}

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, len, (void**)&req, 0,
	    (void**)&rsp, (void**)&wbuf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		pfsd_put_file(file);
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_WRITE;
	req->w_req.w_ino = file->f_inode;
	req->w_req.w_len = len;
	req->w_req.w_off = off2;
	req->w_req.w_flags = file->f_flags;
	req->common_pl_req = file->f_common_pl;

	memcpy(wbuf, buf, len);

	pfsd_chnl_send_recv(s_connid, req, len, rsp, 0, wbuf, pfsd_tolong(ch),
	    0);

	if ((file->f_flags & O_APPEND) == 0)
		CHECK_STALE(rsp);

	ss = rsp->w_rsp.w_len;
	if (ss < 0) {
		errno = rsp->error;
		PFSD_CLIENT_ELOG("pwrite fd %d ino %ld error: %s", fd,
		    file->f_inode, strerror(errno));
	} else {
		if (ss >= 0 && off == -1) {
			__sync_add_and_fetch(&file->f_offset, ss);
		}
		if ((file->f_flags & O_APPEND) != 0 && OFFSET_FILE_POS == off)
			file->f_offset = rsp->w_rsp.w_file_size;
	}

	pfsd_put_file(file);
	pfsd_chnl_buffer_free(s_connid, req, rsp, wbuf, pfsd_tolong(ch));
	return ss;
}

int
pfsd_posix_fallocate(int fd, off_t offset, off_t len)
{
	return pfsd_fallocate(fd, 0, offset, len);
}

#define FALLOC_PFSFL_FIXED_OFFSET   0x0100  /* lower bits defined in falloc.h */

int
pfsd_fallocate(int fd, int mode, off_t offset, off_t len)
{
	if (fd < 0 || offset < 0 || len <= 0) {
		errno = (fd < 0) ? EBADF : EINVAL;
		return -1;
	}

	CHECK_WRITABLE();

	pfsd_file_t *file = NULL;
	PFSD_SDK_GET_FILE(fd);

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	pfsd_response_t *rsp = NULL;
	int rv = -1;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, 0, (void**)&req, 0, (void**)&rsp,
	    NULL, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		pfsd_put_file(file);
		return -1;
	}

	PFSD_CLIENT_LOG("fallocate ino %ld off %ld len %ld", file->f_inode, offset, len);
	/* fill request */
	req->type = PFSD_REQUEST_FALLOCATE;
	req->fa_req.f_ino = file->f_inode;
	req->fa_req.f_len = len;
	req->fa_req.f_off = offset;
	req->fa_req.f_mode = mode;
	req->common_pl_req = file->f_common_pl;

	pfsd_chnl_send_recv(s_connid, req, 0,
	    rsp, 0, NULL, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	rv = rsp->fa_rsp.f_res;
	if (rv != 0) {
		errno = rsp->error;
		PFSD_CLIENT_ELOG("fallocate ino %ld error: %s", file->f_inode, strerror(errno));
	}

	pfsd_put_file(file);
	pfsd_chnl_buffer_free(s_connid, req, rsp, NULL, pfsd_tolong(ch));
	return rv;
}

int
pfsd_truncate(const char *pbdpath, off_t len)
{
	if (!pbdpath || len < 0) {
		errno = EINVAL;
		return -1;
	}

	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL)
		return -1;

	char pbdname[PFS_MAX_NAMELEN];
	if (pfsd_sdk_pbdname(pbdpath, pbdname) != 0) {
		errno = EINVAL;
		return -1;
	}

	CHECK_MOUNT(pbdname);
	CHECK_WRITABLE();

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *buf = NULL;
	int rv = -1;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return -1;
	}

	PFSD_CLIENT_LOG("truncate %s len %ld", pbdpath, len);

	/* fill request */
	req->type = PFSD_REQUEST_TRUNCATE;
	req->t_req.t_len = len;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN, rsp, 0, buf,
	    pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	rv = rsp->t_rsp.t_res;
	if (rv != 0) {
		errno = rsp->error;
		PFSD_CLIENT_ELOG("truncate %s len %ld error: %s", pbdpath, len, strerror(errno));
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));
	return rv;
}

int
pfsd_ftruncate(int fd, off_t len)
{
	if (fd < 0 || len < 0) {
		errno = (fd < 0) ? EBADF : EINVAL;
		return -1;
	}

	CHECK_WRITABLE();

	pfsd_file_t *file = NULL;
	PFSD_SDK_GET_FILE(fd);

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	int rv = -1;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, 0, (void**)&req, 0,
	    (void**)&rsp, NULL, (long*)(&ch)) != 0) {
		pfsd_put_file(file);
		errno = ENOMEM;
		return -1;
	}

	PFSD_CLIENT_LOG("ftruncate ino %ld, len %lu", file->f_inode, len);

	/* fill request */
	req->type = PFSD_REQUEST_FTRUNCATE;
	req->ft_req.f_ino = file->f_inode;
	req->ft_req.f_len = len;
	req->common_pl_req = file->f_common_pl;

	pfsd_chnl_send_recv(s_connid, req, 0, rsp, 0, NULL, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	rv = rsp->ft_rsp.f_res;
	if (rv != 0) {
		errno = rsp->error;
		PFSD_CLIENT_ELOG("ftruncate ino %ld, len %lu: %s", file->f_inode, len, strerror(errno));
	}

	pfsd_put_file(file);
	pfsd_chnl_buffer_free(s_connid, req, rsp, NULL, pfsd_tolong(ch));
	return rv;
}

int
pfsd_unlink(const char *pbdpath)
{
	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL)
		return -1;

	char pbdname[PFS_MAX_NAMELEN];
	if (pfsd_sdk_pbdname(pbdpath, pbdname) != 0) {
		errno = EINVAL;
		return -1;
	}

	CHECK_MOUNT(pbdname);
	/* check writable */
	CHECK_WRITABLE();

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *buf = NULL;
	int rv = -1;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return -1;
	}

	PFSD_CLIENT_LOG("unlink %s", pbdpath);
	/* fill request */
	req->type = PFSD_REQUEST_UNLINK;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN,
	    rsp, 0, buf, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	rv = rsp->un_rsp.u_res;
	if (rv != 0) {
		errno = rsp->error;
		if (errno != ENOENT)
			PFSD_CLIENT_ELOG("unlink %s: %s", pbdpath, strerror(errno));
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));
	return rv;
}

int
pfsd_stat(const char *pbdpath, struct stat *st)
{
	if (!pbdpath || !st) {
		errno = EINVAL;
		return -1;
	}

	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL)
		return -1;

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *buf = NULL;
	int rv = -1;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_STAT;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN,
	    rsp, 0, buf, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	rv = rsp->s_rsp.s_res;
	if (rv != 0) {
		errno = rsp->error;
		if (errno != ENOENT)
			PFSD_CLIENT_ELOG("stat %s: %s", pbdpath, strerror(errno));
	} else {
		memcpy(st, &rsp->s_rsp.s_st, sizeof(*st));
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));
	return rv;
}

int
pfsd_fstat(int fd, struct stat *st)
{
	if (fd < 0 || !st) {
		errno = (fd < 0) ? EBADF : EINVAL;
		return -1;
	}

	pfsd_file_t *file = NULL;
	PFSD_SDK_GET_FILE(fd);

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	int rv = -1;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, 0, (void**)&req, 0,
	    (void**)&rsp, NULL, (long*)(&ch)) != 0) {
		pfsd_put_file(file);
		errno = ENOMEM;
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_FSTAT;
	req->f_req.f_ino = file->f_inode;
	req->common_pl_req = file->f_common_pl;

	pfsd_chnl_send_recv(s_connid, req, 0, rsp, 0, NULL, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	rv = rsp->f_rsp.f_res;
	if (rv != 0) {
		errno = rsp->error;
		PFSD_CLIENT_ELOG("fstat %ld error: %s", file->f_inode, strerror(errno));
	} else {
		memcpy(st, &rsp->f_rsp.f_st, sizeof(*st));
	}

	pfsd_put_file(file);
	pfsd_chnl_buffer_free(s_connid, req, rsp, NULL, pfsd_tolong(ch));
	return rv;
}

static off_t
local_file_lseek(pfsd_file_t *file, off_t offset, int whence)
{
	off_t old_offset, new_offset;

	switch (whence) {
		case SEEK_SET:
			old_offset = file->f_offset;
			new_offset = offset;
			goto check_file_offset;

		case SEEK_CUR:
			old_offset = file->f_offset;
			new_offset = old_offset + offset;
			break;

		case SEEK_END:
			errno = 0;
			return off_t(-1);

		default:
			errno = EINVAL;
			return off_t(-1);
	}

	if (offset > 0 && new_offset < old_offset) {
		errno = EOVERFLOW;
		return off_t(-1);
	}

	/*
	 * when offset < 0 with SEEK_END, f_offset is less than filesize,
	 * new_offset maybe bigger than f_offset. So we compare new_offset and
	 * file size.
	 */
	if (offset < 0 && new_offset > old_offset) {
		errno = EOVERFLOW;
		return off_t(-1);
	}

check_file_offset:
	if (new_offset < 0) {
		errno = EINVAL;
		return off_t(-1);
	} else {
		file->f_offset = new_offset;
		return file->f_offset;
	}
}

off_t
pfsd_lseek(int fd, off_t offset, int whence)
{
	if (fd < 0) {
		errno = EINVAL;
		return -1;
	}

	pfsd_file_t *file = NULL;
	PFSD_SDK_GET_FILE_WR(fd);

	/* for ask pfsd if SEEK_END */
	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	pfsd_response_t *rsp = NULL;

	off_t rv = -1;
	rv = local_file_lseek(file, offset, whence);
	if (rv >= 0)
		goto finish;
	if (rv == off_t(-1) && errno != 0)
		goto finish;

retry:
	/* ask pfsd to seek end */
	if (pfsd_chnl_buffer_alloc(s_connid, 0, (void**)&req, 0,
	    (void**)&rsp, NULL, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		pfsd_put_file(file);
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_LSEEK;
	req->l_req.l_ino = file->f_inode;
	req->l_req.l_offset = offset;
	req->l_req.l_whence = whence;
	req->common_pl_req = file->f_common_pl;
	assert (whence == SEEK_END); /* must be SEED_END */

	pfsd_chnl_send_recv(s_connid, req, 0, rsp, 0, NULL, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	if (rsp->l_rsp.l_offset < 0) {
		errno = rsp->error;
		rv = off_t(-1);
		PFSD_CLIENT_ELOG("lseek %ld off %ld error: %s", file->f_inode,
		    offset, strerror(errno));
	} else {
		file->f_offset = rsp->l_rsp.l_offset;
		rv = rsp->l_rsp.l_offset;
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, NULL, pfsd_tolong(ch));

finish:
	pfsd_put_file(file);
	return rv;
}

int
pfsd_close(int fd)
{
	pfsd_file_t *file = NULL;
	int err = -EAGAIN;
	bool fdok = PFSD_FD_ISVALID(fd);
	if (!fdok)
		err = -EBADF;

	fd = PFSD_FD_RAW(fd);

	while (err == -EAGAIN){
		file = pfsd_get_file(fd, true);
		if (file == NULL) {
			err = -EBADF;
			break;
		}

		err = pfsd_close_file(file);
		if (err != 0) {
			PFSD_CLIENT_ELOG("close fd %d failed, err:%d", fd, err);
			pfsd_put_file(file);
		}
	}
	if (err < 0) {
		errno = -err;
		return -1;
	}
	return 0;
}

int
pfsd_chdir(const char *pbdpath)
{
	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL)
		return -1;

	assert (pbdpath == abspath);

	if (!pfsd_chdir_begin())
		return -1;

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *buf = NULL;
	int rv = -1;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		pfsd_chdir_end();
		errno = ENOMEM;
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_CHDIR;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN,
	    rsp, 0, buf, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	rv = rsp->cd_rsp.c_res;
	if (rv != 0) {
		errno = rsp->error;
		PFSD_CLIENT_ELOG("chdir %s error: %s", pbdpath, strerror(errno));
	} else {
		int err = pfsd_normalize_path(abspath);
		if (err == 0) {
			err = pfsd_dir_xsetwd(abspath, strlen(abspath));
		}
		if (err != 0) {
			errno = err;
			rv = -1;
		}
	}

	pfsd_chdir_end();
	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));
	return rv;
}

char *
pfsd_getwd(char *buf)
{
	return pfsd_getcwd(buf, PFS_MAX_PATHLEN);
}

char *
pfsd_getcwd(char *buf, size_t size)
{
	int err = -EAGAIN;

	if (!buf)
		err = -EINVAL;

	while (err == -EAGAIN) {
		err = pfsd_dir_xgetwd(buf, size);
	}

	if (err < 0) {
		errno = -err;
		PFSD_CLIENT_ELOG("getcwd error: %s", strerror(errno));
		return NULL;
	}

	return buf;
}

int
pfsd_mkdir(const char *pbdpath, mode_t mode)
{
	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL)
		return -1;

	char pbdname[PFS_MAX_NAMELEN];
	if (pfsd_sdk_pbdname(pbdpath, pbdname) != 0) {
		errno = EINVAL;
		return -1;
	}

	CHECK_MOUNT(pbdname);
	CHECK_WRITABLE();

	int err = 0;
	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *buf = NULL;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return -1;
	}

	PFSD_CLIENT_LOG("mkdir %s", pbdpath);
	/* fill request */
	req->type = PFSD_REQUEST_MKDIR;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN,
	    rsp, 0, buf, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	if (rsp->mk_rsp.m_res != 0) {
		err = -1;
		errno = rsp->error;
		PFSD_CLIENT_ELOG("mkdir %s error: %s", pbdpath, strerror(errno));
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));
	return err;
}

int
pfsd_rmdir(const char *pbdpath)
{
	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL)
		return -1;

	char pbdname[PFS_MAX_NAMELEN];
	if (pfsd_sdk_pbdname(pbdpath, pbdname) != 0) {
		errno = EINVAL;
		return -1;
	}

	CHECK_MOUNT(pbdname);
	CHECK_WRITABLE();

	int err = 0;
	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *buf = NULL;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return -1;
	}

	PFSD_CLIENT_LOG("rmdir %s", pbdpath);
	/* fill request */
	req->type = PFSD_REQUEST_RMDIR;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN,
	    rsp, 0, buf, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	if (rsp->rm_rsp.r_res != 0) {
		err = -1;
		errno = rsp->error;
		PFSD_CLIENT_ELOG("rmdir %s error: %s", pbdpath, strerror(errno));
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));
	return err;
}

DIR *
pfsd_opendir(const char *pbdpath)
{
	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL)
		return NULL;

	char pbdname[PFS_MAX_NAMELEN];
	if (pfsd_sdk_pbdname(pbdpath, pbdname) != 0) {
		errno = EINVAL;
		return NULL;
	}

	if (strncmp(s_pbdname, pbdname, sizeof(s_pbdname)) != 0) {
		PFSD_CLIENT_ELOG("No such device %s, exists %s", pbdname,
		    s_pbdname);
		errno = ENODEV;
		return NULL;
	}

	DIR *dir = NULL;

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	unsigned char *buf = NULL;
	pfsd_response_t *rsp = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return NULL;
	}

	/* fill request */
	req->type = PFSD_REQUEST_OPENDIR;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN,
	    rsp, 0, buf, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	if (rsp->od_rsp.o_res != 0) {
		dir = NULL;
		errno = rsp->error;
		PFSD_CLIENT_ELOG("opendir %s error: %s", pbdpath, strerror(errno));
	} else {
		dir = PFSD_MALLOC(DIR);
		if (dir == NULL) {
			errno = ENOMEM;
		} else {
			memset(dir, 0, sizeof(*dir));
			dir->d_ino = rsp->od_rsp.o_dino;
			dir->d_next_ino = rsp->od_rsp.o_first_ino;
		}
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));

	if (dir == NULL)
		return NULL;

	return PFSD_DIR_MAKE(dir);
}

struct dirent *
pfsd_readdir(DIR *dir)
{
	if (!PFSD_DIR_ISVALID(dir)) {
		errno = EINVAL;
		return NULL;
	}

	DIR *raw_dir = PFSD_DIR_RAW(dir);
	if (!raw_dir) {
		errno = EINVAL;
		return NULL;
	}

	struct dirent *ent = &raw_dir->d_sysde;
	struct dirent *sysent = NULL;
	int err = pfsd_readdir_r(dir, ent, &sysent);
	if (err != 0) {
		sysent = NULL;
	}

	return sysent;
}

int
pfsd_readdir_r(DIR *dir, struct dirent *entry, struct dirent **result)
{
	if (!PFSD_DIR_ISVALID(dir)) {
		errno = EINVAL;
		return -1;
	}

	dir = PFSD_DIR_RAW(dir);
	if (!dir || !entry || !result) {
		errno = EINVAL;
		return -1;
	}

	/* Try read from dirent buffer */
	if (dir->d_data_offset < dir->d_data_size) {
		*result = entry;
		memcpy(entry, &dir->d_data[dir->d_data_offset], sizeof(*entry));

		dir->d_data_offset += sizeof(struct dirent);
		assert (dir->d_data_offset <= dir->d_data_size);

		return 0;
	} else {
		dir->d_data_offset = 0;
		dir->d_data_size = 0;
	}

	if (dir->d_next_ino == 0) {
		*result = NULL;
		return 0;
	}

	int err = 0;

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	pfsd_response_t *rsp = NULL;
	unsigned char *dbuf = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, 0, (void**)&req,
	    PFSD_DIRENT_BUFFER_SIZE, (void**)&rsp, (void**)&dbuf, (long*)(&ch))
	    != 0) {
		errno = ENOMEM;
		return -1;
	}
	/* fill request */
	req->type = PFSD_REQUEST_READDIR;
	req->rd_req.r_dino = dir->d_ino;
	req->rd_req.r_ino = dir->d_next_ino;
	req->rd_req.r_offset = dir->d_next_offset;

	pfsd_chnl_send_recv(s_connid, req, 0,
	    rsp, PFSD_DIRENT_BUFFER_SIZE, dbuf, pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	if (rsp->rd_rsp.r_res != 0) {
		*result = NULL;

		/* Dir EOF is not error */
		if (rsp->rd_rsp.r_res != PFSD_DIR_END) {
			err = -1;
			errno = rsp->error;
		}
	} else {
		*result = entry;

		dir->d_data_size = rsp->rd_rsp.r_data_size;
		memcpy(dir->d_data, dbuf, dir->d_data_size);

		memcpy(entry, &dir->d_data[0], sizeof(*entry));
		dir->d_data_offset = sizeof(*entry);
		dir->d_next_ino = rsp->rd_rsp.r_ino;
		dir->d_next_offset = rsp->rd_rsp.r_offset;
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, dbuf, pfsd_tolong(ch));
	return err;
}

int
pfsd_closedir(DIR *dir)
{
	if (!PFSD_DIR_ISVALID(dir)) {
		errno = EINVAL;
		return -1;
	}

	dir = PFSD_DIR_RAW(dir);
	if (!dir) {
		errno = EINVAL;
		return -1;
	}

	PFSD_FREE(dir);
	return 0;
}

int
pfsd_access(const char *pbdpath, int amode)
{
	if (amode != F_OK &&
		(amode & (R_OK | W_OK | X_OK)) == 0) {
		errno = EINVAL;
		return -1;
	}

	char abspath[PFS_MAX_PATHLEN];
	pbdpath = pfsd_name_init(pbdpath, abspath, sizeof abspath);
	if (pbdpath == NULL) {
		errno = EFAULT;
		return -1;
	}

	char pbdname[PFS_MAX_NAMELEN];
	if (pfsd_sdk_pbdname(pbdpath, pbdname) != 0) {
		errno = EINVAL;
		return -1;
	}

	CHECK_MOUNT(pbdname);

	if (amode & W_OK) {
		CHECK_WRITABLE();
	}

	int err = 0;
	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	pfsd_response_t *rsp = NULL;
	unsigned char *buf = NULL;

retry:
	if (pfsd_chnl_buffer_alloc(s_connid, PFS_MAX_PATHLEN, (void**)&req, 0,
	    (void**)&rsp, (void**)&buf, (long*)(&ch)) != 0) {
		errno = ENOMEM;
		return -1;
	}

	/* fill request */
	req->type = PFSD_REQUEST_ACCESS;
	req->a_req.a_mode = amode;
	/* copy pbdpath to iobuf */
	strncpy((char*)buf, pbdpath, PFS_MAX_PATHLEN);

	pfsd_chnl_send_recv(s_connid, req, PFS_MAX_PATHLEN, rsp, 0, buf,
	    pfsd_tolong(ch), 0);
	CHECK_STALE(rsp);

	if (rsp->a_rsp.a_res != 0) {
		err = -1;
		errno = rsp->error;
		if (errno != ENOENT)
			PFSD_CLIENT_ELOG("access %s: %s", pbdpath,
			    strerror(errno));
	}

	pfsd_chnl_buffer_free(s_connid, req, rsp, buf, pfsd_tolong(ch));

	return err;
}

int
pfsd_fsync(int fd)
{
	return 0;
}

ssize_t
pfsd_readlink(const char *pbdpath, char *buf, size_t bufsize)
{
	errno = EINVAL;
	return -1;
}

int
pfsd_chmod(const char *pbdpath, mode_t mode)
{
	return 0;
}

int
pfsd_fchmod(int fd, mode_t mode)
{
	return 0;
}

int
pfsd_chown(const char *pbdpath, uid_t owner, gid_t group)
{
	return 0;
}

static const uint64_t
pfsd_current_version = 2;

unsigned long
pfsd_meta_version_get() {
	return pfsd_current_version;
}

/* libpfs version, 'strings libpfs.a' can get this info */
#define _TOSTR(a)   #a
#define TOSTR(a)    _TOSTR(a)
char pfsd_build_version[] = "libpfs_version_" TOSTR(VERSION_DETAIL);
const char*
pfsd_build_version_get() {
	return pfsd_build_version;
}

