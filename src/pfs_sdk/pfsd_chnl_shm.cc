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
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <stddef.h>

#include "pfsd_chnl_shm.h"
#include "pfsd_chnl_impl.h"
#include "pfsd_shm.h"
#include "pfsd_common.h"
#include "pfsd_worker.h"
#include "pfsd_zlog.h"

#ifdef PFSD_SERVER
#include "pfs_mount.h"
#include "pfsd_option.h"
#endif /* PFSD_SERVER */

#define PIDFILE_MODE_MOUNT_REQ 0666
#define PIDFILE_MODE_UMOUNT_REQ 0777

/* Server side */
static int
pfsd_accept_begin(void *ctx, void *op, int conn_id_hint, const char *cluster,
    const char *pbdname, int host_id, int flags)
{
#ifdef PFSD_SERVER
	assert(pfsd_is_valid_connid(conn_id_hint));
	int connect_id = pfsd_chnl_accept_begin(ctx, op, conn_id_hint);
	if (pfsd_is_valid_connid(connect_id)) {
		if (pfs_mount_acquire(cluster, pbdname, host_id, flags) < 0) {
			pfsd_error("mount %s failed %s", pbdname, strerror(errno));
			pfsd_chnl_accept_begin_rollback(connect_id);
			return -errno;
		}
		pfsd_info("mount successed for %s", pbdname);
	} else {
		pfsd_error("pfsd_chnl_accept_begin failed for %d", host_id);
		return -ECONNREFUSED;
	}

	return connect_id;

#else
	return -1;
#endif
}

/* Server side */
static uint32_t
get_file_mode(chnl_ctx_shm_t *ctx, const char *filename) {
	char pidfile[PFSD_MAX_SVR_ADDR_SIZE];
	/* Can't overflow */
	snprintf(pidfile, PFSD_MAX_SVR_ADDR_SIZE, "%s/%s", ctx->ctx_pidfile_dir,
	    filename);
	struct stat st;
	if (stat(pidfile, &st) == 0) {
		return st.st_mode & 0777;
	}

	return 0;
}

static void
chnl_accept_shm_sync(chnl_ctx_shm_t *ctx, pfsd_chnl_op_t *op,
    const char *filename, uint32_t len)
{
#ifdef PFSD_SERVER
	pidfile_data_t file_data;
	char pidfile[PFSD_MAX_SVR_ADDR_SIZE];
	/* Can't overflow */
	snprintf(pidfile, PFSD_MAX_SVR_ADDR_SIZE, "%s/%s", ctx->ctx_pidfile_dir,
	    filename);

	/* O_SYNC: must write to disk */
	int fd = open(pidfile, O_RDWR | O_SYNC | O_CLOEXEC);
	int32_t connect_id = -1;
	int mntid = -1;
	ssize_t result = -1;
	bool remount = false;

	struct timeval tv_begin, tv_cur;
	struct stat st;
	memset(&file_data, 0, sizeof(file_data));
	if (fd < 0) {
		pfsd_error("when accept conn, open %s failed err %s", pidfile,
		    strerror(errno));
		return;
	}

	if (fstat(fd, &st) < 0) {
		pfsd_error("when accept conn, stat %s failed err %s", pidfile,
		    strerror(errno));
		close(fd);
		return;
	}
	if (st.st_size < (int)sizeof(file_data.sync_data)) {
		pfsd_warn("Sdk is not prepared, it's OK, waiting for sdk done.");
		close(fd);
		return;
	}

	gettimeofday(&tv_begin, NULL);
	do {
		gettimeofday(&tv_cur, NULL);
		if ((tv_cur.tv_sec - tv_begin.tv_sec) * 1000000 +
		    tv_cur.tv_usec - tv_begin.tv_usec >
		    PFSD_CONNECT_TIMEOUT_US) {
			close(fd);

			if (unlink(pidfile) != 0) {
				pfsd_error("when accept conn, "
				    "unlink %s fail err %s",
				    pidfile, strerror(errno));
			}

			pfsd_error("accept conn timeout, unlink %s", pidfile);
			return;
		}

		result = pread(fd, &file_data, sizeof(file_data), 0);
	} while (result < 0 && errno == EINTR);

	if (result < 0 || result < sizeof(file_data.sync_data)) {
		pfsd_error("accept conn read sync_data bytes %d, expect %lu",
		    (int)result, sizeof(file_data.sync_data));
		close(fd);
		if (unlink(pidfile) != 0) {
			pfsd_error("accept conn but unlink %s with error %s",
			    pidfile, strerror(errno));
		}

		return;
	}

	pfsd_info("when accept conn, pread sync_data fine %ld", result);

	/* check if reconnect */
	if (result >= sizeof(file_data)) {
		if (pfsd_is_valid_connid(file_data.ack_data.v1.shm_connect_id)) {
			connect_id = file_data.ack_data.v1.shm_connect_id;
			pfsd_info("re accept with conn id %d", connect_id);
		}
	}

	file_data.ack_data.ver = CHNL_SHM_VER;
	if (file_data.sync_data.ver != CHNL_SHM_VER) {
		pfsd_error("accept conn with wrong sync data ver %u, expect %d",
		    file_data.sync_data.ver, CHNL_SHM_VER);
		file_data.ack_data.err = -EPROTO;
		snprintf(file_data.ack_data.err_msg,
		    sizeof(file_data.ack_data.err_msg),
		    "Unrecognized version : %u, expect %d",
		    file_data.sync_data.ver,
		    CHNL_SHM_VER);
		goto out;
	}

	if (!pfsd_is_valid_connid(connect_id)) {
		/* first mount */
		// 2 is special for thread mode mount to avoid alive check
		// that only relies on fd close detection.
		connect_id = pfsd_accept_begin(ctx, op,
		    ((file_data.sync_data.flags & MNTFLG_TOOL) == 0) ? 2 : 1,
		    file_data.sync_data.cluster,
		    file_data.sync_data.pbdname,
		    file_data.sync_data.host_id,
		    file_data.sync_data.flags);
	} else {
		remount = true;
		int remount_res = 0;
		if (file_data.ack_data.v1.mntid < 0) {
			pfsd_error("We cannot accept req after previous remount"
			    "recovery failer: connecitd %d, mntid %d.",
			    connect_id, file_data.ack_data.v1.mntid);
			file_data.ack_data.v1.err_remount = -errno;
			strncpy(file_data.ack_data.err_msg, "Remount failed!",
			    sizeof(file_data.ack_data.err_msg));
			goto out;
		}
		if (file_data.ack_data.v1.flags != file_data.sync_data.flags) {
			remount_res = pfs_remount(file_data.sync_data.cluster,
			    file_data.sync_data.pbdname,
			    file_data.sync_data.host_id,
			    file_data.sync_data.flags);
		} else {
			pfsd_info("It does not need remount for %s: old "
			    "flag:0x%x, new flag:0x%x",
			    file_data.sync_data.pbdname,
			    file_data.ack_data.v1.flags,
			    file_data.sync_data.flags);
			remount_res = 0;
		}
		pfsd_info("re accept conn remount result %d for %s",
		    remount_res, file_data.sync_data.pbdname);

		if (remount_res < 0) {
			file_data.ack_data.v1.err_remount = -errno;
			strncpy(file_data.ack_data.err_msg, "Remount failed!",
			    sizeof(file_data.ack_data.err_msg));
			goto out;
		} else {
			file_data.ack_data.v1.err_remount = 0;
			file_data.ack_data.v1.flags = file_data.sync_data.flags;
		}
	}

	if (pfsd_is_valid_connid(connect_id)) {
		if (!remount) {
			file_data.ack_data.err = 0;

			memcpy(file_data.ack_data.v1.shm_fname,
			    ctx->svr.shm_fname,
			    sizeof(file_data.ack_data.v1.shm_fname));
			file_data.ack_data.v1.shm_connect_id = connect_id;
			pfsd_info("connect success result %d for %s",
			    connect_id, file_data.sync_data.pbdname);

			/* record mount id add update lru inode-list size */
			pfs_mount_t *mnt = pfs_get_mount(file_data.sync_data.pbdname);
			PFSD_ASSERT(mnt);
			file_data.ack_data.v1.mntid = mnt->mnt_id;
			file_data.ack_data.v1.flags = file_data.sync_data.flags;
			file_data.ack_data.v1.err_remount = 0;
			mntid = mnt->mnt_id;
			pfs_put_mount(mnt);
		}
	} else {
		file_data.ack_data.err = connect_id;
		file_data.ack_data.v1.shm_connect_id = connect_id;
		file_data.ack_data.v1.err_remount = 0;
		pfsd_error("connect failed. result %d for %s",
		    connect_id, file_data.sync_data.pbdname);
		if (file_data.ack_data.err == -ECONNREFUSED)
			strncpy(file_data.ack_data.err_msg,
			    "Too many connections!",
			    sizeof(file_data.ack_data.err_msg));
		else
			strncpy(file_data.ack_data.err_msg, "Mount failed!",
			    sizeof(file_data.ack_data.err_msg));
	}

	if (!remount)
		pfsd_chnl_accept_end(connect_id, mntid);

out:
	file_data.ack_data.v1.shm_mnt_epoch = file_data.sync_data.shm_mnt_epoch;
	/* write ack data to notify client */
	pwrite(fd, &file_data.ack_data,
	    sizeof(file_data.ack_data),
	    offsetof(pidfile_data_t, ack_data));
	close(fd);
#endif
}

/* Server side */
static void
chnl_close_shm_svr(chnl_ctx_shm_t *ctx, const char *filename, uint32_t name_len,
    bool force_umount)
{
#ifdef PFSD_SERVER
	int result = -1;
	struct stat st;
	pidfile_data_t file_data;

	char path[PFSD_MAX_SVR_ADDR_SIZE];
	snprintf(path, PFSD_MAX_SVR_ADDR_SIZE, "%s/%s", ctx->ctx_pidfile_dir,
	    filename);
	filename = path;

	/* 
	 * O_RDONLY for not trigger IN_CLOSE_WRITE, 
	 * which result in forever loop
	 */
	int fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pfsd_error("when close chnl, open %s with err: %s", filename,
		    strerror(errno));
		return;
	}

	if (!force_umount) {
		result = TEMP_FAILURE_RETRY(flock(fd, LOCK_EX | LOCK_NB));

		if (result < 0 && errno == EWOULDBLOCK) {
			pfsd_warn("when close chnl, can't flock %s, "
			    "may be it's alive", filename);
			goto out;
		}
	}

	if (fstat(fd, &st) < 0) {
		pfsd_error("when close chnl, can't stat %s with err %s\n",
		    filename, strerror(errno));
		goto out_unlink;
	}

	if (st.st_size >= (int)sizeof(file_data)) {
		result = pread(fd, &file_data, sizeof(file_data), 0);
		pfsd_info("sizeof(filedata) %lu = %lu + %lu, when svr close "
		    "chnl, read %d bytes: ack.err %d, conn id %d",
		    sizeof(file_data),
		    sizeof(file_data.sync_data),
		    sizeof(file_data.ack_data),
		    result,
		    file_data.ack_data.err,
		    file_data.ack_data.v1.shm_connect_id);
		int conn_id = file_data.ack_data.v1.shm_connect_id;
		if (result == sizeof(file_data) &&
			file_data.ack_data.err == 0 &&
			pfsd_is_valid_connid(conn_id)) {

			/* wait and recycle zombie */
			for (int i = 0; i < PFSD_SHM_MAX; ++i) {
				(void)pfsd_shm_svr_abort_request(g_shm[i],
				    conn_id, false);
			}
			if (file_data.ack_data.v1.mntid < 0) {
				pfsd_error("unmount not needed for cid: %d ",
				    conn_id);
				goto out_unlink;
			}
			do {
				int ret = pfsd_chnl_close_begin(conn_id);
				if (ret == 0) {
					ret = pfs_mount_release(
					    file_data.sync_data.pbdname,
					    file_data.sync_data.host_id);
					pfsd_info("umount %s %s",
					    file_data.sync_data.pbdname,
					    ret == 0 ? "success" : strerror(errno));
					pfsd_chnl_close_end();
					break;
				}
				pfsd_chnl_close_end();
			} while (errno == EAGAIN);
		}
	}

out_unlink:
	if (unlink(filename) != 0) {
		pfsd_error("unlink %s fail because %s", filename,
		    strerror(errno));
	} else {
		pfsd_info("unlink %s success", filename);
	}
out:
	close(fd);
#endif
}

typedef struct {
	void *chnl_ctx;
	void *chnl_op;
} listen_thread_arg_t;

static void *
chnl_listen_shm_thread_entry(void *arg)
{
#ifdef PFSD_SERVER
	listen_thread_arg_t *args = (listen_thread_arg_t *)arg;
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)args->chnl_ctx;
	pfsd_chnl_op_t *op = (pfsd_chnl_op_t *)args->chnl_op;
	free(arg);

	/* wait for prepared */
	pfsd_info("listen thread waiting to work.");
	sem_wait(&ctx->svr.shm_listen_thread_latch);
	pfsd_info("listen thread start working.");

	char buf[2 * PFS_MAX_PATHLEN]; /* must bigger than PFS_MAX_PATHLEN */
	ssize_t numRead = 0;
	int nfd = ctx->svr.shm_inotify_fd;
	while (!g_stop) {
		do {
			numRead = TEMP_FAILURE_RETRY(read(nfd, buf,
			    sizeof(buf)));
		} while (numRead < 0);

		PFSD_ASSERT(numRead >= 0);

		for (char* p = buf; p < buf + numRead; ) {
			struct inotify_event* event = (struct inotify_event *) p;
			if ((event->mask & IN_ISDIR) == 0) {
				if (event->mask & IN_ATTRIB) {
					pfsd_info("inotify attr event: "
					    "name %s and mask %x",
					    event->name, event->mask);
					uint32_t mode = get_file_mode(ctx, event->name);
					if (mode == PIDFILE_MODE_MOUNT_REQ) {
						chnl_accept_shm_sync(ctx, op,
						    event->name, event->len);
					} else if (mode == PIDFILE_MODE_UMOUNT_REQ) {
						chnl_close_shm_svr(ctx,
						    event->name, event->len,
						    true);
					}
					else {
						pfsd_error("unknow mode %x for "
						    "name %s",
						    mode,
						    event->name);
					}
				}

				if (event->mask & IN_CLOSE_WRITE) {
					pfsd_info("inotify close event: name %s "
					    "and mask %x",
					    event->name,
					    event->mask);
					chnl_close_shm_svr(ctx, event->name,
					    event->len, false);
				}
			}

			p += sizeof(struct inotify_event) + event->len;
		}
	}
	//Fixme: using op->chnl_ctx_destroy(ctx) instead? test needed
	free(ctx);
#endif
	return NULL;
}

static int
chnl_listen_shm(void *chnl_ctx, void *chnl_op, const char *svr_addr, void *arg1,
    void *arg2)
{
#ifdef PFSD_SERVER
	/*
	 * IN_ONLYDIR: we only watch the pidfile directory.
	 * IN_ATTRIB : when sdk writen sync_data, fchmod metadata to notify pfsd.
	 * IN_CLOSE_WRITE: sdk process exit or close pidfile.
	 * IN_EXCL_UNLINK: do NOT notify unlink event.
	 */
	int interests = IN_ONLYDIR | IN_CLOSE_WRITE | IN_EXCL_UNLINK | IN_ATTRIB;
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;
	listen_thread_arg_t *args = NULL;
	pthread_t tid;
	int inotify_fd = -1;
	int result = -1;

	(void)arg2;

	if (arg1 == NULL) {
		pfsd_error("arg1 can't be null");
		errno = EINVAL;
		goto fail;
	}

	{
		/* check svr_addr directory be writable */
		char tmpl[PFS_MAX_PATHLEN];
		snprintf(tmpl, PFS_MAX_PATHLEN, "%s/test_writable_pfsd.XXXXXX",
		    svr_addr);
		int fd = mkstemp(tmpl);
		if (fd < 0) {
			pfsd_error("svr_addr %s is not writable", svr_addr);
			goto fail;
		} else {
			unlink(tmpl);
			close(fd);
		}
	}

	memcpy(ctx->svr.shm_fname, arg1, sizeof(ctx->svr.shm_fname));

	inotify_fd = inotify_init();
	PFSD_ASSERT(inotify_fd >= 0);

	result = inotify_add_watch(inotify_fd, svr_addr, interests);
	if (result < 0) {
		pfsd_error("inotify_add_watch fail: (%s)", strerror(errno));
		goto fail;
	}

	ctx->svr.shm_inotify_fd = inotify_fd;

	args = (listen_thread_arg_t *)malloc(sizeof(listen_thread_arg_t));
	args->chnl_ctx = chnl_ctx;
	args->chnl_op = chnl_op;
	/* start inotify thread */
	pthread_create(&tid, NULL, chnl_listen_shm_thread_entry, args);

	return 0;

fail:
	if (inotify_fd >= 0)
		close(inotify_fd);
#endif

	return -1;
}

/* server side */
static int
chnl_prepare_shm(const char *pbdname, int nworkers, void *arg1)
{
#ifdef PFSD_SERVER
	const char *shm_dir = (const char *)arg1;
	int err;

	err = pfsd_shm_init(shm_dir, pbdname, PFSD_SHM_CHNL_DEFAULT);
	if (err != 0) {
		pfsd_error("pfsd_shm_init fail %d", err);
		return err;
	}

	/* prepare for cpu affinity */
	g_cpufile = (pfsd_cpu_record_t *)pfsd_worker_affinity_prepare(nworkers);
	if (g_ncpu > 1 && g_cpufile == NULL) {
		pfsd_warn("cpu number is %d, but can't set affinity, "
		    "may hurt performance.", g_ncpu);
	}

	worker_t *workers = pfsd_create_workers(nworkers);
	PFSD_ASSERT(workers != NULL);

	for (int i = 0; i < nworkers; ++i) {
		workers[i].w_idx = i;
		int r = pthread_create(&workers[i].w_tid, NULL,
		    pfsd_worker_routine, &workers[i]);
		PFSD_ASSERT(r == 0);
	}

	g_workers = workers;
	g_nworkers = nworkers;

#endif
	return 0;
}

#ifdef PFSD_SERVER
static int32_t
chnl_set_mnt_shm(pidfile_data_t *data, int32_t mntflag, bool succ,
    bool is_remount)
{
	if (succ) {
		pfs_mount_t *mnt = pfs_get_mount(data->sync_data.pbdname);
		PFSD_ASSERT(mnt);
		data->ack_data.v1.mntid = mnt->mnt_id;
		pfs_put_mount(mnt);
		data->ack_data.v1.flags = mntflag;
	} else if (!is_remount)
		data->ack_data.v1.mntid = -1;
	else {
		pfsd_error("We can not recover from remount request handle "
		    "error. Just kill the client via invalidating its old "
		    "mount id: %d. Request aborting will be handled later.",
		    data->ack_data.v1.mntid);
		data->ack_data.v1.mntid = -1;
	}
	return data->ack_data.v1.mntid;
}

enum {
	/*
	 * Due to system error or input format error, we do not finish the
	 * recovery;
	 * */
	RECOVER_NOT_HANDLED = -1,

	/*
	 * We handle the recovery process as expected.
	 */
	RECOVER_HANDLED = 0,

	/*
	 * We will handle the recover mount later(after every information
	 * collected)
	 */
	RECOVER_MOUNT_LATER = 1,
};

static int
chnl_recover_mount(void *ctx, void *op, pidfile_data_t *data,
    int32_t conn_id_hint, int32_t mnt_flags, bool need_response, bool
    is_remount, const char *fname, int fd)
{
	chnl_ctx_shm_t *ch_ctx = (chnl_ctx_shm_t *)ctx;
	int cid = pfsd_accept_begin(ctx, op, conn_id_hint,
	    data->sync_data.cluster, data->sync_data.pbdname,
	    data->sync_data.host_id, mnt_flags);
	bool accept_succ = pfsd_is_valid_connid(cid);
	int err = accept_succ ? 0 : cid;
	int32_t mntid = -1;

	if (!accept_succ)
		pfsd_error("recovery failed, err: %d, name: %s", err, fname);

	data->ack_data.v1.shm_mnt_epoch = data->sync_data.shm_mnt_epoch;
	if (is_remount) {
		data->ack_data.v1.err_remount = accept_succ ? 0 : cid;
		if (!accept_succ)
			strncpy(data->ack_data.err_msg, "Remount failed!",
			    sizeof(data->ack_data.err_msg));
	}
	else if (need_response) {
		data->ack_data.err = accept_succ ? 0 : cid;
		data->ack_data.v1.shm_connect_id = cid;
		data->ack_data.ver = CHNL_SHM_VER;
		if (accept_succ)
			memcpy(data->ack_data.v1.shm_fname,
			    ch_ctx->svr.shm_fname,
			    sizeof(data->ack_data.v1.shm_fname));
		else
			strncpy(data->ack_data.err_msg, "Mount failed!",
			    sizeof(data->ack_data.err_msg));
	}

	mntid = chnl_set_mnt_shm(data, mnt_flags, accept_succ, is_remount);
	pfsd_chnl_accept_end(cid, mntid);

	pfsd_info("recover conn result %d for %s", cid,
	    data->sync_data.pbdname);
	if (need_response) {
		int n = pwrite(fd, &data->ack_data, sizeof(data->ack_data),
		    offsetof(pidfile_data_t, ack_data));
		if (n != sizeof(data->ack_data)) {
			pfsd_error("recover %s but pwrite ack failed %s",
			    data->sync_data.pbdname, strerror(errno));
			return RECOVER_NOT_HANDLED;
		}
	}
	return RECOVER_HANDLED;
}

static int
chnl_recover_new_mount(void *ctx, void *op, const char *fname)
{
	pfsd_info("new mount request: %s", fname);
	int fd = open(fname, O_RDWR | O_CLOEXEC);
	int recover_stat = RECOVER_NOT_HANDLED;
	if (fd < 0) {
		pfsd_error("open %s fail %s", fname, strerror(errno));
		return recover_stat;
	}
	pidfile_data_t data;
	memset(&data, 0, sizeof(data));

	int result = pread(fd, &data, sizeof(data), 0);
	if (result != sizeof(data.sync_data)) {
		pfsd_error("illegal client operation, file: %s, result: %d",
		    fname, result);
		close(fd);
		return recover_stat;
	}
	int32_t mnt_flags = data.sync_data.flags;
	int32_t conn_id_hint = ((data.sync_data.flags & MNTFLG_TOOL) == 0) ?
	    2 : 1;
	recover_stat = chnl_recover_mount(ctx, op, &data, conn_id_hint,
	    mnt_flags, true, false, fname, fd);
	close(fd);
	return recover_stat;
}

static int
chnl_recover_shm_file(void *ctx, void *op, const char *fname)
{
	bool need_mount = true;
	bool need_abort = true;
	bool need_response = true;
	bool need_unlink = true;
	bool remount_request = false;

	int recover_stat = RECOVER_NOT_HANDLED;

	int fd = open(fname, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pfsd_error("open %s fail %s", fname, strerror(errno));
		return recover_stat;
	}

	pidfile_data_t data;
	memset(&data, 0, sizeof(data));

	bool locked = TEMP_FAILURE_RETRY(flock(fd, LOCK_EX | LOCK_NB)) == 0;
	/**
	 * We construct the stats from weak to strong condition.
	 * We only negate the stats.
	 */
	struct stat st;
	fstat(fd, &st);
	uint32_t mode = st.st_mode & 0777;
	if (mode == PIDFILE_MODE_UMOUNT_REQ) {
		pfsd_info("Do not recover mount for %s because"
		    " umount request", fname);
		need_mount = false;
		need_response = false;
	}

	int result = pread(fd, &data, sizeof(data), 0);
	if (result == sizeof(data)) {
		int32_t old_conn_id = data.ack_data.v1.shm_connect_id;
		if (!pfsd_is_valid_connid(old_conn_id)) {
			need_mount = false;
			need_abort = false;
		}
		if (data.ack_data.v1.shm_mnt_epoch >=
		    data.sync_data.shm_mnt_epoch)
			need_response = false;
		if (data.ack_data.v1.mntid < 0){
			need_mount = false;
			need_response = false;
			pfsd_error("We can not recover from previous remount "
			    "recovery failer: connecitd %d, mntid %d. And"
			    "we do not reply for any possible further request",
			    old_conn_id, data.ack_data.v1.mntid);
		}else
			pfsd_info("process recover %s", data.sync_data.pbdname);
	} else if (result >= sizeof(data.sync_data) && result < sizeof(data)) {
		need_abort = false;
		/**
		 * Maybe we have partially replied a packet, clean the old
		 * reply.
		 */
		memset(&data.ack_data, 0, sizeof(data.ack_data));
		pfsd_info("process recover %s, never mounted before.",
		    data.sync_data.pbdname);
	} else {
		need_mount = false;
		need_abort = false;
		need_response = false;
		need_unlink = false;
		//File was just created, if result == 0
		//or some unexpected file created, if result > 0
		//or system error, if result < 0
		//We do nothing but wait.
		pfsd_error("File length not expected and we will do nothing: "
		    "pread %s = %d, %s", fname, result, strerror(errno));
	}

	/**
	 * need_abort, need_unlink should be final determined.
	 * They are not fully independent from other stats.
	 */
	if (locked) {
		need_mount = false;
		need_response = false;
	}
	if (need_mount) {
		need_unlink = false;
		need_abort = false;
	}

	pfsd_info("recovery stats for %s: need_mount:%d, "
	    "need_abort:%d, need_response:%d, need_unlink:%d", fname,
	    (int)need_mount, (int)need_abort, (int)need_response,
	    (int)need_unlink);

	if (need_mount) {
		int32_t conn_id_hint = data.ack_data.v1.shm_connect_id;
		int32_t mnt_flags = data.sync_data.flags;

		//We prefer ack mount flag excepting remount wait to be handled.
		if (!need_response) {
			if(data.ack_data.v1.flags == 0) {
				pfsd_error("invalid mount recover "
				    "file, ignore %s, mntflags:%d, "
				    "cid: %d", fname, data.ack_data.v1.flags,
				    conn_id_hint);
				goto fini;
			}
			mnt_flags = data.ack_data.v1.flags;
		} else if (!pfsd_is_valid_connid(conn_id_hint)) {
			recover_stat = RECOVER_MOUNT_LATER;
			goto fini;
		} else
			remount_request = true;
		pfsd_info("mount recover ready for %s: conn_id_hint:%d, "
		    "mntflag:%d, hostid: %d, sync_mntflag:%d, remount_req:%d"
		    , fname, conn_id_hint, mnt_flags, data.sync_data.host_id,
		    data.sync_data.flags, (int)remount_request);
		recover_stat = chnl_recover_mount(ctx, op, &data, conn_id_hint,
		    mnt_flags, need_response, remount_request, fname, fd);
	}
	if (need_abort) {
		int32_t conn_id = data.ack_data.v1.shm_connect_id;
		pfsd_info("connection %d wait abort requests", conn_id);
		PFSD_ASSERT(pfsd_is_valid_connid(conn_id));
		for (int i = 0; i < PFSD_SHM_MAX; ++i) {
			pfsd_shm_svr_abort_request(g_shm[i], conn_id, true);
		}
		recover_stat = RECOVER_HANDLED;
	}
	if (need_unlink) {
		pfsd_info("unlink %s", fname);
		if (unlink(fname) != 0)
			pfsd_info("unlink %s fail because %s", fname,
			    strerror(errno));
		recover_stat = RECOVER_HANDLED;
	}
fini:
	if (locked)
		flock(fd, LOCK_UN);
	close(fd);
	return recover_stat;
}

int
chnl_recover_filter(const char *file_name)
{
	/* Skip . and .. */
	if (strcmp(file_name, ".") == 0 || strcmp(file_name, "..") == 0)
		return -1;

	/*
	 * Only {number}.pid format is expected. We do not use sscanf
	 * for safety.
	 * */
	int fname_len = strlen(file_name);
	if ((fname_len <= 4 ||
	    memcmp(file_name + fname_len - 4, ".pid", 4) != 0) ||
	    atoi(file_name) == 0) {
		pfsd_error("unexpected file name, ignore %s",
		    file_name);
		return -1;
	}
	return 0;
}
#endif

static int
chnl_recover_shm(void *ctx, void *op, const char *svr_addr, int nworkers,
    void *arg)
{
#ifdef PFSD_SERVER
	chnl_ctx_shm_t *ch_ctx = (chnl_ctx_shm_t *)ctx;
	int err = -1;
	int recover_stat = RECOVER_HANDLED;
	struct dirent *dp;
	char fname_buf[CHNL_MAX_CONN][PFS_MAX_PATHLEN];
	int fname_buf_index = 0;

	DIR *dir = opendir(svr_addr);
	if (dir == NULL) {
		pfsd_error("opendir %s err %s", svr_addr, strerror(errno));
		goto fini;
	}

	err = 0;
	for (;;) {
		errno = 0; /* To distinguish error from end-of-directory */
		dp = readdir(dir);
		if (dp == NULL) {
			if (errno != 0) {
				pfsd_error("readdir %s err %s", svr_addr,
				    strerror(errno));
				continue;
			} else {
				break; /* end of DIR */
			}
		}

		if (chnl_recover_filter(dp->d_name) < 0)
			continue;

		char fname[PFS_MAX_PATHLEN];
		snprintf(fname, PFS_MAX_PATHLEN, "%s/%s", svr_addr, dp->d_name);
		pfsd_info("recovery %s begin", fname);
		recover_stat = chnl_recover_shm_file(ctx, op, fname);
		if (recover_stat == RECOVER_MOUNT_LATER) {
			pfsd_info("This is a first mount request, handle it "
			    "later to avoid connect id allocation collision:%s",
			    fname);
			if (fname_buf_index < CHNL_MAX_CONN) {
				memcpy(fname_buf[fname_buf_index], fname,
				    sizeof(fname));
				++fname_buf_index;
			} else
				pfsd_error("Too many connections, ignore %s, "
				    "client should wait its timeout", fname);
		}
		else
			pfsd_info("recovery %s end, result:%d", fname,
			    recover_stat);
	}

fini:
	if (dir)
		closedir(dir);

	for (int i = 0; i < fname_buf_index; ++i) {
		pfsd_info("mount %s begin", fname_buf[i]);
		recover_stat = chnl_recover_new_mount(ctx, op, fname_buf[i]);
		pfsd_info("mount %s end, %d", fname_buf[i], recover_stat);
	}

	sem_post(&ch_ctx->svr.shm_listen_thread_latch);
	pfsd_info("prepare done %d, notify listen thread", err);
	return err;

#endif
	return 0;
}

/* for both sides */
static void *
chnl_ctx_create_shm(const char *svr_addr, bool is_svr)
{
	chnl_ctx_shm_t *result = NULL;
	int err;
	int name_len;
	struct stat dir_info;

	if (strlen(svr_addr) < sizeof("/") || svr_addr[0] != '/') {
		/* should be absolute path */
		errno = EINVAL;
		return NULL;
	}

	/* Check if svr_addr is a directory */
	err = stat(svr_addr, &dir_info);
	if (err != 0) {
		fprintf(stderr, "stat %s fail: %s\n", svr_addr, strerror(errno));
		return NULL;
	}

	if (!S_ISDIR(dir_info.st_mode)) {
		fprintf(stderr, "%s is not dir\n", svr_addr);
		errno = ENOTDIR;
		return NULL;
	}

	result = (chnl_ctx_shm_t *)calloc(sizeof(chnl_ctx_shm_t), 1);
	if (result == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	result->ctx_is_svr = is_svr;
	result->ctx_pidfile_fd = -1;

	if (is_svr) {
		sem_init(&result->svr.shm_listen_thread_latch,
		    PTHREAD_PROCESS_PRIVATE, 0);
	}

	name_len = snprintf(result->ctx_pidfile_addr, PFSD_MAX_SVR_ADDR_SIZE,
	    "%s/%d.pid", svr_addr, getpid());
	if (name_len >= PFSD_MAX_SVR_ADDR_SIZE) {
		errno = ENAMETOOLONG;
		goto fail;
	}

	/* It can't overflow */
	snprintf(result->ctx_pidfile_dir, PFSD_MAX_SVR_ADDR_SIZE, "%s", svr_addr);
	return result;

fail:
	free(result);
	return NULL;
}

int
chnl_connection_open_shm(chnl_ctx_shm_t *ctx)
{
	if (ctx->ctx_pidfile_fd >= 0)
		return 0;

	int flags = O_RDWR | O_CREAT | O_EXCL | O_SYNC | O_CLOEXEC ;
	ctx->ctx_pidfile_fd = open(ctx->ctx_pidfile_addr, flags, 0644);

	return ctx->ctx_pidfile_fd < 0 ? -1 : 0;
}

#ifdef PFSD_CLIENT
extern int s_mount_epoch;
#endif

/* client side */
int
chnl_connection_sync_shm(chnl_ctx_shm_t *ctx, const char *cluster,
    const char *pbdname, int host_id, int flags)
{
#ifdef PFSD_CLIENT
	int result;
	/* Fill mount args first */
	pidfile_data_t *file_data = &ctx->clt.shm_pidfile_data;
	file_data->sync_data.ver = CHNL_SHM_VER;
	file_data->sync_data.host_id = host_id;
	file_data->sync_data.flags = flags;

	if (cluster == NULL)
		cluster = "polarstore";

	strncpy(file_data->sync_data.cluster, cluster,
	    sizeof(file_data->sync_data.cluster));
	strncpy(file_data->sync_data.pbdname, pbdname,
	    sizeof(file_data->sync_data.pbdname));

	result = flock(ctx->ctx_pidfile_fd, LOCK_EX | LOCK_NB);
	if (result < 0) {
		PFSD_CLIENT_ELOG("client flock failed %s", strerror(errno));
		return result;
	}

	/* read old mount epoch first */
	result = TEMP_FAILURE_RETRY(pread(ctx->ctx_pidfile_fd,
	    &file_data->ack_data,
	    sizeof(file_data->ack_data),
	    offsetof(pidfile_data_t, ack_data)));
	if (result == sizeof(file_data->ack_data)) {
		s_mount_epoch = file_data->ack_data.v1.shm_mnt_epoch;
		memset(&file_data->ack_data, 0, sizeof(file_data->ack_data));
	}
	file_data->sync_data.shm_mnt_epoch = s_mount_epoch + 1;
	if (result == sizeof(file_data->ack_data))
		++s_mount_epoch;
	result = TEMP_FAILURE_RETRY(pwrite(ctx->ctx_pidfile_fd,
	    &file_data->sync_data,
	    sizeof(file_data->sync_data),
	    offsetof(pidfile_data_t, sync_data)));
	if (result != sizeof(file_data->sync_data)) {
		PFSD_CLIENT_ELOG("client pwrite failed %s", strerror(errno));
		result = -1;
		goto out;
	}

	/* inotify server by IN_ATTRIB */
	if (fchmod(ctx->ctx_pidfile_fd, PIDFILE_MODE_MOUNT_REQ) != 0) {
		PFSD_CLIENT_ELOG("client fchmod failed: %s", strerror(errno));
		result = -1;
		goto out;
	}

	return 0;

out:
	flock(ctx->ctx_pidfile_fd, LOCK_UN);
	return result;
#else

	return -1;
#endif
}

/* client side */
static int
chnl_getshm(chnl_ctx_shm_t *ctx)
{
	if (ctx == NULL)
		return -1;

#ifdef PFSD_CLIENT
	pidfile_data_t *file_data = &ctx->clt.shm_pidfile_data;
	size_t len;
	int fd, result;
	struct stat st;
	for (int i = 0; i < PFSD_SHM_MAX; ++i) {
		if (ctx->clt.shm_ptr[i] != NULL)
			continue;

		len = strnlen(file_data->ack_data.v1.shm_fname[i], FILE_MAX_FNAME);
		if (len == FILE_MAX_FNAME || len == 0) {
			PFSD_CLIENT_ELOG("wrong shm filename len %lu", len);
			errno = EPROTO;
			return -1;
		}
		fd = open(file_data->ack_data.v1.shm_fname[i],
		    O_RDWR | O_CLOEXEC, 0664);
		if (fd < 0) {
			PFSD_CLIENT_ELOG("shm_open [%s] with err %d",
			    file_data->ack_data.v1.shm_fname[i], errno);
			return -1;
		}

		result = fstat(fd, &st);
		if (result < 0 || st.st_size == 0) {
			PFSD_CLIENT_ELOG("shm [%s] stat failed",
			    file_data->ack_data.v1.shm_fname[i]);
			close(fd);
			return -1;
		}

		ctx->clt.shm_ptr[i] = (char *)mmap(NULL, st.st_size,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (ctx->clt.shm_ptr[i] == MAP_FAILED) {
			PFSD_CLIENT_ELOG("shm %s mmap failed %d",
			    file_data->ack_data.v1.shm_fname[i], errno);
			ctx->clt.shm_ptr[i] = NULL;
			close(fd);
			return -1;
		}
		ctx->clt.shm_len[i] = st.st_size;
		close(fd);
		fd = -1;

		int magic = ((pfsd_shm_t *)ctx->clt.shm_ptr[i])->sh_magic;
		if (magic != PFSD_SHM_MAGIC) {
			PFSD_CLIENT_ELOG("wrong shm magic %u, expect %u",
			    magic, PFSD_SHM_MAGIC);
			return -1;
		}
	}
#endif
	return 0;
}

/* client side */
void
chnl_connection_release_shm(chnl_ctx_shm_t *chnl_ctx, bool forced, bool wait)
{
#ifdef PFSD_CLIENT
	errno = 0;
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;
	if (!ctx || ctx->ctx_is_svr)
		return;

	for (int i = 0; i < PFSD_SHM_MAX; ++i) {
		if (ctx->clt.shm_ptr[i]) {
			munmap(ctx->clt.shm_ptr[i], ctx->clt.shm_len[i]);
			ctx->clt.shm_ptr[i] = NULL;
		}
	}

	if (ctx->ctx_pidfile_fd > 0) {
		/*
		 * must unlock first, we must assure server can flock success
		 * after recv inotify-close
		 */
		flock(ctx->ctx_pidfile_fd, LOCK_UN);

		int result = 0;
		if (forced) {
			/* inotify server by IN_ATTRIB */
			if (fchmod(ctx->ctx_pidfile_fd, PIDFILE_MODE_UMOUNT_REQ) != 0) {
				PFSD_CLIENT_ELOG("client fchmod failed: %s", strerror(errno));
				result = -1;
			}
		}

		close(ctx->ctx_pidfile_fd);
		ctx->ctx_pidfile_fd = -1;

		usleep(1000);

		int done = wait ? 0 : 1;
		while (!done) {
			if (access(ctx->ctx_pidfile_addr, F_OK) < 0 && errno == ENOENT) {
				done = 1;
				PFSD_CLIENT_LOG(
				    "client umount return : deleted %s",
				    ctx->ctx_pidfile_addr);
				break;
			}

			if (result == -1)
				break;

			/* wait pfsd unlink pidfile */
			usleep(1000);
		}

		if (done)
			errno = 0;
		else
			errno = EAGAIN;
	}
#endif
}

void
chnl_ctx_destroy_shm(void *chnl_ctx)
{
	if (chnl_ctx) {
		chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;
		if (ctx->ctx_is_svr)
			sem_destroy(&ctx->svr.shm_listen_thread_latch);

		free(ctx);
	}
}

/* client side */
int32_t
chnl_connection_poll_shm(chnl_ctx_shm_t *ctx, int timeout_us, bool reconn)
{
#ifdef PFSD_CLIENT
	int32_t conn_id = -1;
	struct stat st;
	bool wait = true;
	int result = -1;
	int i = -1;
	pidfile_data_t *file_data = &ctx->clt.shm_pidfile_data;

	if (ctx->ctx_pidfile_fd < 0) {
		errno = EBADF;
		return -1;
	}

	/* poll mount response */
	while (wait) {
		result = fstat(ctx->ctx_pidfile_fd, &st);
		if (result < 0) {
			PFSD_CLIENT_ELOG("fstat error %s", strerror(errno));
			break;
		}

		if (st.st_size >= (int)sizeof(*file_data)) {
			result = TEMP_FAILURE_RETRY(pread(ctx->ctx_pidfile_fd,
			    &file_data->ack_data,
			    sizeof(file_data->ack_data),
			    offsetof(pidfile_data_t, ack_data)));

			if (result != sizeof(file_data->ack_data)) {
				PFSD_CLIENT_ELOG("ack data is not complete, "
				    "it's impossible because pwrite is atomic");
				errno = EAGAIN;
				result = -1;
				wait = false;
			} else {
				if (file_data->ack_data.v1.shm_mnt_epoch >=
				    s_mount_epoch) {
					s_mount_epoch = file_data->ack_data.v1.shm_mnt_epoch;
					PFSD_CLIENT_LOG(
					    "ack data update s_mount_epoch %d",
					    s_mount_epoch);
					wait = false;
				} else {
					if (i++ % 10000 == 0) {
						PFSD_CLIENT_LOG(
						    "waiting... file.epoch %d, s_mount_epoch %d",
						    file_data->ack_data.v1.shm_mnt_epoch,
						    s_mount_epoch);
					}
				}
			}
		}

		if (wait) {
			if (timeout_us <= 0) {
				errno = ETIMEDOUT;
				result = -1;
				wait = false;
			} else {
				usleep(CHNL_SHM_CONNECT_POLL_UNIT);
				timeout_us -= CHNL_SHM_CONNECT_POLL_UNIT;
			}
		}
	}

	if (result >= 0) {
		PFSD_CLIENT_LOG(
		    "connect and got ack data from svr, err = %d, mntid %d",
		    file_data->ack_data.err,
		    file_data->ack_data.v1.mntid);
		if (file_data->ack_data.err != 0) {
			result = file_data->ack_data.err;
			errno = -file_data->ack_data.err;
		}else if (reconn) {
			result = file_data->ack_data.v1.err_remount;
			errno = -file_data->ack_data.v1.err_remount;
			if (result == 0)
				conn_id = file_data->ack_data.v1.shm_connect_id;
			else {
				PFSD_CLIENT_LOG("remount error! %d", errno);
				if (file_data->ack_data.v1.mntid < 0) {
					PFSD_CLIENT_LOG("unrecovered error!");
					exit(-1);
				}
			}
		} else {
			result = chnl_getshm(ctx);
			if (result == 0) {
				ctx->clt.mntid = file_data->ack_data.v1.mntid;
				ctx->clt.shm_connect_id = file_data->ack_data.v1.shm_connect_id;
				conn_id = ctx->clt.shm_connect_id;
			}
		}
	}

	if (result < 0) {
		PFSD_CLIENT_ELOG("Connect failed err %d : %s", result,
		    strerror(errno));
		if (!reconn)
			chnl_connection_release_shm(ctx, false, false);
	}

	return conn_id;
#else
	(void)chnl_getshm(NULL);
	return -1;
#endif
}

/* client side */
int32_t
chnl_connect_shm(void *chnl_ctx, const char *cluster, const char *pbdname,
    int host_id, int flags, int timeout_us, bool reconn)
{
#ifdef PFSD_CLIENT
	int64_t result = -1;
	int32_t conn_id = -1;

	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;
	for (;;) {
		/* create pid file, pfsd will process it by inotify */
		result = chnl_connection_open_shm(ctx);
		if (result < 0) {
			if (errno != EEXIST) {
				PFSD_CLIENT_ELOG("Failed create pidfile: %s",
				    strerror(errno));
				goto fini;
			}
			/* retry create file if EEXIST, because pid reused */
			usleep(10);
		} else {
			break;
		}
	}

	result = chnl_connection_sync_shm(ctx, cluster, pbdname, host_id, flags);
	if (result < 0) {
		PFSD_CLIENT_ELOG("Failed sync shm: %s", strerror(errno));
		goto fini;
	}

	result = chnl_connection_poll_shm(ctx, timeout_us, reconn);
	conn_id = result;

fini:
	return conn_id;
#else
	return -1;
#endif
}

/* client side */
int
chnl_close_shm(void *chnl_ctx, bool forced)
{
#ifdef PFSD_CLIENT
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;
	chnl_connection_release_shm(ctx, forced, true);
	if (errno != 0)
		return -1;
#endif
	return 0;
}

/* client side */
int64_t
chnl_send_req_sync_shm(void *chnl_ctx, int64_t req_len,
    void *req_buffer, int64_t max_rsp_len, void *rsp_buffer, void *io_buffer,
    long buffer_meta)
{
	(void)io_buffer;

#ifdef PFSD_CLIENT
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;
	if (!ctx || ctx->ctx_is_svr)
		return -1;

	pfsd_iochannel_t *ch = NULL;
	memcpy(&ch, &buffer_meta, sizeof(buffer_meta));

	pfsd_request_t *req = (pfsd_request_t *)req_buffer;
	if (ch == NULL || req == NULL)
		return -1;

	pfsd_shm_send_request(ch, req);
#endif
	return 0;
}

/* client side */
int64_t
chnl_recv_rsp_sync_shm(void *chnl_ctx, int64_t req_len, void *req_buffer,
    int64_t max_rsp_len, void *rsp_buffer, void *io_buffer, long buffer_meta)
{
	(void)io_buffer;
#ifdef PFSD_CLIENT
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;
	if (!ctx || ctx->ctx_is_svr)
		return -1;
	/* wait response */
	pfsd_iochannel_t *ch = NULL;
	memcpy(&ch, &buffer_meta, sizeof(buffer_meta));
	if (ch == NULL)
		return -1;

	pfsd_request_t *req = (pfsd_request_t *)req_buffer;
	pfsd_response_t *rsp = (pfsd_response_t *)rsp_buffer;
	if (req == NULL || rsp == NULL)
		return -1;

	pfsd_wait_io(req, &rsp->r_sem);
#endif
	return 0;
}

/* Defined in pfsd_sdk_shm.cc */
extern int pfsd_sdk_alloc_request(int32_t, size_t, pfsd_shm_t *[], int,
    pfsd_iochannel_t **, pfsd_request_t **);

/* client side */
int
chnl_alloc_shm(void *chnl_ctx, int64_t max_req_len, void **req_buffer,
    int64_t max_rsp_len, void **rsp_buffer, void **io_buffer, long *buffer_meta)
{
#ifdef PFSD_CLIENT
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;
	if (!ctx || ctx->ctx_is_svr)
		return -1;

	int64_t iosize = max_req_len > max_rsp_len ? max_req_len : max_rsp_len;
	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	int req_index = -1;
	if (pfsd_sdk_alloc_request(ctx->clt.shm_connect_id, iosize,
	    (pfsd_shm_t **)ctx->clt.shm_ptr, PFSD_SHM_MAX, &ch, &req) != 0) {
		PFSD_CLIENT_ELOG("Alloc request failed");
		return -1;
	}

	req->mntid = ctx->clt.mntid;
	req_index = req - ch->ch_requests;
	*req_buffer = req;
	*rsp_buffer = &ch->ch_responses[req_index];

	void *iobuf = ch->ch_buf + req_index * ch->ch_unitsize;
	if (io_buffer)
		*io_buffer = iobuf;

	/* record channel */
	if (buffer_meta)
		*buffer_meta = pfsd_tolong(ch);
#endif

	return 0;
}

void
chnl_free_shm(void *chnl_ctx, void *req_buffer, void *rsp_buffer,
    void *io_buffer, long buffer_meta)
{
#ifdef PFSD_CLIENT
	(void)io_buffer;

	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;

	if (!ctx || ctx->ctx_is_svr)
		return;

	pfsd_iochannel_t *ch = NULL;
	memcpy(&ch, &buffer_meta, sizeof(buffer_meta));

	pfsd_request_t *req = (pfsd_request_t *)req_buffer;
	if (ch == NULL || req == NULL)
		return;

	(void)pfsd_shm_put_request(ch, req);
#endif
}

int
chnl_abort_shm(void *chnl_ctx, int32_t pid)
{
#ifdef PFSD_CLIENT
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;

	if (!ctx || ctx->ctx_is_svr)
		return -1;

	int conn_id = ctx->clt.shm_connect_id;
	for (int i = 0; i < PFSD_SHM_MAX; ++i) {
		pfsd_shm_t *shm = (pfsd_shm_t *)ctx->clt.shm_ptr[i];
		int total_aborts = pfsd_shm_cli_abort_request(shm, conn_id, pid);
		(void)total_aborts;
	}
#endif

	return 0;
}

void
chnl_update_meta_shm(void *chnl_ctx, long meta)
{
#ifdef PFSD_CLIENT
	chnl_ctx_shm_t *ctx = (chnl_ctx_shm_t *)chnl_ctx;

	if (!ctx || ctx->ctx_is_svr)
		return;

	PFSD_CLIENT_LOG("update mntid from %d to %d", ctx->clt.mntid, int(meta));
	ctx->clt.mntid = int(meta);
#endif
}


void pfsd_chnl_shm_client_init() {
}

PFSD_CHNL_REGISTER(_shm, shared_memory);
