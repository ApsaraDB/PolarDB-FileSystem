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

#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include "pfsd_common.h"
#include "pfsd_sdk.h"
#include "pfsd_sdk_file.h"

#define PFSD_MAX_NFD 102400

bool pfsd_writable(int flags)
{
	return (flags & MNTFLG_WR) != 0;
}


static char work_dir[PFS_MAX_PATHLEN];
static pthread_rwlock_t sdk_work_dir_rwlock;

static int fdtbl_free_last = -1;
static pfsd_file_t *fdtbl[PFSD_MAX_NFD];
static int fdtbl_nopen;
static pthread_mutex_t fdtbl_mtx;

static inline pfsd_file_t*
fd_to_file(int fd)
{
	//When the fd is never allocated or it is recycled, it is free.
	if ((fdtbl[fd] == NULL) || (((size_t)fdtbl[fd]) % 2 == 1))
		return NULL;
	return fdtbl[fd];
}

void pfsd_sdk_file_init()
{
	pthread_mutexattr_t attr;
	int err = pthread_mutexattr_init(&attr);
	pfsd_file_t *file = NULL;
	err |= pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
	err |= pthread_mutex_init(&fdtbl_mtx, &attr);
	err |= pthread_mutexattr_destroy(&attr);
	assert (err == 0);

	if (fdtbl_nopen != 0) {
		//This is atfork in subprocess or after umount in master process
		for (int i = 0; i < PFSD_MAX_NFD; ++i) {
			file = fd_to_file(i);
			if (file)
				pfsd_close_file(file);
		}
	}
	PFSD_ASSERT(fdtbl_nopen == 0);

	pthread_rwlock_init(&sdk_work_dir_rwlock, NULL);
}

pfsd_file_t *
pfsd_alloc_file()
{
	pfsd_file_t *f = PFSD_MALLOC(pfsd_file_t);
	if (f == NULL)
		return NULL;

	memset(f, 0, sizeof(pfsd_file_t));
	pthread_rwlock_init(&f->f_rwlock, NULL);
	f->f_fd = -1;
	f->f_inode = -1;
	return f;
}

void
pfsd_free_file(pfsd_file_t *f)
{
	if (f) {
		pthread_rwlock_destroy(&f->f_rwlock);
		PFSD_FREE(f);
	}
}

static inline int
fd_get_free(pfsd_file_t *file)
{
	int fd = -1;
	if (fdtbl_free_last < 0) {
		if (fdtbl_nopen < PFSD_MAX_NFD) {
			/*
			 * Pop from array
			 */
			fd = fdtbl_nopen;
			++fdtbl_nopen;
			fdtbl[fd] = file;
		}
	} else {
		/*
		 * Pop from the linked list with its head position at
		 * fdtbl_free_last.
		 * Attention (int)(((uint64_t)-1) / 2) == -1.
		 * So after the last element is popped, then
		 * fdtbl_free_last == -1.
		 */
		fd = fdtbl_free_last;
		fdtbl_free_last = (int)(((uint64_t)fdtbl[fdtbl_free_last]) / 2);
		++fdtbl_nopen;
		fdtbl[fd] = file;
	}
	return fd;
}

static inline void
fd_put_free(int fd)
{
	/*
	 * Push into the linked list with its head position changed to
	 * the input fd.
	 */
	fdtbl[fd] = (pfsd_file_t*)(size_t)(fdtbl_free_last * 2 + 1);
	fdtbl_free_last = fd;
	--fdtbl_nopen;
}

int
pfsd_alloc_fd(pfsd_file_t *file)
{
	file->f_fd = -1;

	pthread_mutex_lock(&fdtbl_mtx);
	file->f_fd = fd_get_free(file);
	pthread_mutex_unlock(&fdtbl_mtx);

	if (file->f_fd == -1)
		PFSD_CLIENT_ELOG("alloc fd failed");

	return file->f_fd;
}

pfsd_file_t*
pfsd_get_file(int fd, bool writelock)
{
	pfsd_file_t *file = NULL;

	pthread_mutex_lock(&fdtbl_mtx);
	if (0 <= fd && fd < PFSD_MAX_NFD)
		file = fd_to_file(fd);
	if (file)
		file->f_refcnt++;
	pthread_mutex_unlock(&fdtbl_mtx);

	if (file) {
		if (writelock)
			pthread_rwlock_wrlock(&file->f_rwlock);
		else
			pthread_rwlock_rdlock(&file->f_rwlock);
	} else {
		PFSD_CLIENT_ELOG("can't get file, fd %d", fd);
	}

	return file;
}

void
pfsd_put_file(pfsd_file_t *f)
{
	if (f) {
		pthread_rwlock_unlock(&f->f_rwlock);

		pthread_mutex_lock(&fdtbl_mtx);
		--f->f_refcnt;
		pthread_mutex_unlock(&fdtbl_mtx);
	}
}

int
pfsd_close_file(pfsd_file_t *f)
{
	if (!f)
		return -EINVAL;

	if (f->f_fd < 0 || f->f_fd >= PFSD_MAX_NFD)
		return -EBADF;

	int err = -EAGAIN;

	pthread_mutex_lock(&fdtbl_mtx);
	if (f->f_refcnt <= 1) {
		err = 0;
		fd_put_free(f->f_fd);
	}
	pthread_mutex_unlock(&fdtbl_mtx);
	if (err == 0)
		pfsd_free_file(f);

	return err;
}

static pthread_mutex_t pfsd_chdir_mtx = PTHREAD_MUTEX_INITIALIZER;

bool
pfsd_chdir_begin()
{
	return pthread_mutex_lock(&pfsd_chdir_mtx) == 0;
}

bool
pfsd_chdir_end()
{
	return pthread_mutex_unlock(&pfsd_chdir_mtx) == 0;
}

int
pfsd_dir_xgetwd(char *buf, size_t len)
{
	if (len > PFS_MAX_PATHLEN)
		len = PFS_MAX_PATHLEN;

	int err = 0;
	pthread_rwlock_rdlock(&sdk_work_dir_rwlock);
	if (work_dir[0] == '\0') {
		buf[0] = '\0';
		err = -ENOENT;
	} else {
		size_t wlen = strlen(work_dir);
		if (wlen >= len) {
			err = -ERANGE;
		} else {
			memcpy(buf, work_dir, wlen);
			buf[wlen] = '\0';
		}
	}
	pthread_rwlock_unlock(&sdk_work_dir_rwlock);

	return err;
}

int
pfsd_dir_xsetwd(const char *path, size_t len)
{
	int err = 0;

	if (len >= PFS_MAX_PATHLEN)
		return ENAMETOOLONG;

	pthread_rwlock_wrlock(&sdk_work_dir_rwlock);
	memcpy(work_dir, path, len);
	work_dir[len] = '\0';
	pthread_rwlock_unlock(&sdk_work_dir_rwlock);

	return err;
}

const char *
pfsd_name_init(const char *pbdpath, char *abspbdpath, size_t size)
{
	if (pbdpath == NULL) {
		errno = EINVAL;
		return NULL;
	}

	int err, n, wdlen;
	if (pbdpath[0] == '\0') {
		errno = EINVAL;
		return NULL;
	}

	memset(abspbdpath, 0, size);

	/*
	 * Make up a full path. For an absolute path, it is
	 * trivial. For a relative path, current work dir is
	 * added as the prefix.
	 */
	if (pbdpath[0] == '/') {
		/* absoulte path */
		n = snprintf(abspbdpath, size, "%s", pbdpath);
	} else {
		/* relative path */
		err = pfsd_dir_xgetwd(abspbdpath, size);
		if (err < 0)
			return NULL;

		wdlen = strlen(abspbdpath);
		n = snprintf(abspbdpath + wdlen, size - wdlen, "/%s", pbdpath);
		n += wdlen;
	}

	if (n >= int(size)) {
		errno = ENAMETOOLONG;
		return NULL;
	}

	assert (abspbdpath[0] == '/');
	return abspbdpath;
}

int
pfsd_normalize_path(char *pbdpath)
{
	if (!pbdpath || pbdpath[0] == '\0')
		return 0;

	int err = 0;
	int i;
	char *name = NULL;
	char *path, *savedptr = NULL;
	size_t maxnamelen = PFS_MAX_NAMELEN;
	char *dirs[PFS_MAX_PATHLEN];
	int ndirs = 0;
	char *tmp = strdup(pbdpath);

	for (path = tmp; ; path = NULL) {
		name = strtok_r(path, "/", &savedptr);
		if (name == NULL) {
			break;
		}

		if (strlen(name) >= maxnamelen) {
			err = -ENAMETOOLONG;
			break;
		}

		if (strcmp(name, "..") == 0) {
			if (ndirs > 1)
				--ndirs;
		} else if (strcmp(name, ".") == 0) {
			/* skip dot */
		} else if (name[0] != 0) {
			if (ndirs >= PFS_MAX_PATHLEN) {
				err = -ENAMETOOLONG;
				break;
			}

			dirs[ndirs] = name;
			++ndirs;
		}
	}

	if (err == 0) {
		assert (ndirs > 0);
		pbdpath[0] = 0;
		for (i = 0; i < ndirs; ++i) {
			strcat(pbdpath, "/");
			strcat(pbdpath, dirs[i]);
		}

		/* If /1-1, must be /1-1/ */
		if (ndirs == 1) {
			strcat(pbdpath, "/");
		}
	}

	free(tmp);
	return err;
}

void
pfsd_file_cleanup()
{
	//The function can not be protected within fdtbl_mtx because
	//it will be locked in pfsd_close_file.
	int ret = 0;
	pfsd_file_t *file;
	for (int i = 0; i < PFSD_MAX_NFD; ++i) {
		file = fd_to_file(i);
		if (file) {
			ret = pfsd_close_file(file);
			//We do not check whether ret is zero but warn.
			if (ret < 0)
				PFSD_CLIENT_ELOG("close fd %d err in cleanup, "
				     "error: %d", i, ret);
			else
				PFSD_CLIENT_ELOG("close fd %d in cleanup", i);
		}
	}
}
