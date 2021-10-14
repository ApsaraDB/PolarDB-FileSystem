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

#include "pfsd_sdk.h"
#include "pfs_mount.h"
#include "cmd_impl.h"

/* copy from pfs_api.h */
extern "C" {
/* functions both for file and directory */
int	pfs_rename(const char *oldpbdpath, const char *newpbdpath);

/* file */
int	pfs_creat(const char *pbdpath, mode_t mode);
int	pfs_open(const char *pbdpath, int flags, mode_t mode);
ssize_t	pfs_read(int fd, void *buf, size_t len);
ssize_t	pfs_write(int fd, const void *buf, size_t len);
ssize_t	pfs_pread(int fd, void *buf, size_t len, off_t offset);
ssize_t	pfs_pwrite(int fd, const void *buf, size_t len, off_t offset);
int	pfs_close(int fd);
int	pfs_truncate(const char *pbdpath, off_t len);
int	pfs_ftruncate(int fd, off_t len);
int	pfs_unlink(const char *pbdpath);
int	pfs_stat(const char *pbdpath, struct stat *buf);
int	pfs_fstat(int fd, struct stat *buf);
int	pfs_posix_fallocate(int fd, off_t offset, off_t len);
int	pfs_fallocate(int fd, int mode, off_t offset, off_t len);
off_t	pfs_lseek(int fd, off_t offset, int whence);

/* directory */
int	pfs_mkdir(const char *pbdpath, mode_t mode);
DIR	*pfs_opendir(const char *pbdpath);
struct dirent *pfs_readdir(DIR *dir);
int	pfs_readdir_r(DIR *dir, struct dirent *entry, struct dirent **result);
int	pfs_closedir(DIR *dir);
int	pfs_rmdir(const char *pbdpath);
int	pfs_chdir(const char *path);
char *pfs_getwd(char *buf);
char *pfs_getcwd(char *buf, size_t size);

int	pfs_access(const char *pbdpath, int amode);
}

/* in seconds */
int mount_timeout = 2;

static bool pfsd_mounted = false;

/* default: libpfs
 * Because cmd like cp, will not mount at first,
 * it also supports local disk.
 */
static void __attribute__((constructor))
init_pfs_vfs() {
	pfs.rename = pfs_rename;
	pfs.creat = pfs_creat;
	pfs.open = pfs_open;
	pfs.read = pfs_read;
	pfs.pread = pfs_pread;
	pfs.write = pfs_write;
	pfs.pwrite = pfs_pwrite;
	pfs.close = pfs_close;
	pfs.truncate = pfs_truncate;
	pfs.ftruncate = pfs_ftruncate;
	pfs.unlink = pfs_unlink;
	pfs.stat = pfs_stat;
	pfs.fstat = pfs_fstat;
	pfs.posix_fallocate = pfs_posix_fallocate;
	pfs.fallocate = pfs_fallocate;
	pfs.lseek = pfs_lseek;

	pfs.mkdir = pfs_mkdir;
	pfs.opendir = pfs_opendir;
	pfs.readdir = pfs_readdir;
	pfs.readdir_r = pfs_readdir_r;
	pfs.closedir = pfs_closedir;
	pfs.rmdir = pfs_rmdir;
	pfs.chdir = pfs_chdir;
	pfs.getwd = pfs_getwd;
	pfs.getcwd = pfs_getcwd;

	pfs.access = pfs_access;
}

static void init_pfsd_vfs() {
	pfs.rename = pfsd_rename;
	pfs.creat = pfsd_creat;
	pfs.open = pfsd_open;
	pfs.read = pfsd_read;
	pfs.pread = pfsd_pread;
	pfs.write = pfsd_write;
	pfs.pwrite = pfsd_pwrite;
	pfs.close = pfsd_close;
	pfs.truncate = pfsd_truncate;
	pfs.ftruncate = pfsd_ftruncate;
	pfs.unlink = pfsd_unlink;
	pfs.stat = pfsd_stat;
	pfs.fstat = pfsd_fstat;
	pfs.posix_fallocate = pfsd_posix_fallocate;
	pfs.fallocate = pfsd_fallocate;
	pfs.lseek = pfsd_lseek;

	pfs.mkdir = pfsd_mkdir;
	pfs.opendir = pfsd_opendir;
	pfs.readdir = pfsd_readdir;
	pfs.readdir_r = pfsd_readdir_r;
	pfs.closedir = pfsd_closedir;
	pfs.rmdir = pfsd_rmdir;
	pfs.chdir = pfsd_chdir;
	pfs.getwd = pfsd_getwd;
	pfs.getcwd = pfsd_getcwd;

	pfs.access = pfsd_access;
}

int pfs_mount_ex(const char* cluster, const char* pbdname, int hostid, int flags)
{
	int r;

	pfsd_set_mode(PFSD_SDK_THREADS);
	pfsd_set_connect_timeout(mount_timeout * 1000);

	r = pfsd_mount(cluster, pbdname, hostid, flags);
	if (r == 0) {
		pfsd_mounted = true;
		init_pfsd_vfs();
		return 0;
	} else {
		pfsd_mounted = false;
	}

	/* normal pfs_mount */
	init_pfs_vfs();
	return pfs_mount(cluster, pbdname, hostid, flags);
}

int pfs_umount_ex(const char* pbdname)
{
	if (pfsd_mounted) {
		return pfsd_umount(pbdname);
	}

	return pfs_umount(pbdname);
}

