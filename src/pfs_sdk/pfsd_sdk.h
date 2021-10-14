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

#ifndef _PFSD_SDK_SHM_H_
#define _PFSD_SDK_SHM_H_

#include <dirent.h>
#include <stdint.h>
#include <sys/types.h>

/* copy from pfs_impl.h, just for lib user */
#define	PFS_OBJDATA_SIZE	(128 - 40)
#define	PFS_MAX_NAMELEN		256	/* max file name length,
					   include the last '\0' */
#define	PFS_MAX_PATHLEN		4096	/* max pbdpath length,
					   include the last '\0' */
#define	PFS_MAX_PBDLEN		64	/* max pbdname length,
					   include the last '\0' */

/* pfs permission flags */
/* NOTE: sync macros below with ones in pfs_mount.h */
#define	MNTFLG_RD		0x0001
#define	MNTFLG_WR		0x0002
#define	MNTFLG_LOG		0x0010
#define	MNTFLG_INITED		0x0100
#define	MNTFLG_TOOL		0x1000	/* Only pfstool will set this flag,
					   to get max hostid to instead itself */
#define MNTFLG_PAXOS_BYFORCE	0x200000	/* paxos acquired by force */

#define	PFS_RD			(MNTFLG_RD|MNTFLG_LOG)
#define	PFS_RDWR		(MNTFLG_RD|MNTFLG_WR|MNTFLG_LOG)
#define	PFS_TOOL		MNTFLG_TOOL
#define PFS_PAXOS_BYFORCE	MNTFLG_PAXOS_BYFORCE

#ifdef __cplusplus
extern "C" {
#endif

/* sdk side */
enum {
    PFSD_SDK_THREADS, /* multi threads */
    PFSD_SDK_PROCESS, /* multi process */
};

typedef struct __dirstream DIR;

/*
 * multi threads or multi process
 * DEPRECATED !!! DO NOT USE THIS FUNCTION
 **/
void pfsd_set_mode(int multi_thread_or_process);
/* this is the pid file directory, default /var/run/pfsd/ */
void pfsd_set_svr_addr(const char *svraddr, size_t len);
/* set connect timeout */
void pfsd_set_connect_timeout(int timeout_ms);

/* DEPRECATED !!! DO NOT USE THIS FUNCTION, USE pfsd_mount INSTEAD. */
int pfsd_sdk_init(int mode, const char *svraddr, int timeout_ms,
    const char *cluster, const char *pbdname, int hostid, int flags);

int pfsd_mount(const char *cluster, const char *pbdname, int hostid, int flags);
/* It'll return if all children process exit. */
int pfsd_umount(const char *pbdname);
/*
 * It'll return as soon as possible, must ensure that do NOT issue io after
 * umount.
 *
 **/
int pfsd_umount_force(const char *pbdname);

int pfsd_remount(const char *cluster, const char *pbdname, int hostid,
    int flags);

int pfsd_abort_request(pid_t pid);

int pfsd_mount_growfs(const char *pbdname);

/* functions both for file and directory */
int pfsd_rename(const char *oldpbdpath, const char *newpbdpath);

/* file */
int pfsd_creat(const char *pbdpath, mode_t mode);
int pfsd_open(const char *pbdpath, int flags, mode_t mode);

ssize_t pfsd_read(int fd, void *buf, size_t len);
ssize_t pfsd_write(int fd, const void *buf, size_t len);

ssize_t pfsd_pread(int fd, void *buf, size_t len, off_t off);
ssize_t pfsd_pwrite(int fd, const void *buf, size_t len, off_t off);

int pfsd_truncate(const char *pbdpath, off_t len);
int pfsd_ftruncate(int fd, off_t len);

int pfsd_unlink(const char *pbdpath);

int pfsd_stat(const char *pbdpath, struct stat *buf);
int pfsd_fstat(int fd, struct stat *buf);

int pfsd_posix_fallocate(int fd, off_t offset, off_t len);
int pfsd_fallocate(int fd, int mode, off_t offset, off_t len);
off_t pfsd_lseek(int fd, off_t offset, int whence);

int pfsd_close(int fd);

/* directory */
int pfsd_mkdir(const char *pbdpath, mode_t mode);
DIR *pfsd_opendir(const char *pbdpath);
struct dirent *pfsd_readdir(DIR *dir);
int pfsd_readdir_r(DIR *dir, struct dirent *entry, struct dirent **result);
int pfsd_closedir(DIR *dir);
int pfsd_rmdir(const char *pbdpath);
int pfsd_chdir(const char *path);
char *pfsd_getwd(char *buf);
char *pfsd_getcwd(char *buf, size_t size);

int pfsd_access(const char *pbdpath, int amode);

/* mock */
int pfsd_fsync(int fd);
ssize_t pfsd_readlink(const char *pbdpath, char *buf, size_t bufsize);
int pfsd_chmod(const char *pbdpath, mode_t mode);
int pfsd_fchmod(int fd, mode_t mode);
int pfsd_chown(const char *pbdpath, uid_t owner, gid_t group);

unsigned long pfsd_meta_version_get();
const char *pfsd_build_version_get();

#ifdef __cplusplus
}
#endif

/* ------------------------------------------------------------------- */

#define PFSD_FD_VALIDBIT  30

#define PFSD_FD_ISVALID(fd)                      \
        ( (fd) >= 0 && ( (unsigned int)(fd) & (1U << PFSD_FD_VALIDBIT) ) )

#define PFSD_FD_RAW(fd)                          \
        (int)((unsigned int)(fd) & ~(1U << PFSD_FD_VALIDBIT))

#define PFSD_FD_MAKE(fd)                     \
        (int)((unsigned int)(fd) | (1U << PFSD_FD_VALIDBIT))

#define PFSD_DIR_RAW(dir)                   \
    (DIR *)((uint64_t)(dir) & ~(uint64_t)(0x01))

#define PFSD_DIR_MAKE(dir)                 \
    (DIR *)((uint64_t)(dir) | (uint64_t)(0x01))

#define PFSD_PATH_ISVALID(path)                      \
        (path != NULL &&                        \
              ((path[0] == '/' && isdigit((path)[1])) || path[0] == '.'  \
                     || strncmp(path, "/pangu-", 7) == 0))

#define PFSD_DIR_ISVALID(dir)                        \
        ( (dir) && ( (intptr_t)(dir) & 0x01 ) )

#endif

