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

#ifndef	_PFS_API_H_
#define	_PFS_API_H_

#include <ctype.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <errno.h>

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

/* filesystem */
int	pfs_mount(const char *cluster, const char *pbdname, int host_id, int flags);
int	pfs_umount(const char *pbdname);
int	pfs_mount_growfs(const char *pbdname);

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
int	pfs_setxattr(const char *pbdpath, const char *name, const void *value,
	    size_t size, int flags);
int	pfs_mkstemp(char *tmpl);

/* directory */
int	pfs_mkdir(const char *pbdpath, mode_t mode);
DIR	*pfs_opendir(const char *pbdpath);
struct dirent *pfs_readdir(DIR *dir);
int	pfs_readdir_r(DIR *dir, struct dirent *entry, struct dirent **result);
int	pfs_closedir(DIR *dir);
int	pfs_rmdir(const char *pbdpath);
int 	pfs_chdir(const char *path);
char	*pfs_getwd(char *buf);
char	*pfs_getcwd(char *buf, size_t size);

int	pfs_access(const char *pbdpath, int amode);

/* mock */
int	pfs_fsync(int fd);
ssize_t pfs_readlink(const char *pbdpath, char *buf, size_t bufsize);
int	pfs_chmod(const char *pbdpath, mode_t mode);
int	pfs_fchmod(int fd, mode_t mode);
int	pfs_chown(const char *pbdpath, uid_t owner, gid_t group);

/* extension */
struct direntplus {
	struct dirent	dp_sysde;
	struct stat	dp_stat;
	uint32_t	dp_pvtid;
};
struct direntplus *pfs_readdirplus(DIR *dir);

/* file stream */
FILE   *pfs_fopen(const char *pbdpath, const char *mode);
int    pfs_fclose(FILE *stream);
int    pfs_fgetc(FILE *stream);
size_t pfs_fread(void *buf, size_t size, size_t nmemb, FILE *stream);
size_t pfs_fwrite(const void *buf, size_t size, size_t nmemb, FILE *stream);
int    pfs_fflush(FILE *stream);
void   pfs_rewind(FILE *stream);
int    pfs_fseek(FILE *stream, off_t offset, int whence);
off_t  pfs_ftell(FILE *stream);
int    pfs_feof(FILE *stream);
int    pfs_fileno(FILE *stream);
int    pfs_ferror(FILE *stream);

#ifdef __cplusplus
}
#endif

/* -------------------------------------------------------------------------- */

#define	PFS_FD_VALIDBIT		30

#define PFS_FD_ISVALID(fd)						\
	( (fd) >= 0 && ( (unsigned int)(fd) & (1U << PFS_FD_VALIDBIT) ) )

#define PFS_FD_RAW(fd)							\
	(int)((unsigned int)(fd) & ~(1U << PFS_FD_VALIDBIT))

#define PFS_PATH_ISVALID(path)						\
	(path != NULL &&						\
	 ((path[0] == '/' && isdigit((path)[1])) || path[0] == '.'	\
	  || strncmp(path, "/pangu-", 7) == 0				\
	  || strncmp(path, "/sd", 3) == 0				\
	  || strncmp(path, "/sf", 3) == 0				\
	  || strncmp(path, "/vd", 3) == 0				\
	  || strncmp(path, "/nvme", 5) == 0				\
	  || strncmp(path, "/loop", 5) == 0				\
	  || strncmp(path, "/mapper_", 8) ==0))

#define PFS_DIR_ISVALID(dir)						\
	( (dir) && ( (intptr_t)(dir) & 0x01 ) )

#define PFS_STRM_ISVALID(stream)					\
	( (stream) && ( (intptr_t)(stream) & 0x03 ) )

#define	MYSQL_CALL(type, func, arg1, ...) 	\
	( PFS_##type##_ISVALID((arg1)) 		\
	  ? pfs_##func(arg1, ##__VA_ARGS__) 	\
	  : func(arg1, ##__VA_ARGS__))

#define MYSQL_CALL_2(type, func, arg1, ...)	\
	( PFS_##type##_ISVALID((arg1))		\
	 ? pfs_##func(__VA_ARGS__, arg1)	\
	 : func(__VA_ARGS__, arg1))

#define MYSQLAPI_CREAT(path, mode)					\
	MYSQL_CALL(PATH, creat, path, mode)

#define MYSQLAPI_OPEN(path, flags, mode)				\
	MYSQL_CALL(PATH, open, path, flags, mode)

#define MYSQLAPI_READ(fd, buf, len)					\
	MYSQL_CALL(FD, read, fd, buf, len)

#define MYSQLAPI_WRITE(fd, buf, len)					\
	MYSQL_CALL(FD, write, fd, buf, len)

#define MYSQLAPI_PREAD(fd, buf, len, offset)				\
	MYSQL_CALL(FD, pread, fd, buf, len, offset)

#define MYSQLAPI_PWRITE(fd, buf, len, offset)				\
	MYSQL_CALL(FD, pwrite, fd, buf, len, offset)

#define MYSQLAPI_CLOSE(fd)						\
	MYSQL_CALL(FD, close, fd)

#define MYSQLAPI_TRUNCATE(path, len)					\
	MYSQL_CALL(PATH, truncate, path, len)

#define MYSQLAPI_FTRUNCATE(fd, len)					\
	MYSQL_CALL(FD, ftruncate, fd, len)

#define MYSQLAPI_UNLINK(path)						\
	MYSQL_CALL(PATH, unlink, path)

#define MYSQLAPI_STAT(path, buf)					\
	MYSQL_CALL(PATH, stat, path, buf)

#define MYSQLAPI_FSTAT(fd, buf)						\
	MYSQL_CALL(FD, fstat, fd, buf)

#define MYSQLAPI_POSIX_FALLOCATE(fd, offset, len)			\
	MYSQL_CALL(FD, posix_fallocate, fd, offset, len)

#define MYSQLAPI_FALLOCATE(fd, mode, offset, len)			\
	MYSQL_CALL(FD, fallocate, fd, mode, offset, len)

#define MYSQLAPI_LSEEK(fd, offset, whence)				\
	MYSQL_CALL(FD, lseek, fd, offset, whence)

#define MYSQLAPI_SETXATTR(path, name, value, size, flags)		\
	MYSQL_CALL(PATH, setxattr, path, name, value, size, flags)

#define MYSQLAPI_MKSTEMP(tmpl)						\
	pfs_mkstemp(tmpl)

#define MYSQLAPI_MKDIR(path, mode)					\
	MYSQL_CALL(PATH, mkdir, path, mode)

#define MYSQLAPI_OPENDIR(path)						\
	MYSQL_CALL(PATH, opendir, path)

#define MYSQLAPI_READDIR(dir)						\
	MYSQL_CALL(DIR, readdir, dir)

#define MYSQLAPI_READDIR_R(dir, entry, result)				\
	MYSQL_CALL(DIR, readdir_r, dir, entry, result)

#define MYSQLAPI_READDIRPLUS(dir)					\
	pfs_readdirplus(dir)

#define MYSQLAPI_CLOSEDIR(dir)						\
	MYSQL_CALL(DIR, closedir, dir)

#define MYSQLAPI_RMDIR(path)						\
	MYSQL_CALL(PATH, rmdir, path)

#define MYSQLAPI_RENAME(opath, npath)					\
	MYSQL_CALL(PATH, rename, opath, npath)

#define MYSQLAPI_CHDIR(path)						\
	pfs_chdir(path)

#define MYSQLAPI_GETWD(buf)						\
	pfs_getwd(buf)

#define MYSQLAPI_GETCWD(buf, size)					\
	pfs_getcwd(buf, size)

#define MYSQLAPI_ACCESS(path, amode)					\
	MYSQL_CALL(PATH, access, path, amode)

#define MYSQLAPI_FSYNC(fd)						\
	MYSQL_CALL(FD, fsync, fd)

#define MYSQLAPI_READLINK(path, buf, bufsize)				\
	MYSQL_CALL(PATH, readlink, path, buf, bufsize)

#define MYSQLAPI_CHMOD(path, mode)					\
	MYSQL_CALL(PATH, chmod, path, mode)

#define MYSQLAPI_FCHMOD(fd, mode)					\
	MYSQL_CALL(FD, fchmod, fd, mode)

#define MYSQLAPI_CHOWN(path, owner, group)				\
	MYSQL_CALL(PATH, chown, path, owner, group)

#define MYSQLAPI_FOPEN(path, mode)					\
	MYSQL_CALL(PATH, fopen, path, mode)

#define MYSQLAPI_FCLOSE(stream)						\
	MYSQL_CALL(STRM, fclose, stream)

#define MYSQLAPI_FGETC(stream)						\
	MYSQL_CALL(STRM, fgetc, stream)

#define MYSQLAPI_FREAD(buf, size, nmemb, stream)			\
	MYSQL_CALL_2(STRM, fread, stream, buf, size, nmemb)

#define MYSQLAPI_FWRITE(buf, size, nmemb, stream)			\
	MYSQL_CALL_2(STRM, fwrite, stream, buf, size, nmemb)

#define MYSQLAPI_FFLUSH(stream)						\
	MYSQL_CALL(STRM, fflush, stream)

#define MYSQLAPI_REWIND(stream)						\
	MYSQL_CALL(STRM, rewind, stream)

#define MYSQLAPI_FSEEK(stream, offset, whence)				\
	MYSQL_CALL(STRM, fseek, stream, offset, whence)

#define MYSQLAPI_FTELL(stream)						\
	MYSQL_CALL(STRM, ftell, stream)

#define MYSQLAPI_FEOF(stream)						\
	MYSQL_CALL(STRM, feof, stream)

#define MYSQLAPI_FILENO(stream)						\
	MYSQL_CALL(STRM, fileno, stream)

#define MYSQLAPI_FERROR(stream)						\
	MYSQL_CALL(STRM, ferror, stream)

// Errno
enum PFSErrCode {
	// File
	EPFS_FILE_BASE = 1000,
	EPFS_FILE_2MANY,	/* pfs limit on the total number of
				   files has been reached */
};


#ifdef __cplusplus
extern "C" {
#endif

typedef struct pfs_chunkstream_desc	pfs_chunkstream_desc_t;
typedef struct pfs_chunkstream		pfs_chunkstream_t;

#define	CHUNK_BACKUP		0x0001
#define	CHUNK_RESTORE		0x0002
#define	CHUNK_CRC		0x0010

/**
 * @description:	init meta， only need to be called once
 * @param cluster：	polarstore/disk/river, NULL means polarstore
 * @param flags:	CHUNK_BACKUP CHUNK_RESTORE CHUNK_BACKUP|CHUNK_CRC 
 * @return: 		return pfs_chunkstream_desc_t if success, 
 * 			otherwise return NULL
 */
pfs_chunkstream_desc_t *
	pfs_chunkstream_init(const char *cluster, const char *pbdname, int flags); 

pfs_chunkstream_t *
	pfs_chunkstream_open(const pfs_chunkstream_desc_t *desc, int chunkid);
/**
 * @description:	read data from pbd
 * @param buf:		data buf 
 * @param len:		must be 4K aligned
 * @return:		on success, the number of bytes read is returned
 * 			on error, negative errno is returned
 */
int64_t	pfs_chunkstream_read(pfs_chunkstream_t *stream, char *buf, size_t len);
/**
 * @description:	write data to pbd
 * @param len:		must be 4K aligned
 * @return:		on success, the number of bytes write is returned
 * 			on error, negative errno is returned
 */
int64_t	pfs_chunkstream_write(pfs_chunkstream_t *stream, const char *buf,
	    size_t len);
int	pfs_chunkstream_close(pfs_chunkstream_t *stream);
int	pfs_chunkstream_fini(pfs_chunkstream_desc_t *desc); 
/**
 * @description:	stream is finish
 * @return:		return 0 if stream is finish
 */
int	pfs_chunkstream_isfinish(pfs_chunkstream_t *stream);

/**
 * @description:	get pbd chunk num, used in backup mode
 */
void	pfs_chunkstream_get_nchunk(const pfs_chunkstream_desc_t *desc, 
	    int *nchunk);

#ifdef __cplusplus
}
#endif

#endif	/* _PFS_API_H_ */
