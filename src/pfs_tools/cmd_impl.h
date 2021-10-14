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

#ifndef	_CMD_IMPL_H_
#define	_CMD_IMPL_H_

#include <stdint.h>
#include <sys/types.h>
#include <dirent.h>

typedef struct opts_common {
	int		hostid;
	const char	*cluster;
	int		help;
	int		enable_pfsd;
} opts_common_t;

typedef struct opts_tail {
	opts_common_t   common;
	int             follow;
	int             nlines;         /* XXX not implemented yet */
} opts_tail_t;

typedef struct opts_read {
	opts_common_t   common;
	off_t           offset;
	ssize_t         length;
} opts_read_t;

typedef struct opts_write {
	opts_common_t   common;
	off_t           offset;
	ssize_t         length;
} opts_write_t;

typedef struct opts_fallocate {
	opts_common_t   common;
	off_t           offset;
	ssize_t         length;
} opts_fallocate_t;

typedef struct opts_ftruncate {
	opts_common_t   common;
	off_t           length;
} opts_ftruncate_t;

typedef struct opts_tree {
	opts_common_t   common;
	bool            verbose;        /* Show more details of files in cmd_tree */
} opts_tree_t;


typedef union 	cmd_opts {
	opts_common_t	co_common;
	char		co_opaque[4096];

	opts_read_t	co_read;
	opts_write_t 	co_write;
	opts_tail_t	co_tail;
	opts_fallocate_t co_fallocate;
	opts_ftruncate_t co_ftruncate;

	opts_tree_t	co_tree;
} cmd_opts_t;

typedef	int	cmd_entry_t(int argc, char *argv[], cmd_opts_t *co);
typedef	int	cmd_getopt_t(int argc, char *argv[], cmd_opts_t *co);
typedef	void	cmd_usage_t();

typedef struct 	cmd_info {
	const char	*cmd_name;
	const char	*cmd_desc;
	uint32_t	cmd_flags;
	uint32_t	cmd_mnt_flags;
#define	CMDF_MOUNT	0x0001
#define	CMDF_MOUNT_EX	0x0002
	cmd_getopt_t	*cmd_getopt;
	cmd_entry_t 	*cmd_entry;
	cmd_usage_t	*cmd_usage;
} cmd_info_t;

#define	PFSCMD_INFO(name, flags, mnt_flags, getopt_func, cmd_func, usage_func, desc)	\
static const cmd_info_t cmd_info_##name = 					\
{ 										\
	.cmd_name = #name, 							\
	.cmd_desc = desc,							\
	.cmd_flags = flags, 							\
	.cmd_mnt_flags = mnt_flags, 						\
	.cmd_getopt = getopt_func, 						\
	.cmd_entry = cmd_func, 							\
	.cmd_usage = usage_func,						\
}; 										\
static const cmd_info_t * cmd_info_##name##_ptr __attribute__((used))		\
__attribute__((section("_pfscmd"))) = &cmd_info_##name;				\
struct __hack

typedef struct pfs_chunk_phy pfs_chunk_phy_t;

void	pbdpath_copy(char *dst, const char *src, size_t len);
void	pbdpath_join(const char *pbdpath, const char *suffix,
	    char *buf, size_t buflen);
void	pbdpath_gen(const char *pbdname, const char *abspath,
	    char *buf, size_t len);
void	pbdpath_split(const char *pbdpath, char *pbdnamebuf,
	    size_t nbuflen, char *pathbuf, size_t pbuflen);

ssize_t	do_read(int rdfd, int wrfd, off_t offset, ssize_t length);
ssize_t	do_write(int rdfd, int wrfd, off_t offset, ssize_t length);
int     getopt_none(int argc, char *argv[], cmd_opts_t *co);
int	check_global_security(int iochd, const char *pbdname, uint32_t ckid,
	    bool force, const char *caller);
bool	chunk_isvalid(const pfs_chunk_phy_t *phyck, uint32_t ckid);

typedef struct vfs_mgr
{
    int (*rename)(const char *oldpath, const char *newpath);

    int (*creat)(const char *path, mode_t mode);
    int (*open)(const char *path, int flags, mode_t mode);
    ssize_t (*read)(int fd, void *buf, size_t len);
    ssize_t (*write)(int fd, const void *buf, size_t len);
    ssize_t (*pread)(int fd, void *buf, size_t len, off_t offset);
    ssize_t (*pwrite)(int fd, const void *buf, size_t len, off_t offset);
    int (*close)(int fd);
    int (*truncate)(const char *path, off_t len);
    int (*ftruncate)(int fd, off_t len);
    int (*unlink)(const char *path);
    int (*stat)(const char *path, struct stat *buf);
    int (*fstat)(int fd, struct stat *buf);
    int (*posix_fallocate)(int fd, off_t offset, off_t len);
    int (*fallocate)(int fd, int mode, off_t offset, off_t len);
    off_t (*lseek)(int fd, off_t offset, int whence);

    int (*mkdir)(const char *path, mode_t mode);
    DIR *(*opendir)(const char *path);
    struct dirent *(*readdir)(DIR *dir);
    int	(*readdir_r)(DIR *dir, struct dirent *entry, struct dirent **result);
    int (*closedir)(DIR *dir);
    int (*rmdir)(const char *path);
    int (*chdir)(const char *path);
    char* (*getwd)(char *buf);
    char* (*getcwd)(char *buf, size_t size);

    int (*access)(const char *path, int mode);
} vfs_mgr;

extern vfs_mgr pfs;

int	paxos_leader_reset(int devi, const char *pbdname);

typedef struct	user_action {
	void		*user_func;	/* the real function shall return int */
	uint32_t	user_nargs;
	int		user_arg0;
	int		user_arg1;
} user_action_t;

bool	not_wildcard(const char *pattern);
int	pbdpath_traverse(const char *pbdpath, const char *filter, const user_action_t *action);

/* How many target files that rm cmd can handle with.
 * eg. if you want use `rm a b c`, then PFS_MAX_BATCH_FILES
 * must be no less than 3.
 * For now, only support rm one target at a time.
 */
#define PFS_MAX_BATCH_FILES (1)

#endif	/* _CMD_IMPL_H_ */
