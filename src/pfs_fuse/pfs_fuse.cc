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

#define FUSE_USE_VERSION 	29
#define	FUSE_CONF		((struct pfs_fuse_conf_t *) fuse_get_context()->private_data)

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <fuse.h>
#include <unistd.h>
#include <string.h>
#include "pfsd_sdk.h"

struct pfs_fuse_conf_t {
	char	*pbdname;
	char 	*flags;
	int 	conf;
};

static struct fuse_opt pfs_fuse_opt[] = {
	{ "--pbdname=%s",	offsetof(struct pfs_fuse_conf_t, pbdname),	0 },
	{ "--flags=%s",		offsetof(struct pfs_fuse_conf_t, flags),     0 },
	{ "--conf",		offsetof(struct pfs_fuse_conf_t, conf),	1 },
	FUSE_OPT_END
};

/* FUSE handlers */
static void *
fusepfs_init(struct fuse_conn_info *conn)
{
	int rv;
	if (strcmp(FUSE_CONF->flags, "rw")==0 || strcmp(FUSE_CONF->flags, "RW")==0)
		rv = pfsd_mount("disk", FUSE_CONF->pbdname, 0, PFS_RDWR);
	else if (strcmp(FUSE_CONF->flags, "ro")==0 || strcmp(FUSE_CONF->flags, "RO")==0)
		rv = pfsd_mount("disk", FUSE_CONF->pbdname, 0, PFS_RD);
	else
		rv = EINVAL;
	if (rv != 0)
		exit(-1);

	return FUSE_CONF;
}

static void
fusepfs_destroy(void *private_data)
{
	(void)pfsd_umount(FUSE_CONF->pbdname);
}

static int
fusepfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int fd;
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	fd = pfsd_creat(pbdpath, mode);
	if (fd < 0)
		return -errno;

	fi->fh = fd;
	return 0;
}

static int
fusepfs_open(const char *path, struct fuse_file_info *fi)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int fd;
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	fd = pfsd_open(pbdpath, fi->flags, S_IRWXU | S_IRWXG | S_IRWXO);
	if (fd < 0)
		return -errno;

	fi->fh = fd;
	return 0;
}

static int
fusepfs_rename(const char *path, const char *newpath)
{
	char pbdpath[PFS_MAX_PATHLEN];
	char newpbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = snprintf(newpbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, newpath);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_rename(pbdpath, newpbdpath);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_truncate(const char *path, off_t newsize)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_truncate(pbdpath, newsize);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_ftruncate(const char *path, off_t off, struct fuse_file_info *fi)
{
	int rv;

	rv = pfsd_ftruncate(fi->fh, off);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_mkdir(const char *path, mode_t mode)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_mkdir(pbdpath, mode);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_opendir(const char *path, struct fuse_file_info *fi)
{
	char pbdpath[PFS_MAX_PATHLEN];
	DIR *dp;
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	dp = pfsd_opendir(pbdpath);
	if (dp == NULL)
		return -errno;

	fi->fh = (intptr_t)dp;
	return 0;
}

static int
fusepfs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	dp = (DIR *) (uintptr_t) fi->fh;
	de = pfsd_readdir(dp);
	if (de == NULL)
		return -errno;

	do {
		if (filler(buffer, de->d_name, NULL, 0) != 0) {
			return -ENOMEM;
		}
	} while ((de = pfsd_readdir(dp)) != NULL);

	return 0;
}

static int
fusepfs_rmdir(const char *path)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_rmdir(pbdpath);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_readlink(const char *path, char *link, size_t size)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_readlink(pbdpath, link, size - 1);
	if (rv < 0)
		return -errno;

	link[rv] = '\0';
	return 0;
}

static int
fusepfs_unlink(const char *path)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_unlink(pbdpath);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_access(const char *path, int mask)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_access(pbdpath, mask);
	if (rv < 0)
		return -errno;

	return rv;
}

static int
fusepfs_getattr(const char *path, struct stat *st)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_stat(pbdpath, st);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_chmod(const char *path, mode_t mode)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_chmod(pbdpath, mode);;
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_chown(const char *path, uid_t uid, gid_t gid)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	rv = pfsd_chown(pbdpath, uid, gid);;
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_read(const char *path, char *buffer, size_t size, off_t off, struct fuse_file_info *fi)
{
	ssize_t rlen;

	rlen = pfsd_pread(fi->fh, buffer, size, off);
	if (rlen < 0)
		return -errno;

	return rlen;
}

static int
fusepfs_write(const char *path, const char *buffer, size_t size, off_t off, struct fuse_file_info *fi)
{
	ssize_t wlen;

	wlen = pfsd_pwrite(fi->fh, buffer, size, off);
	if (wlen < 0)
		return -errno;

	return wlen;
}

static int
fusepfs_fallocate(const char *path, int mode, off_t off, off_t length, struct fuse_file_info *fi)
{
	char pbdpath[PFS_MAX_PATHLEN];
	int file_mode = S_IRWXU | S_IRWXG | S_IRWXO;
	int fd, rv;

	rv = snprintf(pbdpath, PFS_MAX_PATHLEN, "/%s%s", FUSE_CONF->pbdname, path);
	if (rv >= PFS_MAX_PATHLEN)
		return -errno;

	if (fi == NULL) {
		fd = pfsd_open(pbdpath, O_RDWR, file_mode);
		if (fd < 0)
			return -errno;
	} else {
		fd = fi->fh;
		if (fd < 0)
			return -EINVAL;
	}

	rv = pfsd_fallocate(fd, mode, off, length);

	if (fi == NULL)
		(void)pfsd_close(fd);

	if (rv < 0)
		return -errno;

	return rv;
}

static int
fusepfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	int rv;

	rv = pfsd_fsync(fi->fh);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_release(const char *path, struct fuse_file_info *fi)
{
	int rv;

	rv = pfsd_close(fi->fh);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	int rv;

	rv = pfsd_closedir((DIR *) (uintptr_t) fi->fh);
	if (rv < 0)
		return -errno;

	return 0;
}

static int
fusepfs_utimens(const char *path, const struct timespec tv[2])
{
	return 0;
}

static int
fusepfs_utime(const char *, struct utimbuf *)
{
	return 0;
}

static struct fuse_operations fusepfs_operations = {

	.getattr            = fusepfs_getattr,      // Get file attr specified by filepath, like lstat()
	.readlink           = fusepfs_readlink,     // Read the target of a symbolic link
	.getdir             = NULL,
	.mknod              = NULL,                 // Create non-dir, non-symlink nodes, rarely needed
	.mkdir              = fusepfs_mkdir,        // Create a dir
	.unlink             = fusepfs_unlink,       // Remove a file
	.rmdir              = fusepfs_rmdir,        // Remove a file
	.symlink            = NULL,                 // Create a symbolic link
	.rename             = fusepfs_rename,       // Rename a file, dir, or other obj
	.link               = NULL,                 // Create a hard link
	.chmod              = fusepfs_chmod,        // Change the permission bits of a file
	.chown              = fusepfs_chown,        // Change the owner and group of a file
	.truncate           = fusepfs_truncate,
	.utime              = fusepfs_utime,
	.open               = fusepfs_open,
	.read               = fusepfs_read,         // Read data from an open file
	.write              = fusepfs_write,        // Write data to an open file
	.statfs             = NULL,                 // Get fs statistics
	.flush              = NULL,      	    // Possibly flush cached data (just flush the data, waiting for async finish)
	.release            = fusepfs_release,      // Release an open file, called when no reference to an open file, see close()
	.fsync              = fusepfs_fsync,        // Sync file contents to disk
	.setxattr           = NULL,
	.getxattr           = NULL,
	.listxattr          = NULL,
	.removexattr        = NULL,
	.opendir            = fusepfs_opendir,      // Open a dir, return fd
	.readdir            = fusepfs_readdir,      // Read a dir, iterate all entries of some dir, return info in buffer
	.releasedir         = fusepfs_releasedir,   // Release dir
	.fsyncdir           = NULL,                 // Sync dir contents
	.init               = fusepfs_init,         // Initialize fs, one-time setup like private_data. return private_data
	.destroy            = fusepfs_destroy,      // Clean up fs, paired with init
	.access             = fusepfs_access,       // Check file access permissions
	.create             = fusepfs_create,       // Create and open a file
	.ftruncate          = fusepfs_ftruncate,
	.fgetattr           = NULL,
	.lock               = NULL,                 // Perform POSIX file locking operation
	.utimens            = fusepfs_utimens,      // Change the access and modification times of a file with nanosecond resolution
	.bmap               = NULL,                 // Map block index within file to block index within device	/
	.flag_nullpath_ok   = 0,
	.flag_nopath        = 0,
	.flag_utime_omit_ok = 0,
	.flag_reserved      = 0,
	.ioctl              = NULL,                 // Ioctl
	.poll               = NULL,                 // Poll for IO readiness events
	.write_buf          = NULL,                 // Write contents of buffer to an open file
	.read_buf           = NULL,                 // Store data from an open file in a buffer
	.flock              = NULL,      	    // Perform BSD file locking operation
	.fallocate          = fusepfs_fallocate,    // Allocates space for an open file
};

static void
print_fuse_conf(struct pfs_fuse_conf_t *fuse_conf)
{
	fprintf(stdout, "****** CONFIG ******\n");
	fprintf(stdout, "\tpbdname:\t%s\n", fuse_conf->pbdname);
	fprintf(stdout, "\tflags:  \t%s\n", fuse_conf->flags);
	fprintf(stdout, "********************\n");
}

int
pfs_fuse_main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct pfs_fuse_conf_t fuse_conf;

	memset(&fuse_conf, 0, sizeof(fuse_conf));
	if (fuse_opt_parse(&args, &fuse_conf, pfs_fuse_opt, NULL) != 0){
		return 1;
	}

	fprintf(stdout, "starting fuse[%d] %s\n", getpid(), fuse_conf.pbdname);

	print_fuse_conf(&fuse_conf);

	/* Turn over control to fuse */
	return fuse_main(args.argc, args.argv, &fusepfs_operations, &fuse_conf);
}
