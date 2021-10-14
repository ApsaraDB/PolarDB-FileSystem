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

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <getopt.h>

#include "pfs_api.h"
#include "pfs_mount.h"
#include "pfs_util.h"
#include "pfs_trace.h"
#include "pfs_namei.h"

#include "cmd_impl.h"

vfs_mgr pfs;

extern char pfs_build_version[];

#define SHOWREADINFO 	0 /* when caculate file's md5, this should be set to 0*/

extern int mount_timeout;
int pfs_mount_ex(const char* cluster, const char* pbdname, int hostid, int flags);
int pfs_umount_ex(const char* pbdname);

#define	BUF_SIZE 	PFS_BLOCK_SIZE
char			cmd_buf[BUF_SIZE];

cmd_entry_t		cmd_help;

cmd_entry_t		cmd_create;
cmd_entry_t		cmd_remove;
cmd_entry_t		cmd_stat;
cmd_entry_t		cmd_read;
cmd_entry_t		cmd_write;
cmd_entry_t		cmd_falloc;
cmd_entry_t		cmd_tail;
cmd_entry_t		cmd_truncate;

cmd_entry_t		cmd_rmdir;
cmd_entry_t		cmd_ls;
cmd_entry_t		cmd_tree;

cmd_getopt_t		getopt_none;
cmd_getopt_t		getopt_rw;
cmd_getopt_t		getopt_tail;
cmd_getopt_t		getopt_tree;
cmd_getopt_t		getopt_truncate;

cmd_usage_t 		usage_touch,
			usage_stat,
			usage_read,
			usage_write,
			usage_falloc,
			usage_tail,
			usage_doom,
			usage_truncate,
			usage_rmdir,
			usage_ls,
			usage_tree;

/* file commands */
PFSCMD_INFO(touch, CMDF_MOUNT_EX,	PFS_RDWR,
	    getopt_none, cmd_create, usage_touch,
	    "create file");
PFSCMD_INFO(stat, CMDF_MOUNT_EX, PFS_RD,
	    getopt_none, cmd_stat, usage_stat,
	    "show file info");
PFSCMD_INFO(read, CMDF_MOUNT_EX, PFS_RD,
	    getopt_rw,	cmd_read, usage_read,
	    "read file");
PFSCMD_INFO(write, CMDF_MOUNT_EX, PFS_RDWR,
	    getopt_rw, cmd_write, usage_write,
	    "write file");
PFSCMD_INFO(fallocate, CMDF_MOUNT_EX, PFS_RDWR,
	    getopt_rw, cmd_falloc, usage_falloc,
	    "allocate block for file");
PFSCMD_INFO(tail, CMDF_MOUNT_EX, PFS_RD,
	    getopt_tail, cmd_tail, usage_tail,
	    "read file tail incessantly");
PFSCMD_INFO(truncate, CMDF_MOUNT_EX, PFS_RDWR,
	    getopt_truncate, cmd_truncate, usage_truncate,
	    "truncate file");

/* dir commands */
PFSCMD_INFO(rmdir, CMDF_MOUNT_EX, PFS_RDWR,
	    getopt_none, cmd_rmdir, usage_rmdir,
	    "remove an empty directory");
PFSCMD_INFO(ls, CMDF_MOUNT_EX, PFS_RD,
	    getopt_none, cmd_ls, usage_ls,
	    "list all direntries in this directory");
PFSCMD_INFO(tree, CMDF_MOUNT_EX, PFS_RD,
	    getopt_tree, cmd_tree, usage_tree,
	    "list all files in this dir and its subdirs");

void
usage()
{
	extern const cmd_info_t *__start__pfscmd[];
	extern const cmd_info_t *__stop__pfscmd[];
	const cmd_info_t **ci;

	printf("Usage: pfs [-H hostid] [-C|--cluster=clustername] [-t pfsd_timeout] <command> [options] pbdpaths""\n"
	    "pfs has following commands\n");

	for (ci = __start__pfscmd; ci != __stop__pfscmd; ci++) {
		printf("  %-*s %s\n", 10, (*ci)->cmd_name, (*ci)->cmd_desc);
	}

	printf("\npfs version: %s\n", pfs_build_version);
	exit(1);
}

/* filesystem */
PFSCMD_INFO(help, 	0,		0,	getopt_none,	cmd_help,	usage,	"show help info");

void
usage_tail()
{
	printf(
	    "  tail file"						"\n"
	    "  $ pfs tail /1/mydir/newfile"				"\n");
}

void
usage_doom()
{
	printf(
	    "  doom file"						"\n"
	    "  $ pfs doom /1/newfile"					"\n");
}

void
usage_touch()
{
	printf(
	    "  create file"						"\n"
	    "  $ pfs touch /1/mydir/newfile"				"\n");
}

void
usage_read()
{
	printf(
	    "pfs read file"						"\n"
    	    "  $ pfs read /1/mydir/myfile"				"\n"
	      								"\n"
	    "  $ pfs read -o 100 -l 20 /1/mydir/myfile"			"\n");
}

void
usage_write()
{
	printf(
	    "  write file"						"\n"
    	    "  $ echo 'Hello, world' | pfs write /1/mydir/myfile"	"\n"
	    								"\n"
	    "  $ cat somefile.txt | pfs write -o 0 -l 300 /1/mydir/myfile""\n");
}

void
usage_truncate()
{
	printf(
	    "  truncate file"                                    	"\n"
	    "  $ pfs truncate -l 20 /1/mydir/myfile"			"\n");
}

void
usage_falloc()
{
	printf(
	    "  fallocate file"						"\n"
	    "  $ pfs fallocate -o 0 -l 1024 /1/mydir/file"		"\n");
}

void
usage_stat()
{
	printf(
	    "  file status"						"\n"
	    "  $ pfs stat /1/mydir/myfile"				"\n");
}

void
usage_rmdir()
{
	printf(
	    "  delete directory"                                        "\n"
	    "  $ pfs rmdir /1/mydir"                                	"\n");
}

void
usage_ls()
{
	printf(
	    "  ls directory"                                            "\n"
	    "  $ pfs ls /1/mydir"                                   	"\n");
}

void
usage_tree()
{
	printf(
	    "  show directory tree"                                     "\n"
	    "  $ pfs tree /1/mydir"                                 	"\n");
}

static struct option long_opts_common[] = {
	{ "help",	optional_argument,	NULL,	'h' },
	{ "hostid",	required_argument,	NULL,	'H' },
	{ "cluster",	required_argument,	NULL,	'C' },
	{ "enable_pfsd", required_argument,	NULL,	'E' },
	{ 0 },
};

int
getopt_common(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;

	co->co_common.hostid = 0;
	co->co_common.cluster = CL_DEFAULT;
	co->co_common.enable_pfsd = 1;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hH:C:t:E:", long_opts_common,
	    NULL)) != -1) {
		switch (opt) {
		case 'H':
			co->co_common.hostid = atoi(optarg);
			if (co->co_common.hostid >= 128) {
				fprintf(stderr, "too large hostid\n");
				usage();
			}
			break;

		case 'C':
			co->co_common.cluster = optarg;
			break;

		case 't':
			mount_timeout = atoi(optarg);
			break;

		case 'E':
			co->co_common.enable_pfsd = atoi(optarg);
			break;

		case 'h':
		default:
			usage();
			return -1;
		}
	}
	return optind;
}

int
getopt_none(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;

	optind = 1; 	/* skip the command name */
	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

int
getopt_rw(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;

	co->co_read.offset = 0;
	co->co_read.length = -1;

	optind = 1;
	while ((opt = getopt(argc, argv, "ho:l:")) != -1) {
		switch (opt) {
		case 'o':
			co->co_read.offset = strtoull(optarg, NULL, 0);
			break;

		case 'l':
			co->co_read.length = strtoull(optarg, NULL, 0);
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

int
getopt_tail(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;
	opts_tail_t *co_tail = (opts_tail_t *)co;

	optind = 1;
	while ((opt = getopt(argc, argv, "hfn:")) != -1) {
		switch (opt) {
		case 'f':
			co_tail->follow = true;
			break;

		case 'n':
			co_tail->nlines = strtol(optarg, NULL, 0);
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

int
getopt_tree(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;

	co->co_tree.verbose = false;
	for (optind = 1; (opt = getopt(argc, argv, "hv")) != -1;) {
		switch (opt) {
		case 'v':
			co->co_tree.verbose = true;
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

int
getopt_truncate(int argc, char *argv[], cmd_opts_t *co)
{
	int opt;

	co->co_ftruncate.length = -1;
	for (optind = 1; (opt = getopt(argc, argv, "hl:")) != -1;) {
		switch (opt) {
		case 'l':
			co->co_ftruncate.length = strtol(optarg, NULL, 0);
			break;

		case 'h':
		default:
			return -1;
		}
	}
	return optind;
}

const cmd_info_t *
cmd_find(const char *cmdname)
{
	extern const cmd_info_t *__start__pfscmd[];
	extern const cmd_info_t *__stop__pfscmd[];
	const cmd_info_t **cipp;

	for (cipp = __start__pfscmd; cipp < __stop__pfscmd; cipp++) {
		//printf("cmd %s\n", (*cipp)->cmd_name);
		if (strcmp((*cipp)->cmd_name, cmdname) == 0)
			return *cipp;
	}
	return &cmd_info_help;
}

/* ARGSUSED */
int
cmd_help(int argc, char *arv[], cmd_opts_t *co)
{
	usage();
	return 1;
}

int
cmd_create(int argc, char *argv[], cmd_opts_t *co)
{
	int fd;
	char pbdpath[PFS_MAX_PATHLEN];

	if (argc != 1)
		return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	fd = pfs.open(pbdpath, O_CREAT, 0);
	if (fd < 0)
		return -1;

	pfs.close(fd);
	return 0;
}

ssize_t
do_read(int rdfd, int wrfd, off_t offset, ssize_t length)
{
	off_t orig_offset = offset;
	ssize_t n, nrd, nwr, left;

	left = length;
	for (nrd = 0; length < 0 || (left -= nrd) > 0; offset += nrd) {
		if (length < 0 || left > BUF_SIZE)
			nrd = BUF_SIZE;
		else
			nrd = left;

		if (PFS_FD_ISVALID(rdfd))
			nrd = pfs.pread(rdfd, cmd_buf, nrd, offset);
		else
			nrd = MYSQLAPI_PREAD(rdfd, cmd_buf, nrd, offset);

		if (nrd < 0)
			return -1;
		if (nrd == 0)
			break;
		for (n = 0; n < nrd; n += nwr) {
			if (PFS_FD_ISVALID(wrfd))
				nwr = pfs.write(wrfd, cmd_buf + n, nrd - n);
			else
				nwr = MYSQLAPI_WRITE(wrfd, cmd_buf + n, nrd - n);
			if (nwr < 0 && (errno == EAGAIN || errno == EINTR)) {
				nwr = 0;
				continue;
			}
			if (nwr < 0)
				return -1;
		}
	}
	return offset - orig_offset;
}

int
cmd_read(int argc, char *argv[], cmd_opts_t *co)
{
	int err, fd;
	char pbdpath[PFS_MAX_PATHLEN];
	ssize_t nrd;

	if (argc != 1)
		return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	fd = pfs.open(pbdpath, 0, 0);
	if (fd < 0)
		return -1;

	nrd = do_read(fd, STDOUT_FILENO, co->co_read.offset, co->co_read.length);
	err = nrd >= 0 ? 0 : -1;

	pfs.close(fd);
	return err;
}

ssize_t
do_write(int rdfd, int wrfd, off_t offset, ssize_t length)
{
	off_t orig_offset = offset;
	ssize_t nrd, nwr, left;

	left = length;
	for (nwr = 0; length < 0 || (left -= nwr) > 0; offset += nwr) {
		if (length < 0 || left > BUF_SIZE)
			nrd = BUF_SIZE;
		else
			nrd = left;

		if (PFS_FD_ISVALID(rdfd))
			nrd = pfs.read(rdfd, cmd_buf, nrd);
		else
			nrd = MYSQLAPI_READ(rdfd, cmd_buf, nrd);

		if (nrd == 0)
			break;
		if (nrd < 0 && (errno == EAGAIN || errno == EINTR)) {
			nwr = 0;
			continue;
		}
		if (nrd < 0)
			return -1;

		if (PFS_FD_ISVALID(wrfd))
			nwr = pfs.pwrite(wrfd, cmd_buf, nrd, offset);
		else
			nwr = MYSQLAPI_PWRITE(wrfd, cmd_buf, nrd, offset);
		if (nwr < 0)
			return -1;
	}
	return offset - orig_offset;
}

int
cmd_write(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];
	int fd;
	ssize_t nwr;

	if (argc != 1)
	       return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	fd = pfs.open(pbdpath, O_CREAT, 0);
	if (fd < 0)
		return -1;

	nwr = do_write(STDIN_FILENO, fd, co->co_write.offset, co->co_write.length);
	err = nwr >= 0 ? 0 : -1;

	if (err == 0) {
		printf("\033[40;32m[   OK   ]\033[0m Write %lu offset,"
		    " %zd bytes to file %s\n",
		    co->co_write.offset, nwr, pbdpath);
	} else {
		printf("\033[40;31m[  FAIL  ]\033[0m Write %lu offset,"
		    " %zd bytes to file %s, errinfo=%s\n",
		    co->co_write.offset, co->co_write.length, pbdpath,
		    strerror(errno));
	}

	pfs.close(fd);
	return err;
}

int
cmd_stat(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];
	struct stat st;

	if (argc != 1)
		return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	err = pfs.stat(pbdpath, &st);
	if (err < 0)
		return -1;

	if (st.st_mode & S_IFREG)
		printf("  file: %s\n", pbdpath);
	else if (st.st_mode & S_IFDIR)
		printf("   dir: %s\n", pbdpath);
	else
		printf("unknown: %s\n", pbdpath);
	printf("  size: %-15lu\tblocks: %lu\n", st.st_size, st.st_blocks);
	printf("device: pbd-%lu\t\tinode: %lu links: %lu\n", st.st_dev,
	       st.st_ino, (long unsigned int)st.st_nlink);
	printf("access: %lu, %s", st.st_atime, ctime(&st.st_atime));
	printf("modify: %lu, %s", st.st_mtime, ctime(&st.st_mtime));
	printf("change: %lu, %s", st.st_ctime, ctime(&st.st_ctime));

	return 0;
}

int
cmd_truncate(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];

	if (argc != 1)
	       return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	err = pfs.truncate(pbdpath, co->co_ftruncate.length);
	err = err < 0 ? -1 : 0;
	return err;
}

int
cmd_falloc(int argc, char *argv[], cmd_opts_t *co) //const char* pbdpath, off_t offset, size_t len)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];
	int fd;
	off_t offset;
	ssize_t length;

	offset = co->co_fallocate.offset;
	length = co->co_fallocate.length;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	fd = pfs.open(pbdpath, 0, 0);
	if (fd < 0)
		return -1;

	err = pfs.posix_fallocate(fd, offset, length);
	err = err < 0 ? -1 : 0;

	pfs.close(fd);
	return err;
}

int
cmd_remove(int argc, char *argv[], cmd_opts_t *co) //const char* pbdpath)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];

	if (argc != 1)
		return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	err = pfs.unlink(pbdpath);
	if (err < 0)
		return -1;

	return 0;
}

int
cmd_tail(int argc, char *argv[], cmd_opts *co)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];
	int fd;
	struct stat oldst, newst;
	ssize_t nrd;

	if (argc != 1)
	       return -1;
	memset(&oldst, 0, sizeof(oldst));
	memset(&newst, 0, sizeof(newst));

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));

	fd = pfs.open(pbdpath, 0, 0);
	if (fd < 0)
		return -1;

	err = pfs.fstat(fd, &oldst);
	if (err < 0) {
		pfs.close(fd);
		return err;
	}

	for (;;) {
		err = pfs.fstat(fd, &newst);
		if (err < 0) {
			pfs.close(fd);
			return err;
		}

		if (newst.st_size == oldst.st_size) {
			sleep(1);
			continue;
		}
		nrd = do_read(fd, STDOUT_FILENO, oldst.st_size,
		    (ssize_t)(newst.st_size - oldst.st_size));
		if (nrd >= 0)
			oldst = newst;
	}
	pfs.close(fd);
	return 0;
}

int
cmd_rmdir(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];

	if (argc != 1)
	       return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));
	err = pfs.rmdir(pbdpath);
	if (err < 0)
	       return -1;

	return 0;
}

char *
rmlastchar(char *datestr)
{
	if (!datestr)
		return NULL;

	int len = strlen(datestr);
	*(datestr + len - 1) = '\0';
	return datestr;
}

int
cmd_ls(int argc, char *argv[], cmd_opts_t *co) //const char* pbdpath)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];
	char filepath[PFS_MAX_PATHLEN];
	struct dirent *de;
	struct dirent debuf;
	DIR *dir;
	uint64_t total_blks = 0;	// total blks(512B) of files in this dir
	struct stat st;

	if (argc != 1)
	       return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));

	dir = pfs.opendir(pbdpath);
	if (dir == NULL)
	       return -1;

	while ((err = pfs.readdir_r(dir, &debuf, &de)) == 0 && de) {
		PFS_ASSERT(de->d_name[0] != '\0');
		// Get file fullpath
		pbdpath_join(pbdpath, de->d_name, filepath, sizeof(filepath));

		// Get file status
		err = pfs.stat(filepath, &st);
		if (err < 0)
			break;

		if (st.st_mode & S_IFREG)
			printf("  File  ");
		else if (st.st_mode & S_IFDIR)
			printf("   Dir  ");
		else
			printf("Unknown  ");

		printf("%-4lu  %-16lu  %s  %s\n", (long unsigned int)st.st_nlink, st.st_size,
			rmlastchar(ctime(&st.st_mtime)), de->d_name);

		total_blks += st.st_blocks;
	}
	if (err == 0)
		printf("total %lu (unit: 512Bytes)\n", total_blks);

	pfs.closedir(dir);

	err = err < 0 ? -1 : 0;
	return err;
}

int
read_dir(const char *pbdpath, bool verbose, int lvl)
{
	int err;
	char newpath[PFS_MAX_PATHLEN];
	int pathlen, nprint;
	DIR *dir;
	struct dirent *de;
	struct dirent debuf;
	struct stat st;
	static uint32_t ndir, nfile;

	nprint = snprintf(newpath, sizeof(newpath), "%s", pbdpath);
	if (nprint >= (int)sizeof(newpath)) {
		pfs_etrace("too long pbd path %s\n", pbdpath);
		return -1;
	}

	pathlen = strlen(pbdpath);
	if (newpath[pathlen - 1] == '/') {	/* strip off tail '/' */
		newpath[pathlen - 1] = '\0';
		pathlen--;
	}
	if (pathlen >= (int)sizeof(newpath))
		return -ENAMETOOLONG;

	dir = pfs.opendir(pbdpath);
	if (dir == NULL)
	       return -1;

	if (verbose == true && lvl == 0)
		printf("name\t\t\ttype\tinode\t\tsize\t\t\tctime\t\t\t\tmtime\n");

	while ((err = pfs.readdir_r(dir, &debuf, &de)) == 0 && de) {
		PFS_ASSERT(de->d_name[0] != '\0');

		nprint = snprintf(&newpath[pathlen], sizeof(newpath)-pathlen,
		    "/%s", de->d_name);
		if (nprint >= (int)sizeof(newpath) - pathlen) {
			err = -ENAMETOOLONG;
			break;
		}

		printf("%*s", lvl, "");
		err = pfs.stat(newpath, &st);
		if (err < 0)
			break;
		if (verbose == true) {
			printf("|-%-20s\t%s\t%-10lu\t%-20ld\t%s\t%s\n",
			    de->d_name,
			    (st.st_mode & S_IFREG) ?
			        "File" : (st.st_mode & S_IFDIR) ?
				"Dir" :
				"Unknown",
			    de->d_ino, st.st_size,
			    rmlastchar(ctime(&st.st_ctime)),
			    rmlastchar(ctime(&st.st_mtime)));
		} else {
			printf("|-%s\n", de->d_name);
		}

		if (st.st_mode & S_IFDIR) {
			ndir++;
			err = read_dir(newpath, verbose, lvl + 1);
			if (err < 0)
				break;
		} else {
			nfile++;
		}
	}

	if (err == 0 && lvl == 0)
		printf("\n%u directories, %u files\n", ndir, nfile);

	pfs.closedir(dir);

	err = err < 0 ? -1 : 0;
	return err;
}

int
cmd_tree(int argc, char *argv[], cmd_opts_t *co)
{
	int err;
	char pbdpath[PFS_MAX_PATHLEN];

	if (argc != 1)
	       return -1;

	pbdpath_copy(pbdpath, argv[0], sizeof(pbdpath));

	err = read_dir(pbdpath, co->co_tree.verbose, 0);
	if (err < 0)
	       return -1;

	return 0;
}

static void proc_info_record(int argc, char *argv[]) {
	int stack_depth = 16;
	//1. record the cmd.
	fprintf(stderr, "pfs tool cmd record:");
	while (argc > 0) {
		fprintf(stderr, "%s ", *argv);
		++argv;
		--argc;
	}
	fprintf(stderr, "\n");

	//2. record the pfs version.
	pfs_itrace("pfs build version:%s\n", pfs_build_version);

	//3. record the process caller stack. pid==1 is init process.
	for (pid_t pid = getppid(); pid > 1 && stack_depth > 0; --stack_depth) {
		char content_buffer[3 * PFS_MAX_PATHLEN];
		char path_buffer[3 * PFS_MAX_PATHLEN];
		FILE* f;
		size_t size;
		char* cursor;

		snprintf(path_buffer, sizeof(path_buffer), "/proc/%d/cmdline",
		    pid);
		f = fopen(path_buffer, "r");
		if (f == NULL) {
			break;
		}
		size = fread(content_buffer, sizeof(char),
		    sizeof(content_buffer) - 1, f);
		fclose(f);
		if (size > 0) {
			content_buffer[size] = '\0';
		} else {
			break;
		}
		for (cursor = content_buffer; cursor < content_buffer + size;
		    ++cursor) {
			if (*cursor == '\0') {
				*cursor = ' ';
			}
		}
		pfs_itrace("pid: %d, caller: %s \n", pid, content_buffer);

		snprintf(path_buffer, sizeof(path_buffer),
		    "/proc/%d/stat", pid);
		f = fopen(path_buffer, "r");
		if (f == NULL) {
			break;
		}
		size = fread(content_buffer, sizeof(char),
		    sizeof(content_buffer) - 1, f);
		fclose(f);
		if (size > 0) {
			cursor = content_buffer;
			cursor[size] = '\0';
			// (1) pid  %d
			cursor = strchr(cursor, ' ');
			if (cursor == NULL) {
				break;
			}
			// (2) cmd  %s
			cursor = strchr(cursor + 1, ' ');
			if (cursor == NULL) {
				break;
			}
			// (3) state  %c
			cursor = strchr(cursor + 1, ' ');
			if (cursor == NULL) {
				break;
			}
			// (4) ppid  %d
			pid = atoi(cursor + 1);
		} else {
			break;
		}
	}
}

int
main(int argc, char *argv[])
{
	int err = 0;
	const char *inputpath;
	char pbdpath[PFS_MAX_PATHLEN] = {'\0'};
	char pbdname[PFS_MAX_PBDLEN] = {'\0'};
	char path[PFS_MAX_PATHLEN] = {'\0'};
	const cmd_info_t *ci;
	cmd_opts_t co;

	/* initialize */
	memset(pbdpath, 0, sizeof(pbdpath));
	memset(pbdname, 0, sizeof(pbdname));
	memset(path, 0, sizeof(path));
	memset(&co, 0, sizeof(co));

	/*
	 * pfs [-H hostid] [-C|--cluster clustername] command [options] pbdpath ...
	 */
	if (argc < 3)
		usage();

	optind = getopt_common(argc, argv, &co);
	if (optind < 0)
	       return -1;
	argc -= optind;
	argv += optind;

	/*
	 * The remaining should be of the form
	 * 'command [options] pbdpath ...'.
	 */
	if (argc < 2)
		usage();

	ci = cmd_find(argv[0]);
	optind = (*ci->cmd_getopt)(argc, argv, &co);
	if (optind < 0) {
		(*ci->cmd_usage)();
		return -1;
	}
	argc -= optind;
	argv += optind;

	/*
	 * Now the remaining arguments should be of the form
	 * 'pbdpath ...'
	 */
	if (argc < 1) {
		(*ci->cmd_usage)();
		return -1;
	}

	/*
	 * The argv[0] may be not a pbdpath, and the pdbname may be
	 * invalid. In that case, pfs_mount will complain.
	 */
	if (ci->cmd_flags & (CMDF_MOUNT|CMDF_MOUNT_EX)) {
		inputpath = argv[0];

		/* 'inputpath' should be either valid pbdpath or pbdname */
		if (inputpath[0] == '/') {
			pbdpath_split(inputpath, pbdname, sizeof(pbdname), NULL, 0);
		} else {
			pbdpath_copy(pbdname, inputpath, sizeof(pbdname));
		}

		/*
		 * If CMDF_MOUNT is set, cluster name must be in co_common
		 * Or to say, cmd requiring src & dst cluster name will not
		 * set CMDF_MOUNT
		 */
		if ((ci->cmd_flags & CMDF_MOUNT_EX) &&
		    co.co_common.enable_pfsd != 0)
			err = pfs_mount_ex(co.co_common.cluster, pbdname,
			    co.co_common.hostid, PFS_TOOL|ci->cmd_mnt_flags);
		else
			err = pfs_mount(co.co_common.cluster, pbdname,
			    co.co_common.hostid, PFS_TOOL|ci->cmd_mnt_flags);
	}
	proc_info_record(argc + optind, argv - optind);
	if (err < 0)
		return -1;

	err = (*ci->cmd_entry)(argc, argv, &co);
	if (err < 0) {
		pfs_etrace("%s failed: %s\n", ci->cmd_name,
		    errno ? strerror(errno) : "impl specific");
		printf("%s failed: %s\n", ci->cmd_name,
		    errno ? strerror(errno) : "impl specific");
	} else
		err = 0;

	if ((ci->cmd_flags & CMDF_MOUNT_EX) &&
	    co.co_common.enable_pfsd != 0)
		pfs_umount_ex(pbdname);
	else if (ci->cmd_flags & CMDF_MOUNT)
		pfs_umount(pbdname);

	return err;
}
