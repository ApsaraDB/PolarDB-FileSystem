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

/*
 * Test if RO node can sense event that a file is removed by RW
 * node and also remove it from its own dentry cache.
 */
#include "pfs_api.h"
#define NAMECACHE_TEST
#include "pfs_namecache.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#define ASSERT(cond, msg)    do {                			\
    if (!(cond)) {                       				\
		fprintf(stderr, "assert %s, %s:%d, %s\n", #cond, __func__, __LINE__, msg); \
		exit(EXIT_FAILURE); \
	} \
} while(0)

void child_proc();
int parent_proc();

pid_t child;
char cluster[128];
char device[128];
int p1[2];
int p2[2];

int main(int argc, char **argv)
{
	pid_t pid;

	if (argc < 2) {
		printf("usage: %s <cluster> <device>\n", argv[0]);
		return EXIT_FAILURE;
	}

	ASSERT(strlen(argv[1]) < sizeof(cluster), "cluster string too long");
	ASSERT(strlen(argv[2]) < sizeof(device), "device string too long");

	strcpy(cluster, argv[1]);
	strcpy(device, argv[2]);

	ASSERT(pipe(p1) == 0, "pipe");
	ASSERT(pipe(p2) == 0, "pipe");

	pid = fork(); 
	if (pid == 0) {
		child_proc();
		exit(0);
	}

	child = pid;
	return parent_proc();
}

std::string get_fname(const char *name)
{
	return std::string("/") + std::string(device) + name;
}

int parent_proc()
{
	FILE *in, *out;
	char buf[128];

	out = fdopen(p1[1], "a");
	ASSERT(out != NULL, "fdopen");
	setvbuf(out, NULL, _IONBF, 0);
	close(p1[0]);

	in = fdopen(p2[0], "r");
	ASSERT(in != NULL, "fdopen");
	close(p2[1]);

	int ret = pfs_mount(cluster, device, 1, PFS_RDWR);
	if (ret != 0) {
		printf("can not mount");
		kill(child, SIGTERM);
		return EXIT_FAILURE;
	}

	std::string dirname = get_fname("/testdir");
	ret = pfs_mkdir(dirname.c_str(), 0);
	ASSERT(ret == 0 || (ret == -1 && errno == EEXIST), "pfs_mkdir");

	std::string fname = get_fname("/testdir/testfile");

	ret = pfs_creat(fname.c_str(), 0);
	ASSERT(ret >= 0, "pfs_creat");

	fprintf(out, "open %s\n", fname.c_str());
	buf[0] = 0;
	fgets(buf, sizeof(buf), in);
	ASSERT(strcmp(buf, "success\n") == 0, "first open command");

	ret = pfs_unlink(fname.c_str());
	ASSERT(ret == 0 || (ret == -1 && errno == ENOENT), "pfs_unlink");

	ret = pfs_open(fname.c_str(), O_RDWR, 0);
	ASSERT((ret == -1 && errno == ENOENT), "pfs_open");

	sleep(3); // wait readonly node to read log

	fprintf(out, "open %s\n", fname.c_str());
	buf[0] = 0;
	fgets(buf, sizeof(buf), in);
	ASSERT(strcmp(buf, "failure\n") == 0, "second open command");

	fprintf(out, "numdelbydeno\n");
	buf[0] = 0;
	fgets(buf, sizeof(buf), in);
	int num_deno_del = atoi(buf);
	ASSERT(num_deno_del == 1, "failure");

	ret = pfs_rmdir(dirname.c_str());
	ASSERT(ret >= 0, "pfs_rmdir");
	sleep(3); // wait readonly node to read log

	fprintf(out, "numdelbydeno\n");
	buf[0] = 0;
	fgets(buf, sizeof(buf), in);
	num_deno_del = atoi(buf);
//	printf("%d\n", num_deno_del);
	ASSERT(num_deno_del == 2, "failure");

	printf("success\n");
	return 0;
}

void child_proc()
{
	FILE *in, *out;
	char cmd[128], buf[128];

	in = fdopen(p1[0], "r");
	ASSERT(in != NULL, "fdopen");
	close(p1[1]);
	out = fdopen(p2[1], "a");
	ASSERT(out != NULL, "fdopen");
	close(p2[0]);
	setvbuf(out, NULL, _IONBF, 0);

	int ret = pfs_mount(cluster, device, 2, PFS_RD|PFS_TOOL);
	ASSERT(ret == 0, "child pfs_mount failure");

	for (;;) {
		fscanf(in, "%s", cmd);
		if (strcmp(cmd, "open") == 0) {
			fscanf(in, "%s", buf);
			int ret = pfs_open(buf, O_RDWR, 0);
			if (ret >= 0) {
				fprintf(out, "success\n");
				pfs_close(ret);	
			} else {
				fprintf(out, "failure\n");
			}
		} else if (strcmp(cmd, "numdelbydeno") == 0) {
			namecache_stat s;
			pfs_namecache_stat(&s);
			fprintf(out, "%ld\n", s.numdelbydeno);
		} else {
			fprintf(stderr, "unknown command:%s\n", cmd);
			exit(1);
		}
	}
}
