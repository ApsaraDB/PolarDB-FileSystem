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
 * Dentry cache performance test
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
#include <chrono>

#define ASSERT(cond, msg)    do {                			\
    if (!(cond)) {                       				\
		fprintf(stderr, "assert %s, %s:%d, %s", #cond, __func__, __LINE__, msg); \
		exit(EXIT_FAILURE); \
	} \
} while(0)

char cluster[128];
char device[128];

std::string get_fname(const char *name);
void create_files(int num);
void mount_fs(void);
void test(int);

#define FILE_NUM	5000

void usage(const char *prog)
{
	printf("usage: %s [OPTION]...\n", prog);
	printf("	-C cluster      specify cluster\n");
	printf("	-D device       specify device\n");
	printf("	-i              create files\n");
	printf("	-t loops        run test\n");
}

int main(int argc, char **argv)
{
	int opt;
	int touch_flag = 0;
	int test_flag = 0;
	int test_loops = 0;
	int touch_num = 0;

	while ((opt = getopt(argc, argv, "C:D:it:")) != -1) {
		switch (opt) {
		case 'C':
			strcpy(cluster, optarg);
            break;
		case 'D':
			strcpy(device, optarg);
			break;
		case 'i':
			touch_flag = 1;
			break;
		case 't':
			test_flag = 1;
			test_loops = atoi(optarg);
			break;
		default: /* '?' */
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (argc < 2) {
		return EXIT_FAILURE;
	}

	mount_fs();

	if (touch_flag) {
		create_files(FILE_NUM);
	} else if (test_flag) {
		test(test_loops);
	}
    return 0;
}

std::string get_fname(const char *name)
{
	return std::string("/") + std::string(device) + name;
}

void mount_fs(void)
{
	int ret = pfs_mount(cluster, device, 1, PFS_RDWR);
	if (ret != 0) {
		printf("can not mount");
		exit(EXIT_FAILURE);
	}
}

void create_files(int num)
{
	char name[128];

	for (int i = 0; i < num; ++i) {
		sprintf(name, "/%s/test_%d", device, i);
		int ret = pfs_creat(name, 0);
		ASSERT(ret > 0, "pfs_creat");
		if (ret > 0)
			pfs_close(ret);
	}
}

void do_test(int loops, int *file_list, int count);

void test(int loops)
{
	const int N = 100;
	int file_list[N];

	srandom(time(NULL));
	for (int i = 0; i < N; ++i) {
		file_list[i] = random() % FILE_NUM;
	}
	printf("cache off\n");
	pfs_set_namecache_enable(false);

	auto start = std::chrono::system_clock::now();
	do_test(loops, file_list, N);
	auto end = std::chrono::system_clock::now();
	std::chrono::duration<double> diff = end-start;
	printf("time: %f seconds\n", diff.count());

	printf("cache on\n");
	pfs_set_namecache_enable(true);
	start = std::chrono::system_clock::now();
	do_test(loops, file_list, N);
	end = std::chrono::system_clock::now();
	diff = end-start;
	printf("time: %f seconds\n", diff.count());
}

void do_test(int loops, int *file_list, int count)
{
	char name[128];
	for (int i = 0; i < loops; ++i) {
		for (int j = 0; j < count; ++j) {
			sprintf(name, "/%s/test_%d", device, file_list[j]);
			int ret = pfs_open(name, O_RDONLY, 0);
			ASSERT(ret > 0, "pfs_open");
			pfs_close(ret);
		}
	}
}
