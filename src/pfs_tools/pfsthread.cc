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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pfs_api.h"
#include "pfs_trace.h"
#include "pfs_devio.h"

#define THREAD_MAX 100

#define TOTAL_LENGTH (512*1024*1024)
static char *data_buf;
static uint32_t	nfile_per_thread;
static uint32_t	hostid;

typedef struct ThreadArg {
	char pbdname[PFS_MAX_PBDLEN];
	int tid;
	uint32_t filecnt;
} ThreadArg_t;

void *thread_run(void *arg);

void
umount(const char *pbdname)
{
	pfs_umount(pbdname);
}

int
mount(const char *pbdname)
{
	int err = 0;

	err = pfs_mount(CL_DEFAULT, pbdname, hostid, PFS_RDWR);
	if (err != 0)
		printf("Mount failed\n");

	return err;
}

int main(int argc, char **argv)
{
	int err;
	uint32_t i;
	char pbdname[PFS_MAX_PBDLEN] = {'\0'};
	pthread_t children[THREAD_MAX];
	ThreadArg_t children_arg[THREAD_MAX] = {0};
	uint32_t threadcnt;

	if (argc < 5) {
		printf("Usage: %s hostid pbdname thread_count nfile_per_thread\n", argv[0]);
		return -1;
	}

	data_buf = (char *)malloc(TOTAL_LENGTH);
	if(data_buf == NULL) {
		printf("create data buffer faield\n");
		return -1;
	}
	for(uint32_t i = 0; i < TOTAL_LENGTH/sizeof(uint64_t); i++) {
		*((uint64_t *)data_buf + 1) = rand();
	}

	hostid = strtoul(argv[1], NULL, 10);
	sprintf(pbdname, "%s", argv[2]);
	threadcnt = strtoul(argv[3], NULL, 10);
	threadcnt = threadcnt > THREAD_MAX ? THREAD_MAX : threadcnt;

	nfile_per_thread = strtoul(argv[4], NULL, 10);

	printf("Hostid: %u, Thread count: %u,  file number per thread: %u\n", hostid, threadcnt, nfile_per_thread);

	err = mount(pbdname);
	if (err < 0)
		return -1;

	for (i = 0; i < threadcnt; ++i) {
		sprintf(children_arg[i].pbdname, "%s", pbdname);
		children_arg[i].tid = i;
		children_arg[i].filecnt = 0;
		pthread_create(&children[i], NULL, thread_run, (void *)&children_arg[i]);
	}

	for (i = 0; i < threadcnt; ++i) {
		pthread_join(children[i], NULL);
	}

	umount(pbdname);
	printf("Test Finish\n");

	uint32_t filecnt = 0;
	for (i = 0; i < threadcnt; ++i)
		filecnt += children_arg[i].filecnt;
	printf("Create file count %u\n", filecnt);

	return 0;
}

void *thread_run(void *arg)
{
	uint32_t i;
	int fd;
	char pbdpath[PFS_MAX_PATHLEN] = {'\0'};
	ThreadArg_t *targ = (ThreadArg_t *)arg;


	for (i = 0; i < nfile_per_thread; ++i) {
		sprintf(pbdpath, "/%s/%u-%d", targ->pbdname, hostid, targ->tid * 10000 + i);
		do {
			errno = 0;
			fd = pfs_open(pbdpath, O_CREAT, 0);
		} while (fd < 0 && errno == EAGAIN);
		if (fd < 0) {
			switch (errno) {
			case EPFS_FILE_2MANY:
				printf("%d: Too many files in PBD\n", targ->tid);
				break;
			case EMFILE:
				printf("%d: Too many files opened in PBD\n", targ->tid);
				break;
			default:
				printf("%d: errno=%s\n", targ->tid, strerror(errno));
				break;
			}
			goto exit_thread;
		} else {
			printf("Create file %s\n", pbdpath);

            pfs_pwrite(fd, data_buf, TOTAL_LENGTH, 0);

			pfs_close(fd);
			++targ->filecnt;
			usleep(10000);
		}
	}

exit_thread:
	return NULL;
}
