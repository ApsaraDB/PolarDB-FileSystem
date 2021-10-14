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


#include <sys/types.h>
#include <string>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pfsd_sdk.h"
#include "pfsd_shm.h"

#define READ_SIZE (1 * 1024)

int main(int ac, char* av[]) {
    std::string pbd = "86-1";
    std::string pbd_path("/" + pbd + "/");
    if (ac > 1) {
        pbd = av[1];
        pbd_path = "/"+pbd+"/";
    }

    int rflags = PFS_RD | MNTFLG_PAXOS_BYFORCE;
    int wflags = PFS_RDWR | MNTFLG_PAXOS_BYFORCE;
    int host_id = 1;
    const char* cluster = NULL;

    pfsd_set_mode(PFSD_SDK_THREADS);

    int r = pfsd_mount(cluster, pbd.data(), host_id, rflags);
    if (r != 0) {
        printf("pfsd_sdk_init failed %d\n", errno);
        return -1;
    }
    int fd = pfsd_open((pbd_path + "hello.txt").data(), O_RDWR|O_CREAT, 0);
    printf("hello.txt: open fd %d\n", fd);
    if (fd < 0) {
        printf("hello.txt: open failed %d, now remount \n", errno);
        r = pfsd_remount(cluster, pbd.data(), host_id, wflags);
        printf("remount: %d, err %d\n", r, errno);

        fd = pfsd_open((pbd_path + "hello.txt").data(), O_RDWR|O_CREAT, 0);
    }

    ssize_t wbytes = pfsd_pwrite(fd, "abcdefghijklmnopqrstuvwxyz", 26, 0);
    printf("hello.txt: write %ld errno %d\n", wbytes, errno);

    char buf[READ_SIZE] = "";
    ssize_t bytes = pfsd_read(fd, buf, READ_SIZE);
    if (bytes > 0)
        printf("read %.*s\n", int(bytes), buf);
    else
        printf("read error %d, %d\n", int(bytes), errno);

    pfsd_close(fd);
    pfsd_umount(pbd.data());
    return 0;
}

