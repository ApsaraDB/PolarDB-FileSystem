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

#ifndef __PFSD_TESTENV_H__
#define __PFSD_TESTENV_H__

#include <gtest/gtest.h>
#include <string>


#define UNIT_1G (1024*1024*1024)
#define UNIT_4K (4*1024)
#define UNIT_4M (4*1024*1024)

#define CHECK_RET(expected, actual) do {\
    EXPECT_EQ(expected, actual);\
    if (expected != actual) {\
        cout << "--- unexpected error: [" << errno\
         << "] " << strerror(errno) << endl;\
        errno = 0; \
    } \
} while (0)

#define CHECK_ERR_RET(expected, actual, expected_errno) do {	\
    EXPECT_EQ(expected, actual);				\
    EXPECT_EQ(expected_errno, errno);				\
} while (0)

#define CHECK_CUR_OFFSET(fd_, val) do {          \
    off_t pos = pfsd_lseek(fd_, 0, SEEK_CUR);    \
    EXPECT_EQ(pos, val);                \
} while(0)

#define CHECK_FILESIZE(fd_, val) do {        \
    struct stat fstat;          \
    pfsd_fstat(fd_, &(fstat));       \
    EXPECT_EQ((fstat).st_size, val);    \
} while(0)

#define CHECK_FILETYPE(pbdpath, type) do {        \
    struct stat fstat;          \
    pfsd_stat(pbdpath , &(fstat));       \
    EXPECT_TRUE(S_IS##type(fstat.st_mode));    \
} while(0)


class PFSDTestEnv : public testing::Environment
{
public:
    explicit PFSDTestEnv(const std::string &cluster, const std::string &pbdname, int hostid) :
        cluster_(cluster),
        pbdname_(pbdname),
        hostid_(hostid) {
        }

    virtual void SetUp();
    virtual void TearDown();

    int mount(int flags);
    int umount();

    std::string cluster_;
    std::string pbdname_;    // "PBD-VERSION"
    int hostid_;
};

extern PFSDTestEnv *g_testenv;

#endif

