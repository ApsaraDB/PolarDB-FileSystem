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


#include <gtest/gtest.h>
#include <string>
#include <iostream>
#include <limits.h>
#include <fcntl.h>

using std::cout;
using std::endl;
using std::string;

#include "pfsd_testenv.h"
#include "pfsd_sdk.h"

#define OFF_MAX ~((off_t)1 << (sizeof(off_t) * 8 - 1))
#define OFF_MIN  ((off_t)1 << (sizeof(off_t) * 8 - 1))

#define NOPASS_OPEN 1
#define NOPASS_OPEN_DIR 0
#define NOPASS_READ 0
#define NOPASS_FSTAT 0
#define NOPASS_TRUNCATE 0
#define NOPASS_FALLOC 0
#define NOPASS_ROFS 0
#define NOPASS_ACCESS 0



class FileTest : public testing::Test {
public:
    FileTest() {
    }

    void SetUp() override {
        filepath_ = "/";
        filename_ = "hello.txt";
        pbdpath_ = "/" + g_testenv->pbdname_ + filepath_ + filename_;

        fd_ = pfsd_creat(pbdpath_.data(), 0);
        ASSERT_GE(fd_, 0) << strerror(errno);
    }

    void TearDown() override {
        pfsd_close(fd_);
        int r = pfsd_unlink(pbdpath_.data());
        assert(r == 0);
    }

    string pbdpath_;
    string filepath_;
    string filename_;
    int fd_;
};

struct fileobj {
    fileobj(const string& file, int flags);
    ~fileobj();

	int	getfd() const { return _fd; }

private:
	int _fd;
};

fileobj::fileobj(const string& file, int flags) {
	_fd = pfsd_open(file.data(), flags, 0);
}

fileobj::~fileobj() {
	if (_fd >= 0) {
		pfsd_close(_fd);
        _fd = -1;
    }
}

TEST_F(FileTest, test) {
    char buf[] = "1234567";
    int n = pfsd_write(fd_, buf, 7);
    EXPECT_EQ(n, 7);

    off_t off = pfsd_lseek(fd_, 0, SEEK_SET);
    EXPECT_EQ(off, 0);

    n = pfsd_read(fd_, buf, 7);
    EXPECT_EQ(n, 7);
}

TEST_F(FileTest, pfsd_hole_read) {
	fileobj fo("/" + g_testenv->pbdname_ + "/hole_read", O_CREAT|O_TRUNC);
	int fd = fo.getfd();
	EXPECT_GE(fd, 0);

	int off = 13;
	char buf[10];
	memset(buf, 't', sizeof(buf));
	pfsd_pwrite(fd, buf, sizeof(buf), off);

	char buf2[off];
	char buf3[off];
	pfsd_pread(fd, buf2, sizeof(buf2), 0);
	memset(buf3, 0, sizeof(buf3));
	int rv = memcmp(buf2, buf3, sizeof(buf3));
	EXPECT_EQ(rv, 0);
}

TEST_F(FileTest, pfsd_write)
{
    ssize_t len;
    int fd;
    std::string dirpath;

    // 1 write len change
    // 1.1 write len is zero
    len = pfsd_write(fd_, "0123456789", 0);
    CHECK_RET(0, len);
    CHECK_CUR_OFFSET(fd_, 0);

    // 1.2 write 10 bytes
    len = pfsd_write(fd_, "0123456789", 10);
    EXPECT_EQ(10, len);
    CHECK_CUR_OFFSET(fd_, 10);
    CHECK_FILESIZE(fd_, 10);

    // 1.3 continue write 8 bytes with overlap
    pfsd_lseek(fd_, -5, SEEK_END);
    len = pfsd_write(fd_, "0123456789", 8);
    EXPECT_EQ(8, len);
    CHECK_CUR_OFFSET(fd_, 13);
    CHECK_FILESIZE(fd_, 13);

    // 1.4 write len -2
    pfsd_lseek(fd_, 5, SEEK_SET);
    len = pfsd_write(fd_, "0123456789", -2);
    CHECK_ERR_RET(-1, len, EFBIG);
    CHECK_FILESIZE(fd_, 13);

    // 2 file offset change
    // 2.1 Write with a big offset, which will cause a big hole
    ssize_t large_len = 0x1000000;
    pfsd_lseek(fd_, large_len, SEEK_SET);
    len = pfsd_write(fd_, "0123456789", 10);
    CHECK_RET(10, len);
    static int curr_file_len = large_len + 10;
    CHECK_FILESIZE(fd_, curr_file_len);

    // 2.2 read with small offset, large len
    pfsd_lseek(fd_, 10, SEEK_SET);
#if 0
    char *buf = (char *)malloc(large_len);
    memset(buf, 0, large_len);
    len = pfsd_read(fd_, buf, large_len);
    EXPECT_EQ(len, large_len);
    free(buf);
#endif
    //  2.3 If result file offset is bigger than the offset maximum,
    // no data transfer shall occur.
    pfsd_lseek(fd_, OFF_MAX, SEEK_SET);
    len = pfsd_write(fd_, "0123456789", 10);
    CHECK_ERR_RET(-1, len, EFBIG);
    CHECK_FILESIZE(fd_, curr_file_len);

    // 3 buf invalid
    len = pfsd_write(fd_, NULL, 10);
    CHECK_ERR_RET(-1, len, EINVAL);
    CHECK_FILESIZE(fd_, curr_file_len);

    // 4 EBADF
    fd = -1;
    pfsd_lseek(fd_, 0, SEEK_SET);
    len = pfsd_write(fd, "0123456789", 10);
    CHECK_ERR_RET(-1, len, EBADF);

    /*
     * EISDIR
     * This errno only exists in PFS.
     */
    dirpath = "/" + g_testenv->pbdname_ + "/";
    fd = pfsd_open(dirpath.c_str(), 0, 0666);
    EXPECT_GE(fd, 0);

    len = pfsd_pwrite(fd, "dummy", 3, 10);
    CHECK_ERR_RET(-1, len, EISDIR);

    len = pfsd_write(fd, "dummy", 3);
    CHECK_ERR_RET(-1, len, EISDIR);

    pfsd_close(fd);
    fd = -1;

    // TODO
    // 5 EDQUOT
    // 6 EINTR
    // 7 EIO
    // 8 ENOSPC no enough room for write, only as many bytes as there is room for shall be written
    // write causes file size exceeds limit(system limit, length type limit)
}

TEST_F(FileTest, pfsd_pwrite)
{
    ssize_t len;
    int err, fd;
    std::string dirpath;

    // 1 write len change
    // 1.1 write len is zero
    len = pfsd_pwrite(fd_, "0123456789", 0, 0);
    CHECK_RET(0, len);

    // 1.2 write 10 bytes
    CHECK_CUR_OFFSET(fd_, 0);
    len = pfsd_pwrite(fd_, "0123456789", 10, 0);
    EXPECT_EQ(len, 10);
    CHECK_FILESIZE(fd_, 10);

    // 1.3 continue write 8 bytes with overlap
    len = pfsd_pwrite(fd_, "0123456789", 8, 5);
    EXPECT_EQ(len, 8);
    CHECK_FILESIZE(fd_, 13);

    // 1.4 write len -2
    len = pfsd_pwrite(fd_, "0123456789", -2, 15);
    CHECK_ERR_RET(-1, len, EFBIG);
    CHECK_FILESIZE(fd_, 13);

    // 2 file offset change
    // 2.1 Write with a big offset, which will cause a big hole
    ssize_t large_len = 0x1000000;
    len = pfsd_pwrite(fd_, "0123456789", 10, large_len);
    CHECK_RET(10, len);
    static int curr_file_len = large_len + 10;
    CHECK_FILESIZE(fd_, curr_file_len);

    // 2.2 read with small offset, large len
#if 0
    char *buf = (char *)malloc(large_len);
    memset(buf, 0, large_len);
    len = pfsd_pread(fd_, buf, large_len, 10);
    EXPECT_EQ(len, large_len);
    free(buf);
#endif

    // 2.3 If result file offset is bigger than the offset maximum,
    // no data transfer shall occur.
    len = pfsd_pwrite(fd_, "0123456789", 10, OFF_MAX);
    CHECK_ERR_RET(-1, len, EFBIG);
    CHECK_FILESIZE(fd_, curr_file_len);

    // 3 buf invalid
    len = pfsd_pwrite(fd_, NULL, 10, curr_file_len);
    CHECK_ERR_RET(-1, len, EINVAL);
    CHECK_FILESIZE(fd_, curr_file_len);

    // 4 EBADF
    fd = -1;
    len = pfsd_pwrite(fd, "0123456789", 10, 0);
    CHECK_ERR_RET(-1, len, EBADF);

    /*
     * EBADF
     * pwrite a fd which represents a directory.
     * Expect: EBADF
     * Actual: EISDIR
     */
    dirpath = "/" + g_testenv->pbdname_ + "/";
    fd = pfsd_open(dirpath.c_str(), 0, 0666);
    EXPECT_GE(fd, 0);

    len = pfsd_pwrite(fd, "dummy", 3, 10);
    CHECK_ERR_RET(-1, len, EISDIR);

    pfsd_close(fd);
    fd = -1;


    // TODO
    // 5 EDQUOT
    // 6 EINTR
    // 7 EIO
    // 8 ENOSPC no enough room for write, only as many bytes as there is room for shall be written
    // write causes file size exceeds limit(system limit, length type limit)

    /*
     * file hole test
     * 1) the whole write area exceeds file size.
     * 2) the whole write area is in the range of filesize.
     * 3) part of write area exceeds file size.
     */
    // 1) write 1B @3M of a empty file
    err = pfsd_ftruncate(fd_, 0);
    EXPECT_EQ(err, 0);
    CHECK_FILESIZE(fd_, 0);
    len = pfsd_pwrite(fd_, "0", 1, 3*1024*1024);
    EXPECT_EQ(len, 1);
    CHECK_FILESIZE(fd_, 3*1024*1024 + 1);

    // 2) write 1B @3M of a 4MB file
    err = pfsd_ftruncate(fd_, 0);
    EXPECT_EQ(err, 0);
    err = pfsd_ftruncate(fd_, 4*1024*1024);
    EXPECT_EQ(err, 0);
    CHECK_FILESIZE(fd_, 4*1024*1024);
    len = pfsd_pwrite(fd_, "0", 1, 3*1024*1024);
    EXPECT_EQ(len, 1);
    CHECK_FILESIZE(fd_, 4*1024*1024);

    // 3) write 2B @(4M-1) of a 4MB file
    err = pfsd_ftruncate(fd_, 0);
    EXPECT_EQ(err, 0);
    err = pfsd_ftruncate(fd_, 4*1024*1024);
    EXPECT_EQ(err, 0);
    CHECK_FILESIZE(fd_, 4*1024*1024);
    len = pfsd_pwrite(fd_, "01", 2, 4*1024*1024-1);
    EXPECT_EQ(len, 2);
    CHECK_FILESIZE(fd_, 4*1024*1024+1);
}

TEST_F(FileTest, pfsd_read)
{
    __attribute__((unused)) off_t newpos;
    ssize_t len;
    char buf[256] = {'\0'};
    std::string dirpath;

    /*
     * Check for correctness
     */
    // Write some data for test
    len = pfsd_pwrite(fd_, "0123456789", 10, 0);
    ASSERT_EQ(len, 10);

    // 1 read file with different len
    /* 1.2
     * BRIEF: len = -1, means max long
     * EXPECT: set errno EFAULT
     * ACTUAL: no error
     */
    //newpos = pfsd_lseek(fd_, 0, SEEK_SET);
    //len = pfsd_read(fd_, buf, -1);
    //CHECK_ERR_RET(-1, len, EINVAL);

#if NOPASS_READ
    // this is the behavior of real read len -1
    int fd1;
    fd1 = open("/var/run/tempfile", O_CREAT);
    len = write(fd1, "0123456789", 10);
    newpos = lseek(fd1, 0, SEEK_SET);
    len = read(fd1, buf, -1);
    CHECK_ERR_RET(-1, len, EFAULT);
    close(fd1);
    unlink("/var/run/tempfile");
#endif

    // 1.2 len long max
    newpos = pfsd_lseek(fd_, 0, SEEK_SET);
    len = pfsd_read(fd_, buf, (size_t)(LONG_MAX));
    CHECK_RET(10, len);

    // 1.3 len 0
    newpos = pfsd_lseek(fd_, 0, SEEK_SET);
    len = pfsd_read(fd_, buf, 0);
    CHECK_RET(0, len);

    // 1.4 len large than fsize, less than long max
    newpos = pfsd_lseek(fd_, 0, SEEK_SET);
    len = pfsd_read(fd_, buf, 10000);
    CHECK_RET(10, len);

    // 2 read with dirrerent starting position
    // 2.1 starting position is 4 bytes before EOF(end-of-file)
    newpos = pfsd_lseek(fd_, -4, SEEK_END);
    memset(buf, 0, sizeof(buf));
    len = pfsd_read(fd_, buf, 10);
    EXPECT_STREQ(buf, "6789");

    // 2.2 starting position is at the EOF
    newpos = pfsd_lseek(fd_, 0, SEEK_END);
    len = pfsd_read(fd_, buf, 10);
    CHECK_RET(0, len);

    // 2.3 starting position is after the EOF
    newpos = pfsd_lseek(fd_, 20, SEEK_END);
    len = pfsd_read(fd_, buf, 10);
    CHECK_RET(0, len);

    // 3 read gap
    len = pfsd_pwrite(fd_, "abcde", 5, 15);
    newpos = pfsd_lseek(fd_, 8, SEEK_SET);
    memset(buf, 0, sizeof(buf));
    len = pfsd_read(fd_, buf, 20);
    EXPECT_EQ(len, 12);
    EXPECT_EQ(strncmp(buf, "89\0\0\0\0\0abcde", len), 0);

    /*
     * Check for Error Code
     */
    int fd;
    string path;

    // 4 read bad fd
    fd = -1;
    len = pfsd_read(fd, buf, 10);
    CHECK_ERR_RET(-1, len, EBADF);

    // 5 read file to invalid buf
    char *invalid_buf = NULL;
    len = pfsd_read(fd_, invalid_buf, 10);
    EXPECT_EQ(len, -1);
    EXPECT_EQ(errno, EINVAL);
#if 0
    /* when buf access permission denied */
    invalid_buf = (char *)0x80480000;
    len = pfsd_read(fd_, invalid_buf, 10);
    EXPECT_EQ(len, -1);
    EXPECT_EQ(errno, EINVAL);
#endif

    // 6 read empty file, with differnt pos
    path = "/" + g_testenv->pbdname_ + "/read.txt";
    pfsd_unlink(path.c_str());
    errno = 0;
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    EXPECT_GT(fd, 0);
    memset(buf, 0, sizeof(buf));
    len = pfsd_read(fd, buf, 10);
    CHECK_RET(0, len);

    newpos = pfsd_lseek(fd, 8, SEEK_SET);
    EXPECT_EQ(newpos, 8);
    len = pfsd_read(fd, buf, 0);
    CHECK_RET(0, len);

    pfsd_close(fd);
    pfsd_unlink(path.c_str());
    errno = 0;

    /*
     * EISDIR
     * read a fd which represents a directory.
     */
    dirpath = "/" + g_testenv->pbdname_ + "/";
    fd = pfsd_open(dirpath.c_str(), 0, 0666);
    EXPECT_GE(fd, 0);

    len = pfsd_read(fd, buf, 3);
    CHECK_ERR_RET(-1, len, EISDIR);

    pfsd_close(fd);
    fd = -1;
}

TEST_F(FileTest, pfsd_pread)
{
    ssize_t len;
    char buf[256] = {'\0'};
    std::string dirpath;

    /*
     * Check for correctness
     */
    // Write some data for test
    len = pfsd_pwrite(fd_, "0123456789", 10, 0);
    ASSERT_EQ(len, 10);

    // 1 read file with different len
#if NOPASS_READ
    /* 1.1
     * BRIEF: len = -1, means max long
     * EXPECT: set errno EFAULT
     * ACTUAL: no error
     */
    len = pfsd_pread(fd_, buf, -1, 0);
    CHECK_ERR_RET(-1, len, EFAULT);

    // this is the behavior of real read len -1
    int fd1;
    fd1 = open("/var/run/tempfile", O_CREAT);
    len = write(fd1, "0123456789", 10);
    len = pread(fd1, buf, -1, 0);
    CHECK_ERR_RET(-1, len, EFAULT);
    close(fd1);
    unlink("/var/run/tempfile");
#endif

    // 1.2 len long max
    len = pfsd_pread(fd_, buf, (size_t)(LONG_MAX), 0);
    CHECK_RET(10, len);

    // 1.3 len 0
    len = pfsd_pread(fd_, buf, 0, 0);
    CHECK_RET(0, len);

    // 1.4 len large than fsize, less than long max
    len = pfsd_pread(fd_, buf, 10000, 0);
    CHECK_RET(10, len);

    // change starting position
    // 2.1 starting position is 4 bytes before EOF(end-of-file)
    memset(buf, 0, sizeof(buf));
    len = pfsd_pread(fd_, buf, 10, 10-4);
    EXPECT_STREQ(buf, "6789");

    // 2.2 starting position is at the EOF
    len = pfsd_pread(fd_, buf, 10, 10);
    CHECK_RET(0, len);

    // 2.3 starting position is after the EOF
    len = pfsd_pread(fd_, buf, 10, 20);
    CHECK_RET(0, len);

    // 2.4 read gap
    len = pfsd_pwrite(fd_, "abcde", 5, 15);
    memset(buf, 0, sizeof(buf));
    len = pfsd_pread(fd_, buf, 20, 8);
    EXPECT_EQ(len, 12);
    EXPECT_EQ(strncmp(buf, "89\0\0\0\0\0abcde", len), 0);

    /*
     * Check for Error Code
     */
    int fd;
    string path;

    // 3 read file to invalid buf
    char *invalid_buf = NULL;

    len = pfsd_pread(fd_, invalid_buf, 10, 0);
    CHECK_ERR_RET(-1, len, EINVAL);
#if 0
    /* when buf access permission denied */
    invalid_buf = (char *)0x80480000;
    len = pfsd_pread(fd_, invalid_buf, 10, 0);
    CHECK_ERR_RET(-1, len, EINVAL);
#endif

    // 4 read bad fd
    fd = -1;
    len = pfsd_pread(fd, buf, 10, 0);
    CHECK_ERR_RET(-1, len, EBADF);

    // 5 read empty file, with differnt pos
    path = "/" + g_testenv->pbdname_ + "/read.txt";
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    EXPECT_GT(fd, 0);

    memset(buf, 0, sizeof(buf));
    len = pfsd_pread(fd, buf, 10, 0);
    CHECK_RET(0, len);

    len = pfsd_pread(fd, buf, 0, 8);
    CHECK_RET(0, len);
    pfsd_close(fd);
    pfsd_unlink(path.c_str());
    errno = 0;

    /*
     * EISDIR
     * pread a fd which represents a directory.
     */
    dirpath = "/" + g_testenv->pbdname_ + "/";
    fd = pfsd_open(dirpath.c_str(), 0, 0666);
    EXPECT_GE(fd, 0);

    len = pfsd_pread(fd, buf, 3, 10);
    CHECK_ERR_RET(-1, len, EISDIR);

    pfsd_close(fd);
    fd = -1;
}

TEST_F(FileTest, pfsd_lseek)
{
    off_t pos;
    int fd;
    ssize_t len;
    std::string dirpath;

    ASSERT_EQ(OFF_MAX, std::numeric_limits<off_t>::max());

    // 1 illegal whence
    pos = pfsd_lseek(fd_, 0, 9999);
    CHECK_ERR_RET(-1, pos, EINVAL);

    // 2 check with different offset
    pos = pfsd_lseek(fd_, 1, SEEK_SET);
    CHECK_RET(1, pos);
    CHECK_CUR_OFFSET(fd_, 1);

    pos = pfsd_lseek(fd_, -10, SEEK_CUR);
    CHECK_ERR_RET(-1, pos, EINVAL);
    CHECK_CUR_OFFSET(fd_, 1);

    pos = pfsd_lseek(fd_, -10, SEEK_SET);
    CHECK_ERR_RET(-1, pos, EINVAL);
    CHECK_CUR_OFFSET(fd_, 1);

    pos = pfsd_lseek(fd_, 0 - OFF_MAX -1, SEEK_CUR);
    CHECK_ERR_RET(-1, pos, EINVAL);
    CHECK_CUR_OFFSET(fd_, 1);

    pos = pfsd_lseek(fd_, -1000, SEEK_END);
    CHECK_ERR_RET(-1, pos, EINVAL);
    CHECK_CUR_OFFSET(fd_, 1);

    pos = pfsd_lseek(fd_, 0, SEEK_END);
    CHECK_RET(0, pos);
    CHECK_CUR_OFFSET(fd_, 0);

    // result offset is overflow
    // On Linux e07e10242.eu6sqa 3.10.0-327.ali2000.alios7.x86_64,
    // 17592186040321 will cause EINVAL and return -1 in sys' lseek()
    pos = pfsd_lseek(fd_, OFF_MAX, SEEK_SET);
    pos = pfsd_lseek(fd_, 1, SEEK_CUR);
    CHECK_ERR_RET(-1, pos, EOVERFLOW);
    CHECK_CUR_OFFSET(fd_, OFF_MAX);

    pos = pfsd_lseek(fd_, 0, SEEK_SET);
    pos = pfsd_lseek(fd_, OFF_MIN, SEEK_CUR);
    CHECK_ERR_RET(-1, pos, EINVAL);
    CHECK_CUR_OFFSET(fd_, 0);

    /*
     * lseek a fd which represents a directory.
     */
    dirpath = "/" + g_testenv->pbdname_ + "/";
    fd = pfsd_open(dirpath.c_str(), 0, 0666);
    EXPECT_GE(fd, 0);

    len = pfsd_lseek(fd, 100, SEEK_SET);
    CHECK_RET(100, len);

    pfsd_close(fd);
    fd = -1;

}

TEST_F(FileTest, pfsd_chdir)
{
    int err, fd;
    char *ptr = NULL;
    char buf[PFS_MAX_PATHLEN];
    ssize_t len;
    string dirpath = "/"+ g_testenv->pbdname_ + "/chdir_dir";
    string filename = "./chdir_file";
    string old_wdpath;
    string pbdpath = dirpath + "/chdir_file";
    /*
     * Only test when chdir success,
     * the file operation under dir.
     * check for the wd change after chdir,
     * and the absolute path of created file
     * under working directory
     */
    ptr = pfsd_getwd(buf);
    CHECK_ERR_RET(NULL, ptr, ENOENT);
    EXPECT_EQ(buf[0], '\0');

    // change work_dir to dirpath
    pfsd_mkdir(dirpath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    errno = 0;
    err = pfsd_chdir(dirpath.c_str());
    CHECK_RET(0, err);

    // read work_dir & compare
    memset(buf, 0, PFS_MAX_PATHLEN);
    ptr = pfsd_getwd(buf);
    EXPECT_TRUE(ptr != NULL);
    EXPECT_STREQ(buf, dirpath.c_str());

    // creat a file under absolute path
    fd = pfsd_open(filename.c_str(), O_CREAT, 0);
    EXPECT_GT(fd, 0);

    len = pfsd_pwrite(fd, "0123456789", 10, 0);
    EXPECT_EQ(len, 10);
    err = pfsd_close(fd);
    CHECK_RET(0, err);

    // read it from work_dir
    fd = 0;
    fd = pfsd_open(pbdpath.c_str(), 0, 0);
    EXPECT_GT(fd, 0);

    memset(buf, 0, PFS_MAX_PATHLEN);
    len = pfsd_read(fd, buf, 10);
    EXPECT_EQ(len, 10);
    EXPECT_STREQ(buf, "0123456789");

    // reset work_dir to /pbdname/
    memset(buf, 0, PFS_MAX_PATHLEN);
    old_wdpath = "/" + g_testenv->pbdname_ + "/";
    err = pfsd_chdir(old_wdpath.c_str());
    ptr = pfsd_getwd(buf);
    EXPECT_TRUE(ptr != NULL);
    EXPECT_STREQ(buf, old_wdpath.c_str());

    pfsd_close(fd);
    pfsd_unlink(pbdpath.c_str());
    pfsd_rmdir(dirpath.c_str());
}

TEST_F(FileTest, pfsd_open)
{
    int fd, ret;
    string path;

    // 1 test repeated open
    // 1.1 open none exist file
    path = "/" + g_testenv->pbdname_ + "/open_O_CREAT.txt";
    pfsd_unlink(path.c_str());
    fd = pfsd_open(path.c_str(), 0, 0);
    CHECK_ERR_RET(-1, fd, ENOENT);
    pfsd_close(fd);

    // 1.2 create new file
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    EXPECT_GT(fd, 0);
    pfsd_close(fd);

    // 3.open existed file
    fd = pfsd_open(path.c_str(), 0, 0);
    EXPECT_GT(fd, 0);
    pfsd_close(fd);
    pfsd_unlink(path.c_str());

#if NOPASS_OPEN_DIR
    /* 2.1
     * BRIEF: try to use open to open dir, without O_DIRECTORY
     * EXPECT: set errno EISDIR
     * ACTUAL: no errno
     */
    struct stat fstat;
    path = "/" + g_testenv->pbdname_ + "/open_dir/";
    pfsd_rmdir(path.c_str());
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    errno = 0;
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    CHECK_ERR_RET(-1, fd, EISDIR);
    pfsd_fstat(fd, &(fstat));
    cout<<"[SPT_DEBUG]open create a file:"<< fd<<", type: dir"<< S_ISDIR(fstat.st_mode);
    pfsd_close(fd);

    /* 2.2
     * BRIEF: try to use open to creat one dir, without O_DIRECTORY
     * EXPECT: set errno EISDIR
     * ACTUAL: no errno, but creat type file
     */
    /* test O_CREAT new dir*/
    path = "/" + g_testenv->pbdname_ + "/open_new_dir/";
    pfsd_rmdir(path.c_str());
    errno = 0;
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    CHECK_ERR_RET(-1, fd, EISDIR);
    pfsd_fstat(fd, &(fstat));
    cout<<"[SPT_DEBUG]open create a file:"<< fd<<", type: file"<< S_ISREG(fstat.st_mode);
    pfsd_close(fd);
    ret = pfsd_rmdir(path.c_str());
    CHECK_ERR_RET(-1, ret, EISDIR);
#endif

    // 3 teset O_EXCL flag
    // 3.1 create new file
    path = "/" + g_testenv->pbdname_ + "/open_O_CREAT_O_EXCL.txt";
    pfsd_unlink(path.c_str());
    errno = 0;
    fd = pfsd_open(path.c_str(), O_CREAT | O_EXCL, 0);
    EXPECT_GT(fd, 0);
    pfsd_close(fd);

    // 3.2 create existed file
    fd = pfsd_open(path.c_str(), O_CREAT | O_EXCL, 0);
    CHECK_ERR_RET(-1, fd, EEXIST);
    pfsd_close(fd);
    pfsd_unlink(path.c_str());

    // 4 teset CREATE file failed
    path = "/" + g_testenv->pbdname_ + "/no_exist_dir/open_O_CREAT.txt";
    pfsd_unlink(path.c_str());
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    CHECK_ERR_RET(-1, fd, ENOENT);
    pfsd_close(fd);

    // 5 O_APPEND flag
    int len = 10;
    ret = pfsd_lseek(fd_, 0, SEEK_SET);
    ret = pfsd_write(fd_, "0123456789", len);
    CHECK_RET(len, ret);
    CHECK_FILESIZE(fd_, len);
    ret = pfsd_lseek(fd_, 0, SEEK_SET);

    fd = pfsd_open(pbdpath_.c_str(), O_APPEND, 0);
    EXPECT_GT(fd, 0);
    CHECK_FILESIZE(fd, len);
    //CHECK_CUR_OFFSET(fd, len);
    pfsd_close(fd);

	// 5 O_APPEND flag
	path = "/" + g_testenv->pbdname_ + "/open_O_APPEND.txt";
	fd = pfsd_open(path.c_str(), O_CREAT | O_TRUNC | O_RDWR| O_APPEND, 0);
	EXPECT_GT(fd, 0);
	CHECK_FILESIZE(fd, 0);
	CHECK_CUR_OFFSET(fd, 0);

	len = 10;
	ret = pfsd_write(fd, "0123456789", len);
	CHECK_RET(len, ret);
	CHECK_FILESIZE(fd, len);
	CHECK_CUR_OFFSET(fd, len);

	/*
	 * write(2):
	 * If the file was open(2)ed with O_APPEND, the file offset is
	 * first set to the end of the file before writing.
	 */
	for (int i = 1; i < 3; i++) {
		ret = pfsd_lseek(fd, 0, SEEK_SET);
		CHECK_CUR_OFFSET(fd, 0);

		ret = pfsd_write(fd, "0", 1);
		CHECK_RET(1, ret);
		len += 1;
		CHECK_FILESIZE(fd, len);
		CHECK_CUR_OFFSET(fd, len);
	}

	/*
	 * pwrite(2) BUGS:
	 * In linux, if a file is opened with O_APPEND, pwrite() appends
	 * data to the end of the file, regardless of the value of offset.
	 */
	off_t oldoff = pfsd_lseek(fd, 0, SEEK_SET);
	for (int i = 1; i < 3; i++) {
		ret = pfsd_pwrite(fd, "1", 1, 0);
		CHECK_RET(1, ret);
		len += 1;
		CHECK_FILESIZE(fd, len);
		/* pwrite doesn't modify file offset */
		CHECK_CUR_OFFSET(fd, oldoff);
	}

	pfsd_close(fd);
    // 6 O_TRUNC flag
    ret = pfsd_lseek(fd_, 0, SEEK_SET);
    fd = pfsd_open(pbdpath_.c_str(), O_TRUNC, 0);
    EXPECT_GT(fd, 0);
    CHECK_FILESIZE(fd, 0);
    CHECK_CUR_OFFSET(fd, 0);
    pfsd_close(fd);

}

TEST_F(FileTest, pfsd_creat)
{
    int fd;
    string path;

    /*
     * test create new file, create existed file,
     * for currently creat is implemented by open,
     * so repeated creat will not fail
     * */
    // 1.1 create new file
    path = "/" + g_testenv->pbdname_ + "/creat.txt";
    pfsd_unlink(path.c_str());
    errno = 0;
    fd = pfsd_creat(path.c_str(), 0);
    EXPECT_GT(fd, 0);
    pfsd_close(fd);

    // 1.2 create existed file
    fd = pfsd_creat(path.c_str(), 0);
    EXPECT_TRUE(fd >= 0);
    pfsd_close(fd);
    pfsd_unlink(path.c_str());
#if NOPASS_OPEN_DIR
    /* 2.1
     * BRIEF: try to use creat to creat dir, without O_DIRECTORY
     * EXPECT: set errno EISDIR
     * ACTUAL: no errno, but creat file type
     */
    path = "/" + g_testenv->pbdname_ + "/creat_dir/";
    pfsd_rmdir(path.c_str());
    errno = 0;
    fd = pfsd_creat(path.c_str(), 0);
    CHECK_ERR_RET(-1, fd, EISDIR);

    /* 2.2
     * BRIEF: try to use creat to open existed dir, without O_DIRECTORY
     * EXPECT: set errno EISDIR
     * ACTUAL: no errno
     */
    path = "/" + g_testenv->pbdname_ + "/creat_exist_dir/";
    pfsd_rmdir(path.c_str());
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    errno = 0;
    fd = pfsd_creat(path.c_str(), 0);
    CHECK_ERR_RET(-1, fd, EISDIR);
    pfsd_rmdir(path.c_str());
#endif

    // 3 test create file failed
    path = "/" + g_testenv->pbdname_ + "/no_exist_dir/creat_failed.txt";
    pfsd_unlink(path.c_str());
    fd = pfsd_creat(path.c_str(), 0);
    CHECK_ERR_RET(-1, fd, ENOENT);
}

TEST_F(FileTest, pfsd_close)
{
    int fd, ret;
    string path;
    struct stat fstat;

    // 1 test repeates close
    // 1.1 close normal file
    path = "/" + g_testenv->pbdname_ + "/close.txt";
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    EXPECT_GT(fd, 0);
    ret = pfsd_close(fd);
    CHECK_RET(0, ret);

    // 1.2 check fd has been released
    ret = pfsd_fstat(fd, &(fstat));
    CHECK_ERR_RET(-1, ret, EBADF);

    // 1.3 repeated close one fd
    ret = pfsd_close(fd);
    CHECK_ERR_RET(-1, ret, EBADF);
    pfsd_unlink(path.c_str());

#if 0
    // 2 test close unlinked file
    // never allowed
    path = "/" + g_testenv->pbdname_ + "/unlink_no_close1.txt";
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    EXPECT_GT(fd >= 0);
    ret = pfsd_unlink(path.c_str());
    CHECK_RET(0, ret);

    ret = pfsd_close(fd);
    CHECK_RET(0, ret);
#endif

    // 3 test close wrong fd
    fd = -1;
    ret = pfsd_close(fd);
    CHECK_ERR_RET(-1, ret, EBADF);

    /* TODO
     * consider EINTR
     */
}

TEST_F(FileTest, pfsd_unlink)
{
    int fd, fd1, ret;
    string path;
    std::string dirpath;

    // 1.1 test unlink normal file
    path = "/" + g_testenv->pbdname_ + "/unlink.txt";
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    pfsd_close(fd);
    fd1 = pfsd_open(path.c_str(), O_CREAT, 0);
    ret = pfsd_unlink(path.c_str());
    CHECK_RET(0, ret);

    // 1.2 repaeted unlink
    ret = pfsd_unlink(path.c_str());
    CHECK_ERR_RET(-1, ret, ENOENT);

    // 2 test unlink no_exist_file
    path = "/" + g_testenv->pbdname_ + "/no_exist_dir/unlink.txt";
    ret = pfsd_unlink(path.c_str());
    CHECK_ERR_RET(-1, ret, ENOENT);

    /*
     * PFS doesn't support unlink dir.
     */

    // 3 test unlink no_existed dir, unlink exist dir
    path = "/" + g_testenv->pbdname_ + "/unlink_dir/";
    pfsd_rmdir(path.c_str());
    errno = 0;
    ret = pfsd_unlink(path.c_str());
    CHECK_ERR_RET(-1, ret, EISDIR);
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    ret = pfsd_unlink(path.c_str());
    CHECK_ERR_RET(-1, ret, EISDIR);
    pfsd_rmdir(path.c_str());
    errno = 0;

    /* 4
     * test unlink not close file, PFS assumed
     * that unlink should be after all close,
     * so unlink will rm file.
     * ATTENTION:
     * In newest version, PFS unlink will wait all opened fds closed.
     * so we skip this test.
     */
    path = "/" + g_testenv->pbdname_ + "/unlink_no_close2.txt";
    fd = pfsd_open(path.c_str(), O_CREAT, 0);

    ret = pfsd_unlink(path.c_str());
    CHECK_RET(0, ret);

    fd = pfsd_open(path.c_str(), 0, 0);
    CHECK_ERR_RET(-1, fd, ENOENT);
    pfsd_close(fd);
    fd = pfsd_open(path.c_str(), O_CREAT | O_EXCL, 0);
    EXPECT_GT(fd, 0);

    ret = pfsd_close(fd);
    CHECK_RET(0, ret);
    ret = pfsd_unlink(path.c_str());
    CHECK_RET(0, ret);

    /**
     * test ENOENT
     */
     ret = pfsd_write(fd1, "34567890", 5);
     CHECK_ERR_RET(-1, ret, ENOENT);
     ret = pfsd_close(fd1);
     CHECK_RET(0, ret);

     fd = pfsd_open(path.c_str(), O_CREAT, 0);
     fd1 = pfsd_open((path+"1").c_str(), O_CREAT, 0);
     pfsd_rename(path.c_str(), (path+"1").c_str());
     ret = pfsd_write(fd1, "34567890", 5);
     CHECK_ERR_RET(-1, ret, ENOENT);
     ret = pfsd_close(fd1);
     CHECK_RET(0, ret);
     ret = pfsd_write(fd, "34567890", 5);
     CHECK_RET(5, ret);
     ret = pfsd_close(fd);
     CHECK_RET(0, ret);

    /*
     * EISDIR
     * pread a fd which represents a directory.
     */
    dirpath = "/" + g_testenv->pbdname_ + "/";
    ret = pfsd_unlink(dirpath.c_str());
    CHECK_ERR_RET(-1, ret, EISDIR);
}

TEST_F(FileTest, pfsd_stat)
{
    struct stat fstat;
    string path;
    int ret, fd;

    // 1 Check the file type
    path = "/" + g_testenv->pbdname_ + "/stat_file";
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    ret = pfsd_stat(path.c_str(), &(fstat));
    CHECK_RET(0, ret);
    EXPECT_TRUE(S_ISREG(fstat.st_mode));

    // 2 Stat one unlinked file
    pfsd_close(fd);
    pfsd_unlink(path.c_str());
    ret = pfsd_stat(path.c_str(), &(fstat));
    CHECK_ERR_RET(-1, ret, ENOENT);

    // 3 Check the dir type
    path = "/" + g_testenv->pbdname_ + "/fstat_dir";
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);

    ret = pfsd_stat(path.c_str(), &(fstat));
    CHECK_RET(0, ret);
    EXPECT_TRUE(S_ISDIR(fstat.st_mode));
    pfsd_rmdir(path.c_str());
}

TEST_F(FileTest, pfsd_fstat)
{
    struct stat fstat;
    string path;
    int fd, ret;

    // 1 Check the file type
    ret = pfsd_fstat(fd_, &(fstat));
    CHECK_RET(0, ret);
    EXPECT_TRUE(S_ISREG(fstat.st_mode));

    // 2 Check the dir type
    path = "/" + g_testenv->pbdname_ + "/fstat_dir";
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);

    fd = pfsd_open(path.c_str(), O_DIRECTORY, 0);
    ret = pfsd_fstat(fd, &(fstat));
    CHECK_RET(0, ret);
    EXPECT_TRUE(S_ISDIR(fstat.st_mode));
    pfsd_close(fd);
    pfsd_rmdir(path.c_str());

    // 3 Stat one closed fd
    pfsd_close(fd_);
    ret = pfsd_fstat(fd_, &(fstat));
    CHECK_ERR_RET(-1, ret, EBADF);
    fd_ = pfsd_open(pbdpath_.c_str(), 0, 0);
#if 0
#if NOPASS_FSTAT
    /* 4
     * BRIEF : stat on unliked but no_closed file
     * EXPECT: set errno ENOENT
     * ACTUAL: pfs crash
     */
    path = "/" + g_testenv->pbdname_ + "/fstat_file";
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    EXPECT_TRUE(fd >= 0);
    errno = 0;
    pfsd_unlink(path.c_str());
    ret = pfsd_fstat(fd, &(fstat));
    CHECK_ERR_RET(-1, ret, ENOENT);
    pfsd_close(fd);
    errno = 0;
#endif
#endif
    // 5 Stat on bad fd
    fd = -1;
    ret = pfsd_fstat(fd, &(fstat));
    CHECK_ERR_RET(-1, ret, EBADF);
}

TEST_F(FileTest, pfsd_truncate)
{
    off_t len;
    int ret;
    string path;

    // 1 write len 10 to file
    len = pfsd_write(fd_, "0123456789", 10);
    CHECK_RET(10, len);
    CHECK_CUR_OFFSET(fd_, 10);
    CHECK_FILESIZE(fd_, 10);

    // 1 change len
    // 1.1 truncate len 10 = fsize
    len = 100;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    // 1.2 truncate len 100 > fsize
    len = 100;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    // 1.3 truncate len 5 < fsize
    len = 5;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    // 1.4 truncate len -2 < 0
    len = -2;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_ERR_RET(-1, ret, EINVAL);
    CHECK_FILESIZE(fd_, 5);

    // 1.5 truncate len 100G
    len = (off_t)100*UNIT_1G;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    ret = pfsd_truncate(pbdpath_.c_str(), 10);
    // 1.5 truncate len OFF_MIN
    len = (off_t)OFF_MIN;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_ERR_RET(-1, ret, EINVAL);
    CHECK_FILESIZE(fd_, 10);

#if NOPASS_TRUNCATE
    // 1.5 truncate len OFF_MAX
    /*
     * BRIEF : truncate len OFF_MAX
     * EXPECT: set errno EFBIG
     * ACTUAL: it just really allocate such large
     */
    len = (off_t)OFF_MAX;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_ERR_RET(-1, ret, EFBIG);
    CHECK_FILESIZE(fd_, 10);
#endif

    // 1.6 truncate len >0 fsize < 0
    len = 0;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, 0);

    len = 1024*1024*4;
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    /* 2
     * BRIEF:truncate a dir
     * EXPECT: Set errno EISDIR
     */
    path = "/" + g_testenv->pbdname_ + "/truncate_dir";
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    len = 0;
    ret = pfsd_truncate(path.c_str(), len);
    CHECK_ERR_RET(-1, ret, EISDIR);

    // 3 truncate non-exist file
    path = "/" + g_testenv->pbdname_ +"/truncate_no_exist";
    len = 0;
    ret = pfsd_truncate(path.c_str(), len);
    CHECK_ERR_RET(-1, ret, ENOENT);


    /* TODO
     * EACCESS
     * EINTR
     * ELOOP
     * ENAMETOOLONG
     */
}

TEST_F(FileTest, pfsd_ftruncate)
{
    off_t len;
    int ret, fd;
    string path;
    // write len 10 to file
    len = pfsd_write(fd_, "0123456789", 10);
    CHECK_RET(10, len);
    CHECK_CUR_OFFSET(fd_, 10);
    CHECK_FILESIZE(fd_, 10);

    // 1 chaneg len
    // 1.1 truncate len 10 = fsize
    len = 100;
    ret = pfsd_ftruncate(fd_, len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    // 1.2 truncate len 100 > fsize
    len = 100;
    ret = pfsd_ftruncate(fd_, len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    // 1.3 truncate len 5 < fsize
    len = 5;
    ret = pfsd_ftruncate(fd_, len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    // 1.4 truncate len -2 < 0
    len = -2;
    ret = pfsd_ftruncate(fd_, len);
    CHECK_ERR_RET(-1, ret, EINVAL);
    CHECK_FILESIZE(fd_, 5);

    // 1.5 truncate len 100G
    len = (off_t)100*UNIT_1G;
    ret = pfsd_ftruncate(fd_, len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    // 1.6 truncate len off_min
    ret = pfsd_ftruncate(fd_, 10);
    len = OFF_MIN;
    ret = pfsd_ftruncate(fd_, len);
    CHECK_ERR_RET(-1, ret, EINVAL);
    CHECK_FILESIZE(fd_, 10);

    /* 2
     * BRIEF:truncate a dir
     * EXPECT: Set errno EISDIR
     */
    path = "/" + g_testenv->pbdname_ + "/truncate_dir";
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    fd = pfsd_open(path.c_str(), 0, 0);
    errno = 0;
    len = 0;
    ret = pfsd_ftruncate(fd, len);
    CHECK_ERR_RET(-1, ret, EISDIR);
    pfsd_close(fd);

    // 3 truncate invalid fd
    len = 0;
    fd = -1;
    ret = pfsd_ftruncate(fd, len);
    CHECK_ERR_RET(-1, ret, EBADF);

#if NOPASS_TRUNCATE
    /* 4
     * BRIEF : truncate one unlinked but no closed fd
     * EXPECT: set errno EBADF
     * ACTUAL: no err
     */
    path = "/" + g_testenv->pbdname_ + "/truncate_no_close";
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    pfsd_unlink(path.c_str());
    errno = 0;
    len = 0;
    ret = pfsd_ftruncate(fd, len);
    CHECK_ERR_RET(-1, ret, EBADF);
    pfsd_close(fd);
#endif

    /* TODO
     * EACCESS
     * EINTR
     * ELOOP
     * ENAMETOOLONG
     */
}

TEST_F(FileTest, pfsd_posix_fallocate)
{
    off_t len, old_len, offset;
    int ret, fd;
    string path;

    // 1 change len
    // 1.1 write len 10 to file
    len = pfsd_write(fd_, "0123456789", 10);
    CHECK_RET(10, len);
    CHECK_CUR_OFFSET(fd_, 10);
    CHECK_FILESIZE(fd_, 10);

    // 1.2 fallocate len 100 > fsize
    len = 100;
    old_len = len;
    ret = pfsd_posix_fallocate(fd_, 0, len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, len);

    // 1.3 fallocate len + off = 5 < fsize
    len = 5;
    ret = pfsd_posix_fallocate(fd_, 0, len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, old_len);

    // 1.4 fallocate len -2 < 0
    len = -2;
    ret = pfsd_posix_fallocate(fd_, 0, len);
    CHECK_ERR_RET(-1, ret, EINVAL);
    CHECK_FILESIZE(fd_, old_len);

    // 1.5 fallocate offset 100 > fsize
    offset = 100;
    len = 500;
    old_len = len;
    ret = pfsd_posix_fallocate(fd_, offset, len);
    CHECK_RET(0, ret);
    CHECK_FILESIZE(fd_, 600);

    // 1.6 fallocate len -2 < 0
    offset = -2;
    len = 500;
    ret = pfsd_posix_fallocate(fd_, offset, len);
    CHECK_ERR_RET(-1, ret, EINVAL);
    CHECK_FILESIZE(fd_,  600);

    // 1.7 BRIEF: fallocate len off_max
    len = OFF_MAX;
    ret = pfsd_posix_fallocate(fd_, 0, len);
    CHECK_ERR_RET(-1, ret, ENOSPC);
    CHECK_FILESIZE(fd_, 600);

    /* 2
     * BRIEF : fallocate a dir
     * EXPECT: Set errno EISDIR
     */
    path = "/" + g_testenv->pbdname_ + "/truncate_dir";
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    fd = pfsd_open(path.c_str(), 0, 0);
    errno = 0;
    len = 100;
    ret = pfsd_posix_fallocate(fd, 0, len);
    CHECK_ERR_RET(-1, ret, EISDIR);
    pfsd_close(fd);

    // 3 fallocate invalid fd
    len = 10;
    fd = -1;
    errno = 0;
    ret = pfsd_posix_fallocate(fd, 0, len);
    CHECK_ERR_RET(-1, ret, EBADF);

#if NOPASS_TRUNCATE
    /* 4
     * BRIEF : fallocate one unlinked but no closed fd
     * EXPECT: set errno EBADF
     * ACTUAL: no err
     */
    path = "/" + g_testenv->pbdname_ + "/fallocate_no_close";
    fd = pfsd_open(path.c_str(), O_CREAT, 0);
    pfsd_unlink(path.c_str());
    errno = 0;
    len = 10;
    ret = pfsd_posix_fallocate(fd, 0, len);
    CHECK_ERR_RET(-1, ret, EBADF);
    pfsd_close(fd);
#endif

    /* 5
     * BRIEF:  fallocate on read-only fs
     * EXPECT: set errno EROFS
     * ACTUAL: errno = EACCES
     */
    len = 10;
    // umount, then mount with read-only mode
    pfsd_close(fd_);
    fd_ = -1;
    ret = g_testenv->umount();
    EXPECT_EQ(0, ret);
    errno = 0;
    ret = g_testenv->mount(PFS_RD);
    CHECK_RET(0, ret);

    // try to mkdir in read-only PBD
    fd_ = pfsd_open(pbdpath_.c_str(), 0, 0);
    ret = pfsd_posix_fallocate(fd_, 0, len);
    CHECK_ERR_RET(-1, ret, EROFS);
    pfsd_close(fd_);

    ret = g_testenv->umount();
    CHECK_RET(0, ret);
    ret = g_testenv->mount(PFS_RDWR);
    fd_ = pfsd_open(pbdpath_.c_str(), 0, 0);
    CHECK_RET(0, ret);
    pfsd_close(fd_);


    /* TODO
     * EACCESS
     * EINTR
     * ELOOP
     * ENAMETOOLONG
     */
}

TEST_F(FileTest, pfsd_access)
{
    int err;

    // 1 check correctness
    string path = "/" + g_testenv->pbdname_ + "/FileTest.txt";
    struct fileobj ff(path, O_CREAT);
    err = pfsd_access(path.c_str(), F_OK);
    EXPECT_EQ(err, 0);

    err = pfsd_access(path.c_str(), R_OK | W_OK | X_OK);
    EXPECT_EQ(err, 0);

    // 2 access non existed file
    path = "/" + g_testenv->pbdname_ + "/FileTest_notexist.txt";
    err = pfsd_access(path.c_str(), F_OK);
    CHECK_ERR_RET(-1, err, ENOENT);

    err = pfsd_access(path.c_str(), R_OK | W_OK | X_OK);
    CHECK_ERR_RET(-1, err, EACCES);

    pfsd_unlink(path.data());

#if NOPASS_ACCESS
    /* 3
     * BRIEF: access a dir
     * EXPECT: Set errno EISDIR
     * ACTUAL: no error but no modify on dir
     */
    path = "/" + g_testenv->pbdname_ + "/access_dir";
    pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    errno = 0;
    err = pfsd_access(path.c_str(), R_OK);
    CHECK_ERR_RET(-1, err, EISDIR);
    pfsd_rmdir(path.c_str());
    errno = 0;
#endif
    /* TODO
     * EACCESS
     * EINTR
     * ELOOP
     * ENAMETOOLONG
     * ENOMEM
     * ENOTDIR
     */

}

TEST_F(FileTest, pfsd_path_test)
{
    string path;
    int fd, ret;

    string workpath = g_testenv->pbdname_ + "/pfsd_path_test_dir";

    /*
     * Check with different kind of path, check the errno
     */
    // 1 path = "."
    path = "/" + workpath + "/";
    ret = pfsd_mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_EQ(ret, 0);
    ret = pfsd_chdir(path.c_str());
    EXPECT_EQ(0, ret);
    ret = pfsd_rmdir(path.c_str());
    ASSERT_EQ(ret, 0);

    path = ".";
    errno = 0;
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    CHECK_ERR_RET(-1, fd, ENOENT);

    // 2 path = "/"
    path = "/";
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    CHECK_ERR_RET(-1, fd, EINVAL);

    // 3 path = ""
    path = "";
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    CHECK_ERR_RET(-1, fd, EINVAL);

    // 4 path = NULL
    path = "";
    fd = pfsd_open(NULL, O_CREAT | O_RDWR, 0);
    CHECK_ERR_RET(-1, fd, EINVAL);

    // 5 path = "/pbdname"
    path = "/" + g_testenv->pbdname_;
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    CHECK_ERR_RET(-1, fd, EINVAL);

    // 6 path = "/pbdname//"
    path = "/" + workpath + "//";
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    CHECK_ERR_RET(-1, fd, EISDIR);

    // 7 path = "//"
    path = "//";
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    CHECK_ERR_RET(-1, fd, EINVAL);

    // 8 path = "//pbdname/"
    path = "//" + workpath + "/";
    fd = pfsd_open(path.c_str(), O_CREAT | O_RDWR, 0);
    CHECK_ERR_RET(-1, fd, EISDIR);
}

#if NOPASS_ROFS
/*
 * BRIEF:  try to umount then mount
 * EXPECT: no err when umount
 * ACTUAL: errno = EINVAL
 */
TEST_F(FileTest, pfsd_ROFS_test)
{
    int ret = 0;
    // umount, then mount with read-only mode
    errno = 0;
    ret = g_testenv->umount();
    CHECK_RET(0, ret);
    ret = g_testenv->mount(PFS_RD);
    CHECK_RET(0, ret);

    ssize_t len = 100;
    /*
     * BRIEF: truncate on read-only fs
     * EXPECT: set errno EROFS
     * ACTUAL: errno = EACCES
     */
    // 1 try to check access permission in read-only PBD
    errno = 0;
    ret = pfsd_access(pbdpath_.c_str(), R_OK | W_OK | X_OK);
    CHECK_ERR_RET(-1, ret, EROFS);

    // 2 try to truncate in read-only PBD
    ret = pfsd_truncate(pbdpath_.c_str(), len);
    CHECK_ERR_RET(-1, ret, EROFS);

    // 3 try to ftruncate in read-only PBD
    len = 5;
    fd_ = pfsd_open(pbdpath_.c_str(), 0, 0);
    ret = pfsd_ftruncate(fd_, len);
    CHECK_ERR_RET(-1, ret, EROFS);

    // 4 try to ftruncate in read-only PBD

    // 5 try to fallocate in read-only PBD
    ret = pfsd_posix_fallocate(fd_, 0, len);
    CHECK_ERR_RET(-1, ret, EROFS);

    // 6 try to write in read-only PBD
    ret = pfsd_write(fd_, "0123456789", len);
    CHECK_ERR_RET(-1, ret, EROFS);
    pfsd_close(fd_);

    errno = 0;
    ret = g_testenv->umount();
    CHECK_RET(0, ret);
    ret = g_testenv->mount(PFS_RDWR);
    fd_ = open(pbdpath_.c_str(), 0, 0);
    CHECK_RET(0, ret);
}
#endif

TEST_F(FileTest, pfsd_large_rdwr)
{
    char *wrbuf, *rdbuf;
    int repeat = UNIT_1G / UNIT_4M;
    int len = 0;
    int offset = 0;

    wrbuf = (char *) calloc(1, UNIT_4M);
    rdbuf = (char *) calloc(1, UNIT_4M);
    ASSERT_TRUE(wrbuf);
    ASSERT_TRUE(rdbuf);

    len = pfsd_pwrite(fd_, wrbuf, UNIT_4K, 0);
    offset += len;

    for (int i =0; i< repeat; i++) {
        len = pfsd_pwrite(fd_, wrbuf, UNIT_4M, offset);
        EXPECT_EQ(UNIT_4M, len);
        offset += len + UNIT_4K;
    }
    CHECK_FILESIZE(fd_, UNIT_1G + UNIT_4K*repeat);

    offset = 0;
    len = 0;
    for (int i = 0; i< repeat; i++) {
        offset += len + UNIT_4K;
        len = pfsd_pread(fd_, rdbuf, UNIT_4M, offset);
        EXPECT_EQ(UNIT_4M, len);
        EXPECT_TRUE(!strncmp(rdbuf, wrbuf, UNIT_4M));
    }
    free(wrbuf);
    free(rdbuf);
}

TEST_F(FileTest, positive_pfsd_align)
{
#define	PFS_MAX_ALIGN_SIZE	(16 << 11)

	char			buf[PFS_MAX_ALIGN_SIZE] = {0};
	uint32_t		idx = 0;
	ssize_t 		len = 0;
	uint32_t		curr_offset = 0;

	for (idx = 0; idx < (PFS_MAX_ALIGN_SIZE); idx++)
	{
		buf[idx] =  (char)((idx % 95) + 32);
	}

	errno = 0;
	len = pfsd_write(fd_, buf, 0);
	EXPECT_EQ(len, 0);
	EXPECT_EQ(errno, 0);
	CHECK_CUR_OFFSET(fd_, 0);

	len = pfsd_write(fd_, buf, 511);		// 511 < 512, align to 512
	EXPECT_EQ(len, 511);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 512);		// align to 512
	EXPECT_EQ(len, 512);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 1023);	// align to 1024
	EXPECT_EQ(len, 1023);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 1024);	// align to 1024
	EXPECT_EQ(len, 1024);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 1025);	// align to 2048
	EXPECT_EQ(len, 1025);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 2048);	// align to 2048
	EXPECT_EQ(len, 2048);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 2049);	// align to 4096
	EXPECT_EQ(len, 2049);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 4096);	// align to 4096
	EXPECT_EQ(len, 4096);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 4097);	// align to 8192
	EXPECT_EQ(len, 4097);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 8192);	// align to 8192
	EXPECT_EQ(len, 8192);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 8193);	// align to 16384
	EXPECT_EQ(len, 8193);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 16384);	// align to 16484
	EXPECT_EQ(len, 16384);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	len = pfsd_write(fd_, buf, 16385);	// align to 16484
	EXPECT_EQ(len, 16385);
	curr_offset += len;
	CHECK_CUR_OFFSET(fd_, curr_offset);
	CHECK_FILESIZE(fd_, curr_offset);

	// If result file offset is bigger than the offset maximum,
	// no data transfer shall occur.
	pfsd_lseek(fd_, OFF_MAX, SEEK_SET);
	len = pfsd_write(fd_, buf, 10);
	EXPECT_EQ(len, -1);
	EXPECT_EQ(errno, EFBIG);
}

