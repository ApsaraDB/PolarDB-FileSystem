# FUSE on pfs

用户态文件系统（FUSE）是Unix和类似Unix的计算机操作系统的一个软件接口，允许非特权用户在不编辑内核代码的情况下创建自己的文件系统。这是通过在用户空间运行文件系统代码来实现的，而FUSE模块只提供了一个通往实际内核接口的桥梁。

为了让用户像其他内核内置文件系统一样使用PFS的内核接口，我们实现了一个FUSE on PFS的处理程序，它被链接到LibFUSE库。这个程序定义了内核接口与 PFS 操作的请求-响应映射，即它指定了PFS如何响应读/写/统计请求。同时，这个程序也被用来挂载 PFS，在挂载PFS的时候，处理程序被注册到内核中。如果用户现在对PFS发出读/写/统计请求，内核会将这些IO请求转发给处理程序，然后将处理程序的响应发回给用户。

# FUSE主要模块

##### FUSE内核模块（内核状态）

FUSE内核模块实现了VFS接口（它实现了fuse文件驱动、fuse设备驱动的注册，并提供了超级块、inode等的维护）。它接收来自VFS的请求并将其传递给LibFUSE，然后LibFUSE将请求传递给PFS处理程序；

##### LibFUSE模块（用户态）

LibFUSE实现了文件系统的主要框架、PFS操作的封装、挂载管理以及通过/dev/fuse设备与内核模块的通信；

##### 用户程序模块（用户态）

用户程序在用户空间实现由LibFUSE库封装的PFS操作。

# 接口

FUSE接口在`fusepfs_operations`中定义，主要分为以下几类。

1. FUSE环境构建：init, destroy

2. 文件操作：create, mknod, open, rename, truncate, ftruncate

3. 目录操作：mkdir, opendir, readdir, rmdir

4. 链接：symlink, readlink, unlink

5. 文件属性：statfs, access, getattr, fgetattr

6. 扩展属性：getxattr, setxattr, listxattr, removexattr

7. 读写：read, write, read_buf, write_buf, fallocate

8. 同步I/O：fsync, fsyncdir

9. 多路复用：poll

10. 释放：release, releasedir

11. 其他：ioctl, lock, bmap

# 使用FUSE on PFS

#### 1. 安装PFS依赖

安装步骤详见文档[Readme-CN.md](./Readme-CN.md)中的【安装依赖】

#### 2. 加载FUSE模块

##### I. 下载FUSE资源包并解压

```bash
tar -zxvf fuse.tar.gz
```

推荐FUSE版本：2.9.2

##### II. 安装FUSE（3.2版本或以上需要安装Meson或Ninj）

```bash
./configure && sudo make install
```

##### III. 检查是否加载成功

```bash
# 检查FUSE模块是否加载成功
lsmod | grep fuse
# 如果尚未加载成功，你可以通过以下命令来挂载FUSE
modprobe fuse
# 查看版本信息
fusermount --version
```

#### 3. 编译与安装

依赖项准备好后，进入代码根目录，执行脚本进行编译：

```bash
./autobuild.sh && sudo ./install.sh
```

#### 4. 使用FUSE

##### I. 挂载FUSE on PFS

挂载前需要对/etc/fuse.conf进行配置，在文件中添加一行`user_allow_other`即可

```bash
/usr/local/polarstore/pfsd/bin/mount_pfs_fuse.sh [-p diskname] [-c rw/ro] mount_dir
# 示例
/usr/local/polarstore/pfsd/bin/mount_pfs_fuse.sh -p nvme1n1 -c rw ./fuse_mntdir
```

`diskname`代表块设备名称。可以通过命令`lsblk`列出所有可用块设备信息；

`rw/ro`代表所启动实例为启动读写实例或者只读实例；

`mount_dir`指fuse挂载目录。

说明：挂载FUSE on PFS首先会启动pfsdaemon后台进程，然后启动pfs-fuse进程并挂载PFS到制定目录。

##### II. 通过FUSE访问PFS

在后台启动FUSE实例后，现在你可以 `cd` 进入挂载目录，像平常使用内核内置的文件系统一样操作PFS。所有操作的结果将被送入PFS挂载的磁盘。示例如下：

```bash
# 进入挂载目录
$cd path/to/fuse_mount_dir
# 创建文件 写文件
$echo "hello pfs fuse">test_file.txt
# 打印文件内容
$cat test_file.txt
hello pfs fuse
```

##### III. 结束使用

1. 解挂FUSE on PFS

你可以通过单独指定一个挂载路径来解挂特定FUSE实例，路径需要以绝对路径的形式指定；
也可以选择`all`参数来解挂所有已挂载的PFS FUSE实例。

```bash
/usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh [mount_dir/all]
# 示例
/usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh  /fuse_mntdir
/usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh  all
```

2. 停止pfsdaemon后台进程

支持两种方式：
1. 通过盘名以停止指定pfsdaemon
2. 以停止所有正在运行的pfsdaemon

```bash
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh [diskname]
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh

example:
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh nvme1n1
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh
```

##### IV. 使用卸载脚本uninstall.sh进行卸载：

```bash
sudo ./uninstall.sh
```