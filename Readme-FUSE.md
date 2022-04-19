# FUSE on PFS

Filesystem in USErspace (FUSE) is a software interface for Unix and Unix-like computer operating systems that lets non-privileged users create their own file systems without editing kernel code. This is achieved by running file system code in user space while the FUSE module provides only a bridge to the actual kernel interfaces.

To allow users to use PFS with kernel interfaces like any other kernel built-in filesystems, we implement a FUSE on PFS handler program, which is linked to the supplied LibFUSE library. This program defines the request-respond mapping of kernal interfaces to pfs operations, which means it specify how PFS is to respond to read/write/stat requests. The program is also used to mount PFS. At the time PFS is mounted, the handler is registered with the kernel. If a user now issues read/write/stat requests for PFS, the kernel forwards these IO-requests to the handler and then sends the handler's response back to the user.

# Main FUSE Modules

#### FUSE kernel module (kernel state)

The FUSE kernel module implements the VFS interface (which implements the registration of the fuse file driver, the fuse device driver, and provides maintenance of super blocks, inode, etc.)  It receives requests from VFS and passes them to LibFUSE, and then LibFUSE passes requests to PFS handler program;

#### LibFUSE module (user state)

LibFUSE implements the main framework of the file system, the encapsulation of PFS operations, mount management and communication with the kernel module via /dev/fuse device;

#### User program module (user state)

User programs implement  PFS operations encapsulated by the LibFUSE library in user space.

# Interfaces

FUSE interfaces are defined in`fusepfs_operations`, mainly divided into the following categories :

1. FUSE environment building: init, destroy

2. file operations: create, mknod, open, rename, truncate, ftruncate

3. directory operations: mkdir, opendir, readdir, rmdir

4. link: symlink, readlink, unlink

5. file attribute: statfs, access, getattr, fgetattr

6. extended attribute: getxattr, setxattr, listxattr, removexattr

7. R/W: read, write, read_buf, write_buf, fallocate

8. Sync I/O: fsync, fsyncdir

9. multiplexing: poll

10. release: release, releasedir

11. other: ioctl, lock, bmap


#  Use FUSE on PFS

#### 1. Install PFS Dependencies

Refer to 【Install Dependencies】part in document [Readme.md](./Readme.md) for installation steps

#### 2. Load FUSE Module

##### I. Download FUSE resource package and decompress

```	bash
tar -zxvf fuse.tar.gz
```
Recommended FUSE version: 2.9.2

##### II. Install FUSE (fuse 3.2 or above needs Meson or Ninj)

```bash
./configure && sudo make install
```

##### III. Check

````bash
# check if FUSE is mounted successfully
lsmod | grep fuse
# If not, you can use `modprobe fuse` to mount FUSE.
modprobe fuse
# Look up version information
fusermount --version
````

#### 3. Complie and Install

After the dependencies are installed, go to the root directory of PFS source code and run the  script to compile and install PFS.

```bash
./autobuild.sh && sudo ./install.sh
```

#### 4. Usage

##### I. mount FUSE on PFS

Before mounting, you need to configure /etc/fuse.conf:
add  `user_allow_other` to the file

```bash
/usr/local/polarstore/pfsd/bin/mount_pfs_fuse.sh [-p diskname] [-c rw/ro] mount_dir
# example
/usr/local/polarstore/pfsd/bin/mount_pfs_fuse.sh -p nvme1n1 -c rw ./fuse_mntdir
```

`diskname`      block device. you can get the information of all your available block devices with shell command  `lsblk`;

`rw/ro`         startup a read&write or read-only instance;

`mount_dir`     fuse mount directory.

p.s. Mounting FUSE on PFS will first start pfsdaemon in the background, then start pfs-fuse process, pfs-fuse will mount PFS to the specified directory.

##### II. Visit PFS by FUSE

After starting a pfsdfuse instance in background, now you can `cd` into the mount directory to operate PFS like a kernel built-in file system as usual. The results of all operations will be sent into the disk mounted via PFS. Here is an example :

```bash
# enter mount directory
$cd path/to/fuse_mount_dir
# create file and write
$echo "hello pfs fuse">test_file.txt
# show new file
$cat test_file.txt
hello pfs fuse
```

##### III. Stop using FUSE on PFS

1. Umount FUSE on pfs


```bash
/usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh [mount_dir/all]
# example
/usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh  /fuse_mntdir
/usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh  all
```

your can appoint a `mount_dir` to umount the selected instance, `mount dir` should be pointed as absolute path;
your can also choose `all` to umount all mounted pfsdfuse instance.

2. Stop pfsdaemon

You can stop single pfsdaemon by pointing a diskname of the pfsdaemon, or you can kill all pfsdaemons by running stop_pfsd.sh without any parameter.

```bash
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh [diskname]
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh

example:
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh nvme1n1
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh
```

##### IV. Run the uninstall.sh script to uninstall pfsdaemon

```
sudo ./uninstall.sh
```