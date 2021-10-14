The PFS tool is used only for debugging and testing. This document describes the commands that you can use in the PFS tool. 
# 1. File System-Related Commands

## 1.1 Overview

| Command | Description | Options |
| --- | --- | --- |
| mkfs | Formats a disk into a file system. | `-u`: specifies the maximum number of writable hosts to which the file system can be mounted.<br>`-l`: specifies the size of the journal file on the disk.<br>`-f`: enables forced formatting.  |
| growfs | Formats the chunks that are added after a storage capacity expansion. | `-o`: specifies the number of chunks before the storage capacity expansion.<br>`-n`: specifies the number of chunks after the storage capacity expansion.<br>`-f`: enables forced formatting.  |
| info | Queries the metadata of the file system on a disk. | None. |
| dumpfs | Queries the metadata that is stored in one chunk or all chunks on a disk from the super blocks of these chunks. | `-m`: queries the metadata that is stored in one chunk or all chunks on the disk. If you do not configure this option, the system returns the headers of these chunks.<br>`-t`: specifies the type of metadata that you want to query.<br>`-c`: specifies the ID of the chunk whose metadata you want to query.<br>`-o`: specifies the serial number of the Metadata object that you want to query. |
| dumple | Queries the log entries of the journal file on a disk. | `-a`: traverses all visible log entries of the journal file.<br>`-t`: specifies the ID of the log entry that you want to query.<br>`-b`: specifies the serial number of the block tag whose log entries you want to query.<br>`-d`: specifies the serial number of the directory entry whose log entries you want to query.<br>`-i`: specifies the serial number of the inode whose log entries you want to query. |

## 1.2 mkfs

- Description: This command is used to format a disk into a file system. 
- Options:
   - `-u`: (Optional) specifies the maximum number of writable hosts to which the file system can be mounted. Default value: 3. Maximum value: 255. 
   - `-f`: (Optional) enables forced formatting. 
- Example:

```bash
# Format the nvme1n1 disk into a file system.
# The -C disk option specifies that the disk that you want to format is a local disk. In this example, the name of the local disk is nvme1n1. 
$sudo pfs -C disk mkfs nvme1n1

# If the system returns the "already formatted" message, check that the mkfs command is run in a ready environment. Then, add the -f option following the mkfs command.
$sudo pfs -C disk mkfs -f nvme1n1

# Format the nvme1n1 disk into a file system. In this example, the file system can be mounted to a maximum of 10 writable hosts.
$sudo pfs -C disk mkfs -u 10 nvme1n1
```

## 1.3 growfs

- Description: This command is used to format the chunks that are added after a storage capacity expansion. The IDs of the chunks that need to be formatted are within the [-o, -n) interval.
- Options:
   - `-o`: specifies the number of chunks before the storage capacity expansion. 
   - `-n`: specifies the number of chunks after the storage capacity expansion. 
   - `-f`: (Optional) enables forced formatting. 
- Examples:

```bash
# Format the chunks that are added to the nvme1n1 disk after the storage capacity of the disk is expanded from 10 GB to 30 GB. In this example, the IDs of the chunks are within the [1, 3) interval.
$sudo pfs -C disk growfs -o 1 -n 3 nvme1n1

# If the system returns the "already formatted" message, check that the growfs command is run in a safe environment. Then, add the -f option following the growfs command.
$sudo pfs -C disk growfs -o 1 -n 3 -f nvme1n1
```

## 1.4 info

- Description: This command is used to query the metadata of the file system on a disk. 
   - The number of directory levels whose metadata you want to query is fixed to 1 and cannot be changed. 
- Examples:

```bash
# Query the metadata of the file system on the nvme1n1 disk.
$sudo pfs -C disk info nvme1n1
Blktag Info:
 (0)allocnode: id 0, shift 0, nchild=3, nall 7680, nfree 1897, next 0
Direntry Info:
 (0)allocnode: id 0, shift 0, nchild=3, nall 6144, nfree 5974, next 0
Inode Info:
 (0)allocnode: id 0, shift 0, nchild=3, nall 6144, nfree 5974, next 0
# The nchild parameter indicates the number of chunks in the file system. The total storage space of the disk is equal to 10 GB multiplied by the value of the nchild parameter. In this example, the total storage space of the nvme1n1 disk is 30 GB.
# The storage capacity of idle blocks on the disk is equal to 4 MB multiplied by 1,897.
```

## 1.5 dumpfs

- Description: This command is used to query the metadata that is stored in one chunk or all chunks on a disk from the super blocks of these chunks. 
- Options:
   - `-m`: queries the metadata that is stored in one chunk or all chunks on the disk. If you do not configure this option, the system returns the headers of these chunks.
   - `-t`: specifies the type of metadata that you want to query. The value 1 specifies to query block tags. The value 2 specifies to query directory entries. The value 3 specifies to query inodes.
   - `-c`: specifies the ID of the chunk that stores the metadata you want to query.
   - `-o`: specifies the serial number of the Metadata object that you want to query.
- Examples:

```bash
# Query the headers of all chunks on the nvme1n1 disk and the metadata that is stored in these chunks.
$sudo pfs -C disk dumpfs nvme1n1
chunk 0:
    ck_magic   0x5046534348
    ck_chunksize 10737418240
    ck_blksize 4194304
    ck_sectsize 4096
    ck_number  0
    ck_nchunk  3
    ck_checksum 2628069786
    ck_physet[MT_BLKTAG].ms_nsect 80
    ck_physet[MT_DIRENTRY].ms_nsect 64
    ck_physet[MT_INODE].ms_nsect 64
    ck_physet[MT_BLKTAG].ms_sectbda 0x1000
    ck_physet[MT_DIRENTRY].ms_sectbda 0x51000
    ck_physet[MT_INODE].ms_sectbda 0x91000
............
type    free    used    total
blktag  7668    12      7680
dentry  6141    3       6144
inode   6141    3       6144

# Query Inode 1 that is stored in Chunk 0 on the nvme1n1 disk.
$sudo pfs -C disk dumpfs -m -c 0 -t 3 -o 1 nvme1n1
 mo_type    inode
 mo_number  1
 mo_checksum 3315235856
 mo_used    1
 mo_version 0
 mo_head    1
 mo_tail    1
  in_type    1
  in_deno    1
  in_flags   0
  in_nlink   1
  in_nblock  1
  in_size    4194304
  in_atime   0
  in_ctime   1551271708
  in_mtime   1551271708
```

## 1.6 dumple

- Description: This command is used to query the log entries of the journal file on a disk. 
- Options:
   - `-a`: traverses all visible log entries in the journal file. If you do not configure this option, the system traverses only the valid log entries in the journal file.
   - `-t`: specifies the ID of the log entry that you want to query.
   - `-b`: specifies the serial number of the block tag whose log entries you want to query.
   - `-d`: specifies the serial number of the directory entry whose log entries you want to query.
   - `-i`: specifies the serial number of the inode whose log entries you want to query.
- Examples:

```bash
# Query all log entries in the journal file on the nvme1n1 disk. These include the log entries that are trimmed.
$sudo pfs -C disk dumple -a nvme1n1
 le_txid    1
 le_lsn     1
 le_sector_bda 10737750016
 le_obj_idx 0
 le_checksum 3912500790
 le_more    1
  mo_type    direntry
  mo_number  2048
  mo_checksum 1467810822
  mo_used    1
  mo_version 0
  mo_next    0
  mo_prev    2
    de_dirino  0
    de_ino     2048
    de_name    largefile
...
 le_txid    2
 le_lsn     6
 le_sector_bda 10738012160
 le_obj_idx 0
 le_checksum 278390252
 le_more    0
  mo_type    inode
  mo_number  2048
  mo_checksum 3233154735
  mo_used    1
  mo_version 0
  mo_head    528385
  mo_tail    528385
    in_type    1
    in_deno    2048
    in_flags   0
    in_nlink   1
    in_nblock  1
    in_size    0
    in_atime   0
    in_ctime   1551337605
    in_mtime   1551337605
[PFS_LOG] Mar  6 15:25:42.498594 INF [82650] number of log entries hit:6 / 2097152 (all in journal)

# Traverse only the valid log entries in the journal file on the nvme1n1 2 disk to find Log Entry 2 that records an update to Inode 2048.
$sudo pfs -C disk dumple -t 2 -i 2048 nvme1n1
 le_txid    2
 le_lsn     6
 le_sector_bda 10738012160
 le_obj_idx 0
 le_checksum 278390252
 le_more    0
  mo_type    inode
  mo_number  2048
  mo_checksum 3233154735
  mo_used    1
  mo_version 0
  mo_head    528385
  mo_tail    528385
    in_type    1
    in_deno    2048
    in_flags   0
    in_nlink   1
    in_nblock  1
    in_size    0
    in_atime   0
    in_ctime   1551337605
    in_mtime   1551337605
[PFS_LOG] Mar  6 15:32:03.101423 INF [105651] number of log entries hit:1 / 6 (valid)
```

# 2. File&Directory-Related Commands

## 2.1 Overview

This section describes the commands that are used to manage the files and directories on a disk. 

## 2.2 Syntax

```bash
pfs  [-H hostid] <command> [options] pbdpath 
```

- `-H hostid`: (Optional) specifies the ID of the host in which the disk resides. The ID of each host in a PFS cluster must be unique. The default host ID is the maximum host ID that is allowed for the disk. 
- `command`: specifies the command that you want to run. 
- `options`: (Optional) specifies an array of options that you want to configure in the command. 
- `pbdpath`: specifies the file or directory that you want to manage. The value of this parameter must be in the `/pbdname/path` format. 

## 2.3 Commands Supported by Files and Directories

### 2.3.1 Overview

| Command | Description | Option |
| --- | --- | --- |
| stat | Queries the properties of a file on a disk | None. |
| rm | Deletes one or more files or a directory from a disk. | `-r`: deletes the directory that you specify. |
| rename | Renames a file or a directory on a disk. | None. |
| du | Queries the amount of storage space that is occupied by a file or a directory on a disk. | `-a`: queries the amount of storage space that is occupied by a file.<br>`-d`: specifies the number of directory levels whose occupied storage space you want to query. |
| cp | Copies a file or a directory from a disk. | `-r`: specifies the directory that you want to copy. |

### 2.3.2 stat

- Description: This command is used to query the properties of a file on a disk. 
- Options: None.
- Examples:

```bash
# Query the properties of the /mydir/myfile file on the nvme1n1 disk.
$sudo pfs -C disk stat /nvme1n1/mydir/myfile
  file:/nvme1n1/mydir/myfile
  size:104857600       blocks:8192
device: nvme1n1          inode:2105 links:1
access:0, Thu Jan  1 08:00:00 1970
modify:1532953314, Mon Jul 30 20:21:54 2018
change:1532953314, Mon Jul 30 20:21:54 2018

# size: indicates the size of the file. Unit: bytes.
#blocks: indicates the number of blocks that are occupied by the file. The size of each block is 512 bytes.
#device: indicates the serial number of the disk on which the file is stored.
#inode: indicates the serial number of the inode of the file.
#links: indicates the number of links to the file. In most cases, the value of this parameter is 1. Symbolic links and hard links are not supported.
#access: indicates the most recent point in time at which the file is accessed. This parameter is not supported.
#modify: indicates the most recent point in time at which the file is modified.
#change: indicates the most recent point in time at which the file or its properties are modified.
```

### 2.3.3 rm

- Description: This command is used to delete one or more files or a directory from a disk. If you want to delete a directory, you must configure the `-r` option in this command. 
- Options:
   - `-r`: (Optional) deletes the directory that you specify. 
- Examples:

```bash
# Delete the mydir directory from the nvme1n1 disk.
$sudo pfs -C disk rm -r /nvme1n1/mydir

# Delete the myfile file from the nvme1n1 disk.
$sudo pfs -C disk rm /nvme1n1/myfile
```

### 2.3.4 rename

- Description: This command is used to rename a file or a directory on a disk. You can also use this command to move a file to a different directory. 
   - If the new file name is the same as the name of an existing file, the system deletes the existing file. 
   - If the new directory name is the same as the name of an existing directory that is not empty, the system deletes the existing directory. 
- Options: None.
- Examples:

```bash
# Rename a file.
$sudo pfs -C disk rename /nvme1n1/myfile /nvme1n1/myfile2

# Rename a directory.
$sudo pfs -C disk rename /nvme1n1/mydir /nvme1n1/other_dir/mydir2
```

### 2.3.5 du

- Description: This command is used to query the amount of storage space that is occupied by a file or a directory on a disk. 
- Options:
   - `-a`: (Optional) queries the amount of storage space that is occupied by a file. This option is disabled by default. 
   - `-d`: (Optional) specifies the number of directory levels whose occupied storage space you want to query. Default value: 1. 
- Examples:

```bash
# Query the amount of storage space that is occupied by the .pfs-journal file on the nvme1n1 disk.
$sudo pfs -C disk du /nvme1n1/.pfs-journal
32768   /nvme1n1/.pfs-journal
# Unit: KB.

# Query the amount of storage space that is occupied by the first two levels of directories in the home directory of the nvme1n1 disk.
$sudo pfs -C disk du -d 2 /nvme1n1/home
23617536        /nvme1n1/home/mysql/data3000
23617536        /nvme1n1/home/mysql
23617536        /nvme1n1/home
# Unit: KB.
```

## 2.4 Commands Supported by Files

### 2.4.1 Overview

| Command | Description | Option | Remarks |
| --- | --- | --- | --- |
| touch | Creates a file. | None. | None. |
| write | Writes data to a file. | `-o`: specifies the offset at which the system starts to write data to the file.<br>`-l`: specifies the number of bytes that you want to write to the file. | This command writes the data that is read from standard input streams. |
| read | Reads data from a file. | `-o`: specifies the offset at which the system starts to read data from the file.<br>`-l`: specifies the number of bytes that you want to read from the file. | None. |
| truncate | Resizes a file. | `-l`: specifies the new size of the file. | No physical blocks are assigned to the file until data is written to fill the increased size of the file. |
| fallocate | Allocates a specified amount of storage space to a file. | `-o`: specifies the offset of the file.<br>`-l`: specifies the amount of storage space that you want to allocate to the file. | New physical blocks are allocated to the file. |
| map | Queries the index table of the blocks that store the data of a file. | `-o`: specifies the offset of the file. | None. |

### 2.4.2 touch

- Description: This command is used to create a file on a disk. If the file that you want to create has been created, the system returns a failure message. 
- Options: None.
- Examples:

```bash
# Create a file named myfile in the mydir directory of the nvme1n1 disk.
$sudo pfs -C disk touch /nvme1n1/mydir/myfile
```

### 2.4.3 write

- Description: This command is used to write the data that is read from standard input streams to a file. You can specify the offset at which the system starts to write data and the number of bytes that you want to write to the file. 
   - If you do not specify an offset, the system starts at the header of the file to write data. 
   - If you specify an offset but do not specify the number of bytes that you want to write, the system starts at the specified offset to write all data that is read from standard input streams. 
   - If you do not specify an offset or the number of bytes that you want to write, the system starts at the header of the file to write all data that is read from standard input streams. 
- Options:
   - `-o`: (Optional) specifies the offset at which the system starts to write data to the file. Default value: 0. 
   - `-l`: (Optional) specifies the number of bytes that you want to write to the file. If you do not configure this option, the system writes all data that is read from standard input streams to the file. 
- Examples:

```bash
# Write three bytes starting at an offset of 2. In this example, 012 is written to the file that you specify.
$sudo echo "012345" | pfs -C disk write -o 2 -l 3 /nvme1n1/mydir/myfile
```

### 2.4.4 read

- Description: This command is used to read data from a file. You can specify the offset from which the system starts to read data and the number of bytes that you want to read from the file. 
   - If you do not specify an offset, the system starts at the header of the file to read data. 
   - If you specify an offset but do not specify the number of bytes that you want to read, the system reads data starting at the offset to the end of the file. 
   - If you do not specify an offset or the number of bytes that you want to read, the system reads all data of the file. 
- Options:
   - `-o`: (Optional) specifies the offset at which the system starts to read data from the file. Default value: 0. 
   - `-l`: (Optional) specifies the number of bytes that you want to read from the file. 
- Examples:

```bash
# Read 10 bytes starting at an offset of 2.
$sudo pfs -C disk read -o 2 -l 10 /nvme1n1/mydir/myfile

```

### 2.4.5 truncate

- Description: This command is used to resize a file. After you resize a file, no new physical blocks are assigned to the file until data is written to fill the increased size of the file. 
- Options:
   - `-l`: specifies the new size of the file. 
- Examples:

```bash
# Change the size of the myfile file to 100 MB.
$sudo pfs -C disk truncate -l 104857600 /nvme1n1/mydir/myfile
```

### 2.4.6 fallocate

- Description: This command is used to allocate a specified amount of storage space to a file. You can specify the offset of the file. After this command is successfully run, the size of the file may change. 
   - If the sum of the offset and the allocated storage space is less than or equal to the original size of the file, the size of the file remains unchanged. 
   - If the sum of the offset and the allocated storage space is greater than the original size of the file, the size of the file changes to the new file that you specify. 
- Options:
   - `-o`: (Optional) specifies the offset of the file. Default value: 0. 
   - `-l`: specifies the amount of storage space that you want to allocate to the file. 
- Examples:

```bash
# Allocate 100 bytes of storage space starting at an offset of 4 to the myfile file. After this command is successfully run, the size of the file changes to 104 bytes.
$sudo pfs -C disk fallocate -o 4 -l 100 /nvme1n1/mydir/myfile

$sudo pfs -C disk stat /nvme1n1/mydir/myfile
  file:/1/mydir/myfile
  size:104             blocks:8192
device: dev-20          inode:4103 links:1
access:0, Thu Jan  1 08:00:00 1970
modify:1532953314, Mon Jul 30 20:21:54 2018
change:1532953314, Mon Jul 30 20:21:54 2018
```

## 2.5 Commands Supported by Directories

### 2.5.1 Overview

| Command | Description | Option | Remarks |
| --- | --- | --- | --- |
| mkdir | Creates a directory on a disk. | `-p`: creates a parent directory for the directory that you want to create if the directory does not have a parent directory. | None. |
| ls | Queries all subdirectories in a directory of a disk. | None. | None. |
| tree | Queries the directory tree for a directory of a disk. | `-v`: queries the details about all directories in the directory tree for the directory. | None. |
| rmdir | Deletes an empty directory from a disk. | None. | The directory can be deleted only when it is empty. |

### 2.5.2 mkdir

- Description: This command is used to create a directory on a disk. 
- Options:
   - `-p`: creates a parent directory for the directory that you want to create if the directory does not have a parent directory. 
- Examples:

```bash
# Create a directory named mydir2 on the nvme1n1 disk.
$sudo pfs -C disk mkdir /nvme1n1/mydir2

# Create a directory named mydir3 on the nvme1n1 disk. Also, specify to create a parent directory named mydir2 for the mydir3 directory if the mydir3 directory does not have a parent directory.
$sudo pfs -C disk mkdir -p /nvme1n1/mydir2/mydir3
```

### 2.5.3 ls

- Description: This command is used to query all subdirectories in a directory of a disk. 
- Options: None.
- Examples:

```bash
# Query the subdirectories in the home directory of the nvme1n1 disk.
$sudo pfs -C disk ls /nvme1n1/
  File  1     4194304           Wed Jul 11 00:04:55 2018  .pfs-paxos
  File  1     33554432          Wed Jul 11 00:04:55 2018  .pfs-journal
   Dir  1     128               Wed Jul 11 00:04:55 2018  home
  File  1     17547574          Mon Jul 30 17:42:19 2018  test.log
   Dir  1     0                 Mon Jul 30 17:43:48 2018  dir1
   Dir  1     256               Mon Jul 30 20:19:38 2018  mydir
total 114688 (unit:512Bytes)
# The total parameter indicates the total size of blocks that are occupied by all regular files in the home directory. In this example, the total size is 512 bytes.
```

### 2.5.4 tree

- Description: This command is used to query the directory tree for a directory of a disk. 
- Options:
   - `-v`: (Optional) queries the details about all directories in the directory tree for the directory that you specify. By default, this option is disabled. 
- Examples:

```bash
# Query the directory tree for the home directory of the nvme1n1 disk.
$sudo pfs -C disk tree /nvme1n1/
|-.pfs-paxos
|-.pfs-journal
|-test_write_normal_f_1
|-test_rmdir_file_1
|-test_rmdir_not_empty
 |-file_0
 |-file_1
 |-file_2
 |-file_3
 |-file_4
|-truncate_test_f_3
|-test_truncate_dir
|-truncate_test_f_2
|-truncate_test_f_1
|-rename_test_f2_new
|-rename_test_f3
|-rename_test_dir3
|-rename_test_f1_new

3 directories, 15 files
```

### 2.5.5 rmdir

- Description: This command is used to delete an empty directory from a disk. If the directory that you specify is not empty, the system returns a failure message. 
- Options: None.
- Examples:

```bash
# Delete the mydir2 directory from the nvme1n1 disk.
$sudo pfs -C disk rmdir /nvme1n1/mydir2
```
