PFS工具仅供调试测试时使用。本文档介绍了PFS工具的使用命令。
# 1. 文件系统操作
## 1.1 概览

| 操作(command) | 功能                                      | 选项(options)                                                |
| ------------- | ----------------------------------------- | ------------------------------------------------------------ |
| mkfs          | 创建文件系统                              | `-u`：最大写实例数。<br>`-l`：journal文件大小。<br>`-f`：强制格式化。 |
| growfs        | 格式化新扩容的chunk                       | `-o`：扩容前chunk数。<br>`-n`：扩容后chunk数。<br>`-f`：强制格式化。 |
| info          | 打印元数据使用情况                        | 无                                                           |
| dumpfs        | 读取superblock，检查chunk header和metaobj | `-m`：dump meta data (默认dump ck hdr)<br>`-t`：meta data type。<br>`-c`：chunk id。<br>`-o`：metaobj id 。 |
| dumple        | 读取journal中的log entry内容              | `-a`：遍历整个journal。<br>`-t`：txid。<br>`-b`：btno。<br>`-d`：deno。<br>`-i`：ino。 |



## 1.2 mkfs

- 功能描述：在指定的磁盘设备上格式化文件系统。
- 参数说明： 
   - `-u`：最大实例个数，默认是3，最大可设置为255，可选。
   - `-f`：强制执行格式化，可选。
- 示例：

```bash
# 格式化nvme1n1
# 参数"-C disk"表示此次操作的是本地磁盘设备, nvme1n1是本地的一块存储设备名。
$sudo pfs -C disk mkfs nvme1n1

# 如果提示“already formatted”导致mkfs失败，确认mkfs操作安全后，添加'-f'标志
$sudo pfs -C disk mkfs -f nvme1n1

# 格式化nvme1n1，实例数10
$sudo pfs -C disk mkfs -u 10 nvme1n1
```

## 1.3 growfs

- 功能描述：格式化扩容后的新chunk [old, new)
- 参数说明： 
   - `-o`：格式化前的chunk数。
   - `-n`：格式化后的chunk数。
   - `-f`：强制执行格式化，可选。
- 示例：

```bash
# 磁盘设备 nvme1n1大小从10GB扩成30GB后，格式化新chunk [1, 3)
$sudo pfs -C disk growfs -o 1 -n 3 nvme1n1

# 如果提示“already formatted”导致growfs失败，确认growfs操作安全后，添加'-f'标志
$sudo pfs -C disk growfs -o 1 -n 3 -f nvme1n1
```

## 1.4 info

- 功能描述：打印文件系统的元数据信息。 
   - 打印PFS整体元数据使用情况：打印深度为1。
- 示例：

```bash
#打印磁盘 nvme1n1中文件系统的元数据信息
$sudo pfs -C disk info nvme1n1
Blktag Info:
 (0)allocnode: id 0, shift 0, nchild=3, nall 7680, nfree 1897, next 0
Direntry Info:
 (0)allocnode: id 0, shift 0, nchild=3, nall 6144, nfree 5974, next 0
Inode Info:
 (0)allocnode: id 0, shift 0, nchild=3, nall 6144, nfree 5974, next 0
 #nchild是chunk个数，磁盘总容量=nchild*10GB，nvme1n1有30GB
 #磁盘空闲block容量=1897*4MB
```


## 1.5 dumpfs

- 功能描述：打印superblock内元数据。
- 参数说明： 
   - `-m`：打印meta，未指定则打印chunk header
   - `-t`：指定metaobj类型，1/2/3分别对应bt/de/in
   - `-c`：指定chunk id
   - `-o`：指定metaobj number
- 示例：

```bash
# 打印nvme1n1的所有chunk header以及元数据统计信息
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
…………
type    free    used    total
blktag  7668    12      7680
dentry  6141    3       6144
inode   6141    3       6144

# 读取nvme1n1的metaobj元数据，指定chunk0，且metaobj number为1的inode
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

- 功能描述：打印journal内log entry数据。
- 参数说明： 
   - `-a`：遍历journal中所有可见的log entry（默认只遍历当前有效的log entry）
   - `-t`：指定特定的txid
   - `-b`：指定blocktag metaobj number
   - `-d`：指定direntry metaobj number
   - `-i`：指定inode metaobj number
- 示例：

```bash
# 打印nvme1n1中journal的所有log entry内容，包括已被trim的le项
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
[PFS_LOG] Mar  6 15:25:42.498594 INF [82650] number of log entries hit: 6 / 2097152 (all in journal)

# 遍历nvme1n1中journal的有效log entry，并且筛选出txid为2，metaobj number为2048的inode的le项
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
[PFS_LOG] Mar  6 15:32:03.101423 INF [105651] number of log entries hit: 1 / 6 (valid)
```

# 2. 文件目录操作
## 2.1 功能描述
对磁盘中的文件和目录进行操作。
## 2.2 参数说明
用法：`pfs  [-H hostid] <command> [options] pbdpath` 

- `-H：hosti`必须在集群中唯一，默认是该磁盘允许的最大hostid，可选。
- `command`：操作命令，必填。
- `options`：命令选项，可选。
- `pbdpath`：文件或目录路径，格式为`/pbdname/path`，必填。

## 2.3 文件和目录共同操作
### 2.3.1 概览

| 操作(command) | 功能           | 选项(options)                        |
| ------------- | -------------- | ------------------------------------ |
| stat          | 显示属性信息   | 无                                   |
| rm            | 删除目录或文件 | `-r`：删除目录                       |
| rename        | 重命名         | 无                                   |
| du            | 统计磁盘使用量 | `-a`：打印文件。<br>`-d`：打印深度。 |
| cp            | 拷贝目录或文件 | `-r`：拷贝目录                       |

### 2.3.2 stat

-  功能描述：查看属性信息 。
-  命令选项：无 
-  示例： 

```bash
#在nvme1n1中，查看/mydir/myfile的文件信息
$sudo pfs -C disk stat /nvme1n1/mydir/myfile
  file: /nvme1n1/mydir/myfile
  size: 104857600       blocks: 8192
device: nvme1n1          inode: 2105 links: 1
access: 0, Thu Jan  1 08:00:00 1970
modify: 1532953314, Mon Jul 30 20:21:54 2018
change: 1532953314, Mon Jul 30 20:21:54 2018
#size：文件长度（字节）
#blocks：所占块数（块大小：512Bytes）
#device：磁盘号
#inode：inode号
#links：链接数，通常为1，暂时不支持软硬链接
#access：atime，最近一次访问时间，暂不支持
#modify：mtime，最近一次文件内容的修改时间
#change：ctime，最近一次文件内容或属性的修改时间
```

### 2.3.3 rm

- 功能描述：删除目录或文件，目录需要添加`-r`选项。
- 命令选项： 
   - `-r`：删除目录，可选。
- 示例：

```bash
# 删除nvme1n1的目录/mydir
$sudo pfs -C disk rm -r /nvme1n1/mydir

# 删除nvme1n1的文件/myfile
$sudo pfs -C disk rm /nvme1n1/myfile
```

### 2.3.4 rename

- 功能描述：重命名目录或文件，支持移动到其他目录。 
   - 文件：如果新路径已经存在，则删除已有文件。
   - 目录：如果新路径已经存在，且该目录非空，则删除已有目录。
- 命令选项：无
- 示例：

```bash
# 重命名文件
$sudo pfs -C disk rename /nvme1n1/myfile /nvme1n1/myfile2

# 重命名目录
$sudo pfs -C disk rename /nvme1n1/mydir /nvme1n1/other_dir/mydir2
```

### 2.3.5 du

- 功能描述：查看目录或文件磁盘使用量。
- 命令选项： 
   - `-a`：打印文件，默认关闭，可选。
   - `-d`：打印深度，默认是1，可选。
- 示例：

```bash
# 显示文件磁盘使用量
$sudo pfs -C disk du /nvme1n1/.pfs-journal
32768   /nvme1n1/.pfs-journal
# 单位是KB

# 显示根目录磁盘使用量，打印深度是2
$sudo pfs -C disk du -d 2 /nvme1n1/home
23617536        /nvme1n1/home/mysql/data3000
23617536        /nvme1n1/home/mysql
23617536        /nvme1n1/home
# 单位是KB
```

## 2.4 文件操作

### 2.4.1 概览

| 操作(command) | 功能                | 选项(options)                         | 备注                    |
| ------------- | ------------------- | ------------------------------------- | ----------------------- |
| touch         | 创建文件            | 无                                    | —                       |
| write         | 写文件              | `-o`: 写偏移。<br>`-l`: 操作长度。    | 从stdin中读取数据       |
| read          | 读取文件            | `-o`: 读偏移。<br>`-l`: 操作长度。    | —                       |
| truncate      | 调整文件大小        | `-l`: 文件大小                        | 不会分配真实的物理block |
| fallocate     | 分配存储空间        | `-o`: 分配偏移。<br> `-l`: 分配长度。 | 分配真实的物理块        |
| map           | 显示文件block索引表 | `-o`: 文件偏移                        | —                       |

### 2.4.2 touch

-  功能描述：创建文件，如果文件已存在，则创建失败。
-  命令选项：无 
-  示例： 

```bash
#在nvme1n1的/mydir目录中创建myfile
$sudo pfs -C disk touch /nvme1n1/mydir/myfile
```

### 2.4.3 write

-  功能描述：从stdin中读取数据后，写入文件，可指定写操作的起始偏移或写入长度。 
   - 如果未设置偏移，则从文件头部开始写。
   - 如果未设置长度，则从指定偏移处写入所有读取到的数据。
   - 如果两者均未设置，则从文件开头写入所有读取到的数据。
-  命令选项： 
   - `-o` ：写操作的起始偏移，默认值是0，可选。
   - `-l` ：写入的数据长度，未设置的话，则写入所有读取到的数据，可选。
-  示例：
 
```bash
#从偏移2处写入3个字节的数据(写入'012')
$sudo echo "012345" | pfs -C disk write -o 2 -l 3 /nvme1n1/mydir/myfile
```

### 2.4.4 read

-  功能描述：读取文件，可指定读操作的起始偏移或长度。 
   - 如果未设置偏移，则从文件头部开始读。
   - 如果未设置长度，则从指定偏移处读到文件尾。
   - 如果两者均未设置，则读取完整文件内容。
-  命令选项： 
   - `-o` ：读操作的起始偏移，默认值是0，可选。
   - `-l` ：读取的数据长度，未设置的话，则从偏移处读到文件尾，可选。
-  示例：
 
```bash
#从偏移2处读取10个字节的文件内容
$sudo pfs -C disk read -o 2 -l 10 /nvme1n1/mydir/myfile
012
```

### 2.4.5 truncate

-  功能描述：调整文件长度，如果文件变大，新增区域不会分配物理block。 
-  命令选项： 
   - `-l` ：新的文件长度。
-  示例： 

```bash
# 将myfile的长度调整未100MB
$sudo pfs -C disk truncate -l 104857600 /nvme1n1/mydir/myfile
```

### 2.4.6 fallocate

-  功能描述：为文件分配指定长度的存储空间，可指定起始偏移。操作成功后，文件长度可能发生变更。 
   - 偏移+长度<=操作前文件长度：文件长度不变。
   - 偏移+长度>操作前文件长度：文件长度变大。
-  命令选项： 
   - `-o` ：起始偏移，默认值是0，可选。
   - `-l` ：存储空间大小，必填。
-  示例： 

```bash
#从偏移4处，预分配100字节的存储空间，新文件长度是104字节
$sudo pfs -C disk fallocate -o 4 -l 100 /nvme1n1/mydir/myfile

$sudo pfs -C disk stat /nvme1n1/mydir/myfile
  file: /1/mydir/myfile
  size: 104             blocks: 8192
device: dev-20          inode: 4103 links: 1
access: 0, Thu Jan  1 08:00:00 1970
modify: 1532953314, Mon Jul 30 20:21:54 2018
change: 1532953314, Mon Jul 30 20:21:54 2018
```

## 2.5 目录操作
### 2.5.1 概览

| 操作(command) | 功能       | 选项(options)               | 备注           |
| ------------- | ---------- | --------------------------- | -------------- |
| mkdir         | 创建目录   | `-p`： 父目录不存在，则创建 | —              |
| ls            | 打印目录   | 无                          | —              |
| tree          | 打印目录树 | `-v`：打印目录项详细信息    | —              |
| rmdir         | 删除空目录 | 无                          | 目录必须是空的 |

### 2.5.2 mkdir

- 功能描述：创建目录。
- 命令选项： 
   - `-p`：如果父目录不存在，则创建，可选。
- 示例：

```bash
#在nvme1n1上创建新目录mydir2
$sudo pfs -C disk mkdir /nvme1n1/mydir2

#在nvme1n1上创建新目录mydir3，如果目录mydir2不存在，则创建
$sudo pfs -C disk mkdir -p /nvme1n1/mydir2/mydir3
```

### 2.5.3 ls

- 功能描述：打印当前目录的所有目录项。
- 命令选项：无
- 示例：

```bash
#打印nvme1n1的根目录
$sudo pfs -C disk ls /nvme1n1/
  File  1     4194304           Wed Jul 11 00:04:55 2018  .pfs-paxos
  File  1     33554432          Wed Jul 11 00:04:55 2018  .pfs-journal
   Dir  1     128               Wed Jul 11 00:04:55 2018  home
  File  1     17547574          Mon Jul 30 17:42:19 2018  test.log
   Dir  1     0                 Mon Jul 30 17:43:48 2018  dir1
   Dir  1     256               Mon Jul 30 20:19:38 2018  mydir
total 114688 (unit: 512Bytes)
#total代表该目录中所有普通文件所占的块数(块大小：512Bytes)
```

### 2.5.4 tree

- 功能描述：打印当前目录的目录树，包括所有子目录及其中的文件。
- 命令选项： 
   - `-v` ：打印所有目录项的详细信息，默认关闭，可选。
- 示例：

```bash
#从根目录开始打印nvme1n1的目录树
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

- 功能描述：删除空目录，如果目录非空，则删除失败。
- 命令选项：无
- 示例：

```bash
#删除nvme1n1的目录/mydir2
$sudo pfs -C disk rmdir /nvme1n1/mydir2
```

