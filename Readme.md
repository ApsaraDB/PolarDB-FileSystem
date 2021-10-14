You can refer to [Readme-CN](Readme-CN.md) for introduction in Chinese.
# What is PFS
The PolarDB File System (hereafter simplified as PFS or PolarFS) is a high-performance Distributed File System in User Space that is developed by Alibaba Cloud and used in PolarDB. PFS follows the standards of Portable Operating System Interface (POSIX). 
# Quick Start
PFS for PostgreSQL uses the background process **_pfsdaemon_** to provide services. PFS for PostgreSQL is developed and tested based on AliOS and CentOS 7.5. Theoretically, PFS for PostgreSQL can also be built based on other Linux versions. 
## Install Dependencies
In the following example, CentOS 7.5 is selected. Before you build PFS for PostgreSQL, install the following software:

- [CMake](https://cmake.org/): The CMake version must be 2.8 or later. 
- [GCC or G++](http://www.gnu.org/software/gcc/): The GNU Compiler Collection (GCC) version or the GNU C++ Compiler (G++) version must be 4.8.5 or later. 
- [zlog](https://github.com/HardySimpson/zlog/releases): The zlog version must be 1.2.12 or later. 
- [libaio-devel](https://pagure.io/libaio)

We recommend that you use `yum` or `apt-get` command to install CMake, GCC or G++, and libaio-devel. 
To install zlog, you must download the source code and run `make && sudo make install` command. zlog is installed in the _/usr/local/lib_ directory. If the dynamic libraries cannot be located when pfsdaemon is running, you can run `ldconfig` command to add _/usr/local/lib_ directory into the settings of dynamic libraries. <br><br>
We also provide you installation by rpm package. If you use rpm package installation, skip the two steps of "Compile" and "Install pfsdaemon".

## Compile
After the dependencies are installed, go to the root directory of PFS source code and run the autobuild.sh script to compile PFS.
```
./autobuild.sh
```
## Install pfsdaemon
To install or uninstall pfsdaemon, you must be granted the root permissions. 
After you compile PFS, run the install.sh script to automatically install pfsdaemon.
```
sudo ./install.sh
```
## Run pfsdaemon

##### 1. Format the storage devices of PFS. 

   First, run the following command to find the existing block devices:

```
lsblk
```
​		Then, select the block device that you want to format, such as `nvme1n1`, and run the following command to format the device:
```
sudo pfs -C disk mkfs nvme1n1
```

##### 2. Run the following command to start pfsdaemon:
```
sudo /usr/local/polarstore/pfsd/bin/start_pfsd.sh -p nvme1n1
```
​		 `-p nvme1n1` is a parameter that specifies the device name, and it is required. 
​		The following parameters are optional in the command:

```
-f (not daemon mode)
-w #nworkers
-c log_config_file
-b (if bind cpuset)
-e db ins id
-a shm directory
-i #inode_list_size
```

##### 3. Run the following command to stop pfsdaemon:
```
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh nvme1n1
```
`			nvme1n1` specifies the device name. 

##### 4. Clear the files that are generated when pfsdaemon is running. 

   After stopping pfsdaemon, run the following command to clear the temporary files, logs and shared memory files that are generated when pfsdaemon is running:

```
sudo /usr/local/polarstore/pfsd/bin/clean_pfsd.sh nvme1n1
```
`nvme1n1` specifies the device name. 

##### 5. Use the PFS tool to check whether PFS is running as expected. 

   Perform common operations on files to verify that PFS is running as expected. For more information, see Instruction to the [PFS tool](PFS_Tools-EN.md). 
   For example, you can run the following commands to view the new file hello.txt:

```
sudo pfs -C disk touch /nvme1n1/hello.txt
sudo pfs -C disk ls /nvme1n1/
```
​		`nvme1n1` specifies the device name. 
## Uninstall pfsdaemon
To uninstall pfsdaemon, you must be granted the root permissions. 

##### 1. Run the following command to stop pfsdaemon:
```
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh nvme1n1
```
`	nvme1n1` specifies the device name. 

##### 2. Run the uninstall.sh script to uninstall pfsdaemon. 
```
sudo ./uninstall.sh
```
# Documentation
The **doc** folder includes the following file:

- Readme-EN.md: Brief introduction about PFS, and the steps of quick start with PFS.
- [PFS_Tools-EN.md](PFS_Tools-EN.md): user manual about the commands of PFS tool.

# Software License
PFS is developed based on[ the open source software license Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
# Publications

- PolarFS: An Ultra-low Latency and Failure Resilient Distributed File System for Shared Storage Cloud Database in VLDB 2018
- POLARDB Meets Computational Storage: Efficiently Support Analytical Workloads in Cloud-Native Relational Database in FAST 2020

# Contact us

- For more information about the ApsaraDB PolarDB PostgreSQL-compatible edition, see [PolarDB Official Site](https://help.aliyun.com/product/172538.html).
- Use the DingTalk application to scan the following QR code and join the DingTalk group.

![](https://raw.githubusercontent.com/alibaba/PolarDB-for-PostgreSQL/main/doc/PolarDB-EN/pic/polardb_group.png)
​

