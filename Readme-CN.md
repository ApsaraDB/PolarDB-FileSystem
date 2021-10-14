# 什么是PFS
PolarDB File System，简称PFS或PolarFS，是由阿里云自主研发的高性能类POSIX的用户态分布式文件系统，服务于阿里云数据库PolarDB产品。
# 快速入门
PFS（PostgreSQL版）是以后台进程（pfsdaemon）的方式提供服务，目前完成基于AliOS以及CentOS 7.5的开发和测试工作，其他Linux版本理论上也可以搭建。
​

## 安装依赖
以CentOS 7.5为例，构建工程需要完成以下软件安装：

- [CMake](https://cmake.org/)：需要2.8及以上版本。
- [gcc&g++](http://www.gnu.org/software/gcc/)：需要4.8.5及以上版本。
- [zlog](https://github.com/HardySimpson/zlog/releases)：需要1.2.12及以上版本。​
- [libaio-devel](https://pagure.io/libaio)​

CMake、gcc&g++、libai​o-devel的安装建议使用yum或apt-get。
zlog需要下载源码后执行 `make && sudo make install` 安装，而且由于zlog安装的目录在`/usr/local/lib`，如果运行时找不到动态库，可以通过`ldconfig`配置进行添加。<br><br>
​本项目也提供rpm包安装，如果使用rpm包安装，跳过编译和安装这2个步骤。

## 编译
依赖项准备好后，进入代码根目录，执行脚本进行编译：
```bash
./autobuild.sh
```
## 安装pfsdaemon
安装pfsdaemon需要root权限。
在完成编译工作后，使用安装脚本 install.sh 进行自动化安装：
```bash
sudo ./install.sh
```



## 运行pfsdaemon

##### 1. 格式化存储设备。首先执行以下命令查找现有的块设备：
```bash
lsblk
```
​		选择需要格式化的块设备名，例如 nvme1n1，运行pfs格式化命令：
```bash
sudo pfs -C disk mkfs nvme1n1
```

##### 2. 执行如下脚本启动pfsdaemon：
```bash
sudo /usr/local/polarstore/pfsd/bin/start_pfsd.sh -p nvme1n1
```
​		其中，"-p 设备名"必须设置，nvme1n1指代设备名。
​		其他可选启动参数如下：

```bash
 -f (not daemon mode)
 -w #nworkers
 -c log_config_file
 -b (if bind cpuset)
 -e db ins id
 -a shm directory
 -i #inode_list_size
```

##### 3. 可执行如下脚本停止pfsdaemon：
```bash
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh nvme1n1
```
​		nvme1n1指代设备名。

##### 4. 清除pfsdaemon运行文件。

   停止pfsdaemon后，清理运行时产生的临时文件、日志、共享内存文件：

```bash
sudo /usr/local/polarstore/pfsd/bin/clean_pfsd.sh nvme1n1
```
​		nvme1n1指代设备名。

##### 5. 使用PFS工具进行检查。

   参照[PFS工具使用说明](docs/PFS_Tools-CN.md)，进行常见的文件操作，验证文件系统是否正确安装。
   例如使用如下命令，可以查看创建的新文件 hello.txt：

```bash
sudo pfs -C disk touch /nvme1n1/hello.txt
sudo pfs -C disk ls /nvme1n1/
```
​		nvme1n1指代设备名。


## 卸载pfsdaemon
卸载pfsdaemon需要root权限。

##### 1. 执行如下脚本停止pfsdaemon：
```bash
sudo /usr/local/polarstore/pfsd/bin/stop_pfsd.sh nvme1n1
```

##### 2. 使用卸载脚本 uninstall.sh 进行卸载：
```bash
sudo ./uninstall.sh
```


# 文档
在docs目录下，包括内容如下：

- [PFS_Tools-CN.md](docs/PFS_Tools-CN.md)：PFS工具的命令使用手册。

# License
PFS基于[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)协议开源。

# 出版物

- 《PolarFS: An Ultra-low Latency and Failure Resilient Distributed File System for Shared Storage Cloud Database》VLDB2018
- 《POLARDB Meets Computational Storage: Efficiently Support Analytical Workloads in Cloud-Native Relational Database》FAST2020



# 联系我们

- 产品官网：[阿里云原生关系型数据库PolarDB](https://help.aliyun.com/product/172538.html)
- 使用钉钉扫描如下二维码，加入钉钉群。

![image.png](https://raw.githubusercontent.com/alibaba/PolarDB-for-PostgreSQL/main/doc/PolarDB-EN/pic/polardb_group.png)
