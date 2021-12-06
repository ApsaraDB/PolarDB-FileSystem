#!/bin/bash

# Copyright (c) 2017-2021, Alibaba Group Holding Limited
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

INSTALL_BASE_DIR="/usr/local/polarstore"

#prepare dir
mkdir -p ${INSTALL_BASE_DIR}
mkdir -p ${INSTALL_BASE_DIR}/pfsd
mkdir -p ${INSTALL_BASE_DIR}/pfsd/bin
mkdir -p ${INSTALL_BASE_DIR}/pfsd/conf
mkdir -p ${INSTALL_BASE_DIR}/pfsd/include
mkdir -p ${INSTALL_BASE_DIR}/pfsd/lib

#check install
if [ -f "${INSTALL_BASE_DIR}/pfsd/include/pfsd_sdk.h" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/lib/libpfsd.a" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/lib/libpfsd_test.so" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/bin/pfsdaemon" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/bin/pfs-fuse" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/bin/pfsd_shm_tool" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/conf/pfsd_logger.conf" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/bin/start_pfsd.sh" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/bin/stop_pfsd.sh" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/bin/mount_pfs_fuse.sh" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/bin/umount_pfs_fuse.sh" ] || \
[ -f "${INSTALL_BASE_DIR}/pfsd/bin/clean_pfsd.sh" ] || \
[ -f "/etc/init.d/pfsd_env" ] || \
[ -f "/etc/polarfs.conf" ] || \
[ -f "/usr/local/bin/pfs" ] || \
[ -f "/usr/local/bin/pfsadm" ];then
	echo "pfsd/fuse has installed, install failed"
	exit 1
fi

if [ ! -f "src/pfs_sdk/pfsd_sdk.h" ] || \
[ ! -f "lib/libpfsd.a" ] || \
[ ! -f "lib/libpfsd_test.so" ] || \
[ ! -f "bin/pfsdaemon" ] || \
[ ! -f "bin/pfs-fuse" ] || \
[ ! -f "bin/pfsd_shm_tool" ] || \
[ ! -f "conf/pfsd_logger.conf" ] || \
[ ! -f "deploy_scripts/start_pfsd.sh" ] || \
[ ! -f "deploy_scripts/stop_pfsd.sh" ] || \
[ ! -f "deploy_scripts/mount_pfs_fuse.sh" ] || \
[ ! -f "deploy_scripts/umount_pfs_fuse.sh" ] || \
[ ! -f "deploy_scripts/clean_pfsd.sh" ] || \
[ ! -f "src/pfsd/pfsd.init" ] || \
[ ! -f "etc/polarfs.conf" ] || \
[ ! -f "bin/pfs" ] || \
[ ! -f "bin/pfsadm" ];then
	echo "installing files not found, please check files or run autobuild.sh first"
	exit 1
fi

if [[ $EUID -ne 0 ]];then
	echo "pfsd/fuse install script must be run as root"
	exit 1
fi

#install
install -m 0644 src/pfs_sdk/pfsd_sdk.h			${INSTALL_BASE_DIR}/pfsd/include/pfsd_sdk.h
install -m 0755 lib/libpfsd.a				${INSTALL_BASE_DIR}/pfsd/lib/libpfsd.a
install -m 0755 lib/libpfsd_test.so			${INSTALL_BASE_DIR}/pfsd/lib/libpfsd_test.so
install -m 0755 bin/pfsdaemon				${INSTALL_BASE_DIR}/pfsd/bin/pfsdaemon
install -m 0755 bin/pfs-fuse                            ${INSTALL_BASE_DIR}/pfsd/bin/pfs-fuse
install -m 0755 bin/pfsd_shm_tool			${INSTALL_BASE_DIR}/pfsd/bin/pfsd_shm_tool
install -m 0644 conf/pfsd_logger.conf			${INSTALL_BASE_DIR}/pfsd/conf/pfsd_logger.conf
install -m 0755 deploy_scripts/start_pfsd.sh		${INSTALL_BASE_DIR}/pfsd/bin/start_pfsd.sh
install -m 0755 deploy_scripts/stop_pfsd.sh		${INSTALL_BASE_DIR}/pfsd/bin/stop_pfsd.sh
install -m 0755 deploy_scripts/mount_pfs_fuse.sh	${INSTALL_BASE_DIR}/pfsd/bin/mount_pfs_fuse.sh
install -m 0755 deploy_scripts/umount_pfs_fuse.sh	${INSTALL_BASE_DIR}/pfsd/bin/umount_pfs_fuse.sh
install -m 0755 deploy_scripts/clean_pfsd.sh		${INSTALL_BASE_DIR}/pfsd/bin/clean_pfsd.sh
install -m 0755 src/pfsd/pfsd.init			/etc/init.d/pfsd_env
install -m 0644 etc/polarfs.conf			/etc/polarfs.conf

install -m 0755 bin/pfs					/usr/local/bin/pfs
install -m 0755 bin/pfsadm				/usr/local/bin/pfsadm

#prepare for pfsd running
mkdir -p /dev/shm/pfsd
mkdir -p /var/run/pfsd
mkdir -p /var/run/pfs
chmod 777 /var/run/pfsd
chmod 777 /dev/shm/pfsd
chmod 777 /var/run/pfs
touch /var/run/pfsd/.pfsd
chkconfig --add pfsd_env

echo "install pfsd success!"
