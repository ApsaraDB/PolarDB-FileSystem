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

#uninstall check
exist_command="ps -ef | grep pfsdaemon |  grep -v grep  | wc -l"
exist=$(eval $exist_command)
if [ $exist -ge 1 ]; then
	echo "pfsd is running, before uninstall pfsd, please stop pfsd"
	exit 1
fi

if [[ $EUID -ne 0 ]];then
	echo "pfsd uninstall script must be run as root"
	exit 1
fi

#uninstall
rm ${INSTALL_BASE_DIR}/pfsd/include/pfsd_sdk.h
rm ${INSTALL_BASE_DIR}/pfsd/lib/libpfsd.a
rm ${INSTALL_BASE_DIR}/pfsd/lib/libpfsd_test.so
rm ${INSTALL_BASE_DIR}/pfsd/bin/pfsdaemon
rm ${INSTALL_BASE_DIR}/pfsd/bin/pfsd_shm_tool
rm ${INSTALL_BASE_DIR}/pfsd/conf/pfsd_logger.conf
rm ${INSTALL_BASE_DIR}/pfsd/bin/start_pfsd.sh
rm ${INSTALL_BASE_DIR}/pfsd/bin/stop_pfsd.sh
rm ${INSTALL_BASE_DIR}/pfsd/bin/clean_pfsd.sh
rm /etc/init.d/pfsd_env
rm /etc/polarfs.conf

rm /usr/local/bin/pfs
rm /usr/local/bin/pfsadm

echo "uninstall pfsd success!"