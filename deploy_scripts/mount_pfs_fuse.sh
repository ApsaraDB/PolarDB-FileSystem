#! /bin/sh

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

BASE_DIR=$(cd "$(dirname "$0")"; pwd)
FUSE_BIN=${BASE_DIR}/pfs-fuse

usage(){
    echo "[mount_pfs_fuse.sh] usage: "
    echo "          /usr/local/polarstore/pfsd/bin/mount_pfs_fuse.sh [-p diskname] [-c rw/ro] mount_dir"
    echo "example:"
    echo "          /usr/local/polarstore/pfsd/bin/mount_pfs_fuse.sh -p nvme1n1 -c rw fuse/mount/dir"
    echo "logger location:"
    echo "          /var/log/pfs-[disk].log"
}

if [ $# -eq 0 ]; then
    usage
    exit
else
# parameters check
    if [ $# -ne 5 ]; then
        usage
        exit
    fi

    # PFS options
    if [ "$1" = '-p' ] && [ "$3" = '-c' ]; then
	DISK_NAME=$2
	PFS_FLAGS=$4
    elif [ "$1" = '-c' ] && [ "$3" = '-p' ]; then
	PFS_FLAGS=$2
	DISK_NAME=$4
    else
	echo "Invalid arguments"
	usage
	exit
    fi
    MNT_DIR=$5

    if [ "$PFS_FLAGS" = 'rw' ] || [ "$PFS_FLAGS" = 'RW' ];then
        is_rw=1
    elif [ "$PFS_FLAGS" = 'ro' ] || [ "$PFS_FLAGS" = 'RO' ];then
        is_rw=0
    else
	echo "-c (read/write flag) should be followed by 'rw'(read and write)/'ro'(read only)"
	usage
	exit 1
    fi

    # check if pfdameon exist
    pfsd_exist="ps -ef | grep pfsdaemon | grep -w '\-p $DISK_NAME' | wc -l"
    exist_ret0=$(eval $pfsd_exist)

    if [ $exist_ret0 -eq 0 ]; then
        mkdir -p /var/run/pfs
        mkdir -p /var/run/pfsd
        mkdir -p /dev/shm/pfsd

        chmod 777 /var/run/pfs
        chmod 777 /var/run/pfsd
        chmod 777 /dev/shm/pfsd

        CONF_FILE=${BASE_DIR}/../conf

        ulimit -c unlimited
        ${BASE_DIR}/../bin/pfsdaemon -p ${DISK_NAME} -c ${CONF_FILE}/pfsd_logger.conf

        sleep 1

        # check if start success
        exist_ret0=$(eval $pfsd_exist)
        if [ $exist_ret0 -eq 0 ]; then
            echo "pfsdaemon $DISK_NAME start failed"
            usage
            exit 1
        fi

        echo "pfsdaemon $DISK_NAME start success"
    fi

    # parameters check
    echo "[mount_pfs_fuse.sh] pfs fuse mount..."
    mntdir_exist="ps -ef | grep  'pfs-fuse' | grep -w '$MNT_DIR' | wc -l"
    exist_ret1=$(eval $mntdir_exist)
    # if multi-write instance on ont disk
    diskname_rw_exist="ps -ef | grep  'pfs-fuse' | grep -w '$DISK_NAME' | grep -w 'rw'| wc -l"
    exist_ret2=$(eval $diskname_rw_exist)
    if [ $exist_ret1 -ge 1 ]; then
        echo "[mount_pfs_fuse.sh] mount error: path $MNT_DIR is already mounted"
	fi
    if [ $is_rw -eq 1 ] && [ $exist_ret2 -ge 1 ]; then
        echo "[mount_pfs_fuse.sh] mount error: disk $DISK_NAME is already mounted with a rw instance! a disk can only be mounted with one rw instance, you can mount a ro instance or choose another disk."
		exit 1
    fi

    # pfs fuse mount
    sudo $FUSE_BIN -s -o allow_other -o direct_io -o auto_unmount --pbdname=$DISK_NAME --flags=$PFS_FLAGS $MNT_DIR
	sleep 1
    # check if pfs fuse mount success
    mount_exist="ps -ef | grep 'pfs-fuse' | grep -w '$MNT_DIR' | grep -w '$DISK_NAME' | grep -w '$PFS_FLAGS' | wc -l"
    exist_ret=$(eval $mount_exist)
    if [ $exist_ret -eq 0 ]; then
        echo "[mount_pfs_fuse.sh] pfs fuse mount failed!"
        usage
        exit 1
    else
        echo "[mount_pfs_fuse.sh] pfs fuse mount success!"
    fi
fi
