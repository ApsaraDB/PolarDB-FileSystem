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

usage(){
    echo "[umount_pfs_fuse.sh] usage: "
    echo "          /usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh [absolute_mount_dir/all]"
    echo "example:"
    echo "          /usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh  /fuse/mount/dir"
    echo "          /usr/local/polarstore/pfsd/bin/umount_pfs_fuse.sh  all"
    echo "logger location:"
    echo "          /var/log/pfs-[disk].log"
}

kill_single_fuse() {
    echo "[umount_pfs_fuse.sh] umount pfs fuse $MNTDIR..."
    MNTDIR=$1

    sudo umount -l $MNT_DIR
    sleep 1

    exist_command="ps -ef | grep 'pfs-fuse' |  grep -w '$MNTDIR' | wc -l"
    exist=$(eval $exist_command)
    if [ $exist -eq 0 ]; then
        echo "[umount_pfs_fuse.sh] pfs fuse $MNT_DIR umount success!"
        exit 0
    fi

    ps -ef |grep 'pfs-fuse' | grep -w $MNTDIR | awk '{print $2}' | xargs kill -9
    sleep 1

    exist=$(eval $exist_command)
    if [ $exist -eq 0 ]; then
	    echo "[umount_pfs_fuse.sh] pfs fuse $MNT_DIR umount success!"
	    exit 0
    else
        echo "[umount_pfs_fuse.sh] pfs fuse $MNT_DIR umount failed!"
	usage
    fi
}

kill_all_fuse() {
    echo "[umount_pfs_fuse.sh] umount all pfs fuses..."

    ps -ef |grep 'pfs-fuse' | grep 'pbdname' | awk '{print $2}'| xargs kill -9
    sleep 1

    exist_command="ps -ef | grep 'pfs-fuse' | grep 'pbdname' | wc -l"
    exist=$(eval $exist_command)

    if [ $exist -eq 0 ]; then
	    echo "[umount_pfs_fuse.sh] umount all pfs fuses success!"
  	    exit 0
    else
	    echo "[umount_pfs_fuse.sh] pfs fuse umount failed!"
	    usage
    fi
}

# umount pfs fuse
if [ $# -ne 1 ]; then
    usage
    exit
else
    # umount fuse
    echo "[umount_pfs_fuse.sh] pfs fuse umount..."
    if [ "$1" == 'all' ]; then
        kill_all_fuse
    elif [ "$1" = '--help' ] || [ "$1" = '-h' ]; then
        usage
        exit
    else
        MNT_DIR=$1
        kill_single_fuse $MNT_DIR
    fi
fi
