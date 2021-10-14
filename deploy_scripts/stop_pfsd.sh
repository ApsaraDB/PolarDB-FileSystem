#! /bin/bash

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

kill_single_pfsd() {
    pbd=$1
    pfsdname="pfsdaemon -p $pbd"
    exist_command="ps -ef | grep pfsdaemon |grep -w '\-p $pbd' | wc -l"
    exist=$(eval $exist_command)
    if [ $exist -eq 0 ]; then
        echo "$pfsdname not exist"
        exit 1
    fi

    pid=`ps -ef |grep pfsdaemon |grep -w '\-p '$pbd'' |awk '{print $2}'`
    kill -2 $pid
    sleep 1

    # check if stop success, if not, use kill -9 
    exist=$(eval $exist_command)
    if [ $exist -eq 0 ]; then
        echo "$pfsdname stop success"
        exit 0
    fi

    echo "going to kill -9 $pfsdname"
    kill -9 $pid
    sleep 1
    exist=$(eval $exist_command)
    if [ $exist -eq 0 ]; then
        echo "$pfsdname stop success"
    else
        echo "$pfsdname stop failed!"
    fi
}

kill_all_pfsd() {
    pkill -2 pfsdaemon		
    sleep 1		
    cnt=`ps -ef | grep pfsdaemon |  grep -v grep  | wc -l`
    if [ $cnt -eq 0 ]; then
        echo "pkill -2 all pfsdaemon success"
        exit 0
    fi

    echo "going to pkill -9 all pfsdaemon"
    pkill -9 pfsdaemon
    sleep 1
    cnt=`ps -ef | grep pfsdaemon |  grep -v grep  | wc -l`
    if [ $cnt -eq 0 ]; then
        echo "pkill -9 all pfsdaemon success"
        exit 0
    fi
    echo "pkill -9 all pfsdaemon failed!"
}

if [ $# -gt 0 ]; then
    kill_single_pfsd $1
else
    kill_all_pfsd
fi
