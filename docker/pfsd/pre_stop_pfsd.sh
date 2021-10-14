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

#! /bin/bash

# stop pfsd and cleanup resources

# 1. check arg for pbdname
pbd=$1
if test -z $pbd;then
    echo "Error: not get pbdname"
    exit
fi

echo "Exec: pre_stop_pfsd $pbd"

# 2. create exit file
exit_file="/scripts/pfsd_ins_exit"
touch $exit_file

# 3. check if pfsdaemon alive
pfsd_pid=`ps -ef|grep pfsdaemon|grep -v grep|gawk '{print $2}'`

if test -z "$pfsd_pid";then
    echo "Error: not found pfsd running"
else
    # 4. kill pfsdaemon
    echo "kill -2 $pfsd_pid"
    kill -2 $pfsd_pid
    sleep 1
    pfsd_pid2=`ps -ef|grep pfsdaemon|grep -v grep|gawk '{print $2}'`
    if test -n "$pfsd_pid2";then
        echo "kill -9 $pfsd_pid2"
        kill -9 $pfsd_pid2
        exit
    fi
fi

# 5. exec clean pfsd
echo "/usr/local/polarstore/pfsd/bin/clean_pfsd.sh $pbd"
exec /usr/local/polarstore/pfsd/bin/clean_pfsd.sh $pbd

