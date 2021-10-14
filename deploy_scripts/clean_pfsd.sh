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

# cleanup resources

pbd=$1
if test -z $pbd;then
	echo "Error: not get pbdname"
	exit
fi

/usr/local/polarstore/pfsd/bin/stop_pfsd.sh $pbd

pidfile="/var/run/pfsd/pfsd_${pbd}.pid"
echo $pidfile | xargs rm -f

clientpiddir="/var/run/pfsd/${pbd}"
echo $clientpiddir | xargs rm -rf

shmfile="/dev/shm/pfsd/shm_pfsd-${pbd}_*"
echo $shmfile | xargs rm -f

logdir="/var/log/pfsd-${pbd}"
echo $logdir | xargs rm -rf

echo "clean pfsd $pbd files success"
