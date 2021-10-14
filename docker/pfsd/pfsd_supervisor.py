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

#!/usr/bin/python
# -*- coding: utf-8 -*-

import signal
import os
import sys
import subprocess
import time
import logging
import logging.config

# start_pfsd.sh -p 1-1 -w 32 -s 5 -a /dev/shm/pfsd
# -p is required, others are optional

# 必须前台运行
entrypoint = "/usr/local/polarstore/pfsd/bin/start_pfsd.sh -f "
mylog = None
share_dir = "/scripts"

def create_file(filename):
    try:
        if not os.path.exists(filename):
            dirname = os.path.dirname(filename)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            open(filename, 'a').close()
            mylog.debug("Successfully created file %s", filename)
        else:
            mylog.info("Ready file %s already exists ", filename)
    except Exception as e:
        raise Exception("Failed to create file %s, exception: %s" % (filename, str(e)))

def read_file(filename):
    try:
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        raise Exception("Failed to read file %s, exception: %s" % (filename, str(e)))

def pfsd_lock_filename():
    return os.path.join(share_dir, "pfsd_ins_lock")

def is_instance_locked():
    return os.path.exists(pfsd_lock_filename())

def pfsd_ready_filename():
    return os.path.join(share_dir, "pfsd_ins_ready")

def is_instance_ready():
    if os.path.exists(pfsd_ready_filename()):
        return read_file(pfsd_ready_filename())

    return None

# pre stop脚本生成这个文件，随后不久容器需要退出，所以不要拉起进程
def pfsd_exit_filename():
    return os.path.join(share_dir, "pfsd_ins_exit")

def pfsd_check_instance_exit():
    if os.path.exists(pfsd_exit_filename()):
        mylog.warning("Enter exit state, will exit at most 10minutes later...")
        time.sleep(600)
        sys.exit(0)


# 当发起start_instance, pfsd可能需要1秒才感知，pfsd读取启动参数后，创建这个文件
# 而管控则会等待这个文件的创建，然后删除，同步返回start_instance成功
def pfsd_started_filename():
    return os.path.join(share_dir, "pfsd_started")

def wait_for_instance_ready():
    sleep_times = 0
    args = ""
    while True:
        args = is_instance_ready()
        if args is not None:
            break

        if sleep_times % 60 == 0:
            mylog.warning("Not ready file %s, wait and check later..." % (pfsd_ready_filename()))

        time.sleep(1)
        sleep_times += 1

    mylog.info("Find ready file %s, instance is ready to start" % (pfsd_ready_filename()))
    create_file(pfsd_started_filename())
    return args

def wait_for_instance_unlocked():
    sleep_times = 0
    while is_instance_locked():
        if sleep_times % 60 == 0:
            mylog.warning("Found stop lock file %s, wait and check later..." % (pfsd_lock_filename()))

        time.sleep(1)
        sleep_times += 1

    mylog.info("No stop lock file %s, instance is ready to start" % (pfsd_lock_filename()))

def start_pfsd():
    sleep_time = 0
    while True:
        pfsd_check_instance_exit()

        # 第一次启动时，需要等待管控指令，接收参数
        args = wait_for_instance_ready()
        mylog.info("Got args: %s" % (args))

        wait_for_instance_unlocked()

        mylog.debug("Starting pfsd with args %s!" % (args))
        p = subprocess.Popen(entrypoint + args, shell=True)
        _, err = p.communicate()
        os.remove(pfsd_started_filename())
        mylog.warning("Pfsd exit with code %d, stderr: %s, args: %s" % (p.returncode, err, args))
	
	if sleep_time > 30:
	    sleep_time = 30
        
 	sleep_time += 1
        if is_instance_locked():
            continue # 存在stop锁，说明管控执行了stop_instance
        elif p.returncode != 0: # 进程异常退出
            #return p.returncode
            time.sleep(sleep_time)
        else:
            time.sleep(sleep_time)

# pfsd容器入口
if __name__ == "__main__":
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    pfsd_path = ["/var/run/pfs", "/var/run/pfsd", "/dev/shm/pfsd", "/var/log"]
    for path in pfsd_path:
        try:
            os.mkdir(path)
            os.chmod(path, 0777)
        except OSError as e:
            pass

    mylog = logging.getLogger("pfsd_super")
    try:
        logging.config.fileConfig('log.conf')
    except Exception as e:
        logging.basicConfig(filename='/var/log/pfsd_super.log', level=logging.DEBUG, format='[%(asctime)s]%(levelname)s: %(message)s')

    try:
        os.remove(pfsd_exit_filename())
    except OSError as e:
        pass

    err = start_pfsd()
    sys.exit(err)

