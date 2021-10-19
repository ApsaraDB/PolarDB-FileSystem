#!/usr/bin/python
# -*- coding: utf-8 -*-

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

import os
import sys
import subprocess
import time
import datetime
import logging
import logging.config

#stop_cmd = "/usr/local/polarstore/pfsd/bin/stop_pfsd.sh "
#force_stop_cmd = "/usr/local/polarstore/pfsd/bin/stop_pfsd.sh "
stop_cmd = "pkill -2 pfsdaemon "
force_stop_cmd = "pkill -9 pfsdaemon"
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

def write_file(filename, content, append = False):
    try:
        if not os.path.exists(filename):
            dirname = os.path.dirname(filename)
            if not os.path.exists(dirname):
                os.makedirs(dirname)

        mode = 'a' if append else 'w'
        with open(filename, mode) as f:
            f.write(content)
            mylog.info("write [%s] to %s", content, filename)
    except Exception as e:
        raise Exception("Failed to write file %s, exception: %s" % (filename, str(e)))

def pfsd_ready_filename():
    return os.path.join(share_dir, "pfsd_ins_ready")

def create_ready_file():
    create_file(pfsd_ready_filename())

def pfsd_lock_filename():
    return os.path.join(share_dir, "pfsd_ins_lock")

def create_stop_lock_file():
    create_file(pfsd_lock_filename())

def check_pfsd_is_running():
    p1 = subprocess.Popen(['ps', '-ef'], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(['grep', 'pfsdaemon'], stdin=p1.stdout, stdout=subprocess.PIPE)
    p3 = subprocess.Popen(['grep', '-v', 'grep'], stdin=p2.stdout, stdout=subprocess.PIPE)
    out = p3.communicate()
    if out[0] is None or out[0] == "": 
        mylog.error("Error: not found pfsd running")
        return False
    else:
        return True

def lock_stop_instance():
    begin_time = datetime.datetime.utcnow()
    create_stop_lock_file()

    os.system(stop_cmd)

    # 不断检查直到pfsd退出或者超时
    while check_pfsd_is_running():
        if (datetime.datetime.utcnow() - begin_time).total_seconds() > 10:
            mylog.warning("shutdown timeout, force stop pfsd")
            os.system(force_stop_cmd)
            return

        time.sleep(1)

    mylog.info("Successfully stopped pfsdaemon")

def unlock_start_instance():
    try:
        if os.path.exists(pfsd_lock_filename()):
            os.remove(pfsd_lock_filename())
            mylog.info("Successfully removed stop lock file %s", pfsd_lock_filename())
        else:
            mylog.error("Stop lock file %s not exist", pfsd_lock_filename())
    except Exception as e:
        raise Exception("Failed to remove stop lock file %s, exception: %s" % (pfsd_lock_filename(), str(e)))

# 当发起start_instance, pfsd可能需要1秒才感知，pfsd读取启动参数后，创建这个文件
# 而管控则会等待这个文件的创建，然后删除，同步返回start_instance成功
def pfsd_started_filename():
    return os.path.join(share_dir, "pfsd_started")

def start_instance():
    if len(sys.argv) <= 1:
        return os.errno.EINVAL

    try:
        write_file(pfsd_ready_filename(), " ".join(sys.argv[1:]), append = False)
        while True:
            if os.path.exists(pfsd_started_filename()):
                mylog.info("Pfsd is ready to starting, start_instance return successfully with arg [%s]" % (" ".join(sys.argv[1:])))
                return 0
            else:
                time.sleep(1)
    except Exception as e:
        return os.errno.EACCES
    return -1

# 管控重启pfsd实例,就是停止pfsd进程，并创建一个文件pfsd_lock_filename():
# pfsd看到这个文件，就继续启动pfsd进程，完成重启。
def restart_instance():
    if len(sys.argv) > 1:
        try:
            write_file(pfsd_ready_filename(), " ".join(sys.argv[1:]), append = False)
        except Exception as e:
            return os.errno.EACCES

    lock_stop_instance()
    unlock_start_instance()
    return 0

def entry(envs):
    #srv_opr_type = envs.get("srv_opr_type")
    srv_opr_action = envs.get("srv_opr_action")
    mylog.debug("srv_opr_action %s" % (srv_opr_action))
    if srv_opr_action == "restart_instance":
        return restart_instance()
    elif srv_opr_action == "start_instance":
        return start_instance()
    else:
        mylog.error("unknown oper %s" % srv_opr_action)
        return os.errno.EBADRQC

# 管控触发
if __name__ == "__main__":

    mylog = logging.getLogger("pfsd_oper")
    try:
        logging.config.fileConfig('log.conf')
    except Exception as e:
        logging.basicConfig(filename='/var/log/pfsd_oper.log', level=logging.DEBUG, format='[%(asctime)s]%(levelname)s: %(message)s')

    err = entry(os.environ)
    sys.exit(err)
