/*
 * Copyright (c) 2017-2021, Alibaba Group Holding Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "pfsd_testenv.h"
#include "pfsd_sdk.h"
#include "pfs_mount.h"
#include "pfsd_common.h"
#include <iostream>
#include <stdlib.h>

using std::cout;
using std::endl;

PFSDTestEnv *g_testenv = NULL;

#define TEST_CONNECT_TIMEOUT (5 * 1000)

void PFSDTestEnv::SetUp() {
    cout << "Start PFSDTest of host " << hostid_
        << " on clsuter " << cluster_ << ", pbd " << pbdname_ << endl;

    int flags = MNTFLG_TOOL | MNTFLG_RDWR | MNTFLG_LOG;
    int err = pfsd_sdk_init(PFSD_SDK_THREADS, PFSD_USER_PID_DIR, TEST_CONNECT_TIMEOUT,
                            cluster_.data(), pbdname_.data(), hostid_, flags);
    if (err < 0) {
        cout << "pfsd_sdk_init failed." << endl;
        abort();
    }

    cout << "Setup successful" << endl;
}

void PFSDTestEnv::TearDown() {
    cout << "Finish PFSDTest of host " << hostid_ << " on pbd " << pbdname_ << endl;
    umount();
}

int PFSDTestEnv::mount(int flags) {
    flags |= PFS_TOOL;
    int e = pfsd_sdk_init(PFSD_SDK_THREADS, PFSD_USER_PID_DIR, TEST_CONNECT_TIMEOUT,
                          cluster_.data(), pbdname_.data(), hostid_, flags);
    return e >= 0 ? 0 : -1;
}

int PFSDTestEnv::umount() {
    return pfsd_umount(pbdname_.data());// just close pid file
}

