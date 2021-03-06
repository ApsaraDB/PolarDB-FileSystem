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

#include <iostream>
#include <string>
#include <gtest/gtest.h>
#include "pfsd_testenv.h"

using namespace std;

int main(int argc, char **argv)
{
	if (argc < 4) {
		cout << "Usage: " << argv[0] << " [hostid] [cluster] [pbdname]" << endl;
		return -1;
	} else {
		int hostid = atoi(argv[1]);
		string cluster(argv[2]);
		string pbdname(argv[3]);

		g_testenv = dynamic_cast<PFSDTestEnv *>(
				::testing::AddGlobalTestEnvironment(
					new PFSDTestEnv(cluster, pbdname, hostid)
					)
				);
		::testing::InitGoogleTest(&argc, argv);

		return RUN_ALL_TESTS();
	}
}
