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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

extern int pfs_fuse_main(int argc, char *argv[]);

int main(int argc, char *argv[])
{
	int rv;

	rv = pfs_fuse_main(argc, argv);
	if(rv < 0){
		fprintf(stderr, "[pfsd fuse] pfs_fuse_main error, err=%d\n", rv);
		return -1;
	}

	return 0;
}
