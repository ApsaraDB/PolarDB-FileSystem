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

#ifndef _PFSD_OPTION_H_
#define _PFSD_OPTION_H_

#include "pfs_impl.h"

typedef struct {
	/* Worker threads, same as num of channels */
	int o_workers;
	/* Worker thread usleep interval in us */
	int o_usleep;
	/* pbdname like 1-1 */
	char o_pbdname[PFS_MAX_PBDLEN];
	/* shm directory */
	char o_shm_dir[PFS_MAX_PATHLEN];
	/* config file */
	char o_log_cfg[PFS_MAX_PATHLEN];
	/* daemon mode */
	int o_daemon;
	/* if bind cpuset */
	int o_affinity;
} pfsd_option_t;

extern pfsd_option_t g_option;

int pfsd_parse_option(int ac, char *av[]);
void pfsd_usage(const char *prog);
void pfsd_worker_usleep();

#endif

