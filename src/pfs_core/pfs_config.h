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

#ifndef _CHUNK_SERVER_PFS_CONFIG_H_
#define _CHUNK_SERVER_PFS_CONFIG_H_

#include <sys/queue.h>
#include <stdio.h>
#include <ctype.h>

#define DEFAULT_CONFIG_PATH	"/etc/polarfs.conf"

#define MAX_KEY_LEN 32
#define MAX_VAL_LEN 20

#define MAX_CONFIG_LINE_LEN 4096

/*
 * return ret
 */
typedef enum {
	CONFIG_OK = 0,
	CONFIG_ERR_FILE,
	CONFIG_ERR_PARAMS,
	CONFIG_ERR_PARSING,
	CONFIG_ERR_MEM,
	CONFIG_ERR_VAL,
} pfs_config_ret;

/*
 * \brief: config item key-value pair, key is config name, value is config value
 *  for compatible, value type is char[], work with specified translating func
 */
typedef struct pfs_config_kv {
	char	kv_key[MAX_KEY_LEN];
	char	kv_value[MAX_VAL_LEN];

	TAILQ_ENTRY(pfs_config_kv) next;
} pfs_config_kv_t;

/*
 *  \brief: declare config section
 *  contains section list and kv_list of every section
 */
typedef struct pfs_config_section {
	char	sect_name[MAX_KEY_LEN];
	int	num_of_kv;

	TAILQ_HEAD(, pfs_config_kv) kv_list;
	TAILQ_ENTRY(pfs_config_section) next;
} pfs_config_section_t;

/*
 * \brief: configuration handle
 */
typedef struct pfs_config {
	int	num_of_sect;

	TAILQ_HEAD(, pfs_config_section) sect_list;
} pfs_config_t;

/* brief: reload config from file */
int	pfs_config_load(const char *config_path, void (*func)(const char *, const char *, void*), void *data);

#endif //_CHUNK_SERVER_PFS_CONFIG_H_
