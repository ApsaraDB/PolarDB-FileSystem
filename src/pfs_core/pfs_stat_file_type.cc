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

#include <stdlib.h>
#include <string.h>
#include "pfs_stat_file_type.h"

#define FULL_MATCH(a, b) \
	(0 == memcmp((a), (b), sizeof(b) - 1))
#define TAIL_MATCH(a, len, b) \
	(len >= sizeof(b) && FULL_MATCH(a + len - sizeof(b) + 1, b))
#define HEAD_MATCH(a, len, b) \
	(len >= sizeof(b) && FULL_MATCH(a, b))

#ifndef PGSQL

static bool
is_number_string(const char* str)
{
	while(*str != '\0') {
		if (*str < '0' || *str > '9')
			return false;
		++str;
	}
	return true;
}

const char* pfs_file_type_name[FILE_TYPE_COUNT] = {
    "unknown",
    "pfs_paxos",
    "pfs_journal",
    "sys_space",
    "user_space",
    "replica",
    "checkpoint",
    "undo_log",
    "redo_log",
    "bin_log",
    "purge",
    "write_back",
    "swap_out",

    "others",

    "color_red",
    "color_green",
};

int
pfs_get_file_type(const char* file_path)
{
	const char *file_name = strrchr(file_path, '/'), *tail_str = NULL;
	size_t len = 0;
	int file_type = FILE_OTHERS;
	if (file_name == NULL) {
		return file_type;
	}
	++file_name;
	len = strlen(file_name) + 1;
	switch (len) {
		//It is fixed in "innodb_data_file_path" config.
		case sizeof("ibdata1"):
			if (FULL_MATCH(file_name, "ibdata1"))
				return FILE_SYSTEM_SPACE;
			break;
		case sizeof("innodb_repl.info"):
			if (FULL_MATCH(file_name, "innodb_repl.info"))
				return FILE_REPLICATION;
			break;
		case sizeof("ib_checkpoint"):
			if (FULL_MATCH(file_name, "ib_checkpoint"))
				return FILE_CHECKPOINT;
			break;
		default:
			break;
	}
	if (TAIL_MATCH(file_name, len, ".ibd"))
		return FILE_USER_SPACE;
	if (HEAD_MATCH(file_name, len, "ibdata")) {
		tail_str = file_name + sizeof("ibdata") - 1;
		file_type = FILE_SYSTEM_SPACE;
		goto tail_number_check;
	}
	if (HEAD_MATCH(file_name, len, "undo")){
		tail_str = file_name + sizeof("undo") - 1;
		/**
		 * In mysql 8.0, "undoNNN" is changed to "undo_NNN"
		 */
		if (*tail_str == '_')
			++tail_str;
		file_type = FILE_UNDO_LOG;
		goto tail_number_check;
	}
	if (HEAD_MATCH(file_name, len, "ib_logfile")){
		tail_str = file_name + sizeof("ib_logfile") - 1;
		file_type = FILE_REDO_LOG;
		goto tail_number_check;
	}
	if (HEAD_MATCH(file_name, len, "purged_")){
		tail_str = file_name + sizeof("purged_") - 1;
		file_type = FILE_PURGE;
		goto tail_number_check;
	}
	if (HEAD_MATCH(file_name, len, "mysql-bin.")){
		tail_str = file_name + sizeof("mysql-bin.") - 1;
		file_type = FILE_BIN_LOG;
		goto tail_number_check;
	}

	//When we use "pfs ls /1-1/" cmd, here returns that the type of
	//".pfs-paxos" is FILE_OTHERS for better performance in most cases.
	return file_type;

tail_number_check:
	if (is_number_string(tail_str))
		return file_type;
	return FILE_OTHERS;
}

#else

const char* pfs_file_type_name[FILE_TYPE_COUNT] = {
    "unknown",
    "pfs_paxos",
    "pfs_journal",
    "sys_space",
    "user_space",
    "user_vm",
    "user_fsm",
    "clog",
    "redo_log",
    "log_index",
    "full_page",
    "write_back",
    "swap_out",

    "others",

    "color_red",
    "color_green",
};

int
pfs_get_file_type(const char* file_path)
{
	int type = FILE_OTHERS;
	size_t len = 0;
	const char *file_name = strchr(file_path, '/');
	if (file_name != file_path)
		return type;
	while(*(++file_name) == '/');
	--file_name;

	len = strlen(file_name);
	if (HEAD_MATCH(file_name, len, "/data/base/")) {
		type = FILE_USER_SPACE;
		if (TAIL_MATCH(file_name, len, "_vm"))
			type = FILE_USER_SPACE_VM;
		else if (TAIL_MATCH(file_name, len, "_fsm"))
			type = FILE_USER_SPACE_FSM;
		return type;
	} else if (HEAD_MATCH(file_name, len, "/data/global/"))
		return FILE_SYSTEM_SPACE;
	else if (HEAD_MATCH(file_name, len, "/data/pg_wal/")) {
		type = FILE_REDO_LOG;
		if (HEAD_MATCH(file_name, len, "/data/pg_wal/archive_status"))
			type = FILE_OTHERS;
		return type;
	}
	else if (HEAD_MATCH(file_name, len, "/data/pg_xact/"))
		return FILE_CLOG;
	else if (HEAD_MATCH(file_name, len, "/data/pg_logindex/"))
		return FILE_LOG_INDEX;
	else if (HEAD_MATCH(file_name, len, "/data/polar_fullpage/"))
		return FILE_FULL_PAGE;
	return  type;
}

#endif

int
pfs_get_file_type_index(const char* file_type, int file_type_len)
{
	int file_type_index = -1;
	int i;
	if (strlen(file_type) == 0)
		return file_type_index;
	for (i = 0; i < FILE_TYPE_COUNT; ++i) {
		if (strncmp(file_type, pfs_file_type_name[i], file_type_len)
		    == 0) {
			file_type_index = i;
			break;
		}
	}
	return file_type_index;
}

int
pfs_get_file_type_index_pat(char* file_type_pattern, int file_type_len,
    bool *filter)
{
	char *savedptr = NULL, *name = NULL, *tmp = file_type_pattern;
	int result;
	for(result = -1;;file_type_pattern = NULL) {
		name = strtok_r(file_type_pattern, "|", &savedptr);
		if (name == NULL)
			break;
		result = pfs_get_file_type_index(name,
		    tmp + file_type_len - name);
		if (result < 0)
			break;
		if (filter)
			filter[result] = true;
	}
	return result;
}

const char*
pfs_get_file_type_name(int type)
{
	return pfs_file_type_name[type];
}

