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

#ifndef PFS_FILE_TYPE_H
#define PFS_FILE_TYPE_H

#define FILE_COLOR_TYPE_NCOUNT 2

#define PGSQL

#ifndef PGSQL

enum {
	FILE_PFS_INITED,
	FILE_PFS_PAXOS,
	FILE_PFS_JOUNAL,
	FILE_SYSTEM_SPACE,
	FILE_USER_SPACE,
	FILE_REPLICATION,
	FILE_CHECKPOINT,
	FILE_UNDO_LOG,
	FILE_REDO_LOG,
	FILE_BIN_LOG,
	FILE_PURGE,
	FILE_WRITE_BACK,
	FILE_SWAP_OUT,
	FILE_OTHERS,

	FILE_COLOR_0,
	FILE_COLOR_1,
	FILE_TYPE_COUNT
};

#else

enum {
	FILE_PFS_INITED,
	FILE_PFS_PAXOS,
	FILE_PFS_JOUNAL,
	FILE_SYSTEM_SPACE,
	FILE_USER_SPACE,
	FILE_USER_SPACE_VM,
	FILE_USER_SPACE_FSM,
	FILE_CLOG,
	FILE_REDO_LOG,
	FILE_LOG_INDEX,
	FILE_FULL_PAGE,

	FILE_WRITE_BACK,
	FILE_SWAP_OUT,
	FILE_OTHERS,

	FILE_COLOR_0,
	FILE_COLOR_1,
	FILE_TYPE_COUNT
};

#endif

int pfs_get_file_type(const char* file_path);
int pfs_get_file_type_index_pat(char* file_type_pattern, int file_type_len,
    bool *filter);
const char* pfs_get_file_type_name(int type);
int pfs_get_file_type_index(const char* file_type, int file_type_len);

#endif
