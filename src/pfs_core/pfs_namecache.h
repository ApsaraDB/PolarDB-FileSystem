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

#ifndef _PFS_NAME_CACHE_H_
#define _PFS_NAME_CACHE_H_ 1

typedef struct admin_buf admin_buf_t;

#ifndef NAMECACHE_TEST
void pfs_namecache_enter(pfs_mount_t *mnt, pfs_ino_t parent_ino,
    pfs_ino_t child_ino, const char *name, int64_t deno);

#if 0
void pfs_namecache_delete(pfs_mount_t *mnt, pfs_ino_t parent_ino,
    const char *name);
#endif

void pfs_namecache_delete_by_deno(pfs_mount_t *mnt, int64_t deno);

int pfs_namecache_lookup(pfs_mount_t *mnt, pfs_ino_t parent_ino,
    const char *name, pfs_ino_t *child_ino);

void pfs_namecache_clear_mount(pfs_mount_t *mnt);
#endif

int pfs_get_namecache_enable(void);
void pfs_set_namecache_enable(int enable);

struct namecache_stat
{
	unsigned long hashsize;
	unsigned long numcache;
	unsigned long numchecks;
	unsigned long numhits;
	unsigned long nummiss;
	unsigned long numdelbydeno;
	unsigned long numdelbyname;
	unsigned long numevicts;
	unsigned long numrejects;
};

void pfs_namecache_stat(namecache_stat *stat);
int pfs_namecache_dump(int type, admin_buf_t *ab);
int pfs_namecache_dumpbin(struct cmdinfo *ci, admin_buf_t *ab);

#endif
