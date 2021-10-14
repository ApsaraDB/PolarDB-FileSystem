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

#ifndef _PFS_VERSION_H_
#define _PFS_VERSION_H_

enum {
	PFS_FEATURE_NONE	= 0,
	PFS_FEATURE_BLKHOLE	= (1ULL << 0),
	PFS_FEATURE_EXTNAME	= (1ULL << 1),
	PFS_FEATURE_PVTID	= (1ULL << 2),
};

typedef struct pfs_chunk_phy	pfs_chunk_phy_t;
typedef struct pfs_mount	pfs_mount_t;
int	pfs_version_select(pfs_mount_t *mnt);
int	pfs_version_upgrade(pfs_mount_t *mnt);
bool	pfs_version_has_features(pfs_mount_t *mnt, uint64_t features);
bool	pfs_version_has_features(uint64_t rv, uint64_t features);
uint64_t pfs_version_get();

#endif
