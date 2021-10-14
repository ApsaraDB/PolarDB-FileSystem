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

#include <stdint.h>

#include "pfs_impl.h"
#include "pfs_mount.h"
#include "pfs_meta.h"
#include "pfs_version.h"
#include "pfs_devio.h"

static uint64_t	pfs_current_version	= 2;

/* table of features supported by all versions */
static uint64_t pfs_feature_table[PFS_MAX_VERSION] = {
	[0] = PFS_FEATURE_NONE,
	[1] = PFS_FEATURE_BLKHOLE,
	[2] = PFS_FEATURE_BLKHOLE | PFS_FEATURE_EXTNAME,
	[3] = PFS_FEATURE_BLKHOLE | PFS_FEATURE_EXTNAME | PFS_FEATURE_PVTID,
};

int
pfs_version_select(pfs_mount_t *mnt)
{
	uint64_t diskver;

	diskver = mnt->mnt_disk_version =
		chunk_magic_version(mnt->mnt_chunkv[0]->ck_phyck->ck_magic);

	pfs_itrace("pfs version: current %llu vs on-disk %llu\n",
	    pfs_current_version, diskver);

	if (pfs_current_version < diskver)
		ERR_RETVAL(ENOTSUP);

	/*
	 * To avoid confusing DB instances, pfs tools always use the
	 * on disk version. Whileas DB instances always run with the
	 * version of the binary executable.
	 */
	if (pfs_istool(mnt))
		mnt->mnt_run_version = diskver;
	else
		mnt->mnt_run_version = pfs_current_version;
	pfs_itrace("pfs run version: %llu\n",  mnt->mnt_run_version);
	return 0;
}

int
pfs_version_upgrade(pfs_mount_t *mnt)
{
	pfs_chunk_phy_t *phyck = NULL;

	PFS_ASSERT(!pfs_istool(mnt) && pfs_writable(mnt));
	PFS_ASSERT(mnt->mnt_run_version == pfs_current_version);

	/*
	 * A RW DB instance can upgrade version only if current
	 * version is newer than the on disk one.
	 */
	PFS_ASSERT(mnt->mnt_disk_version <= mnt->mnt_run_version);
	if (mnt->mnt_disk_version == mnt->mnt_run_version)
		return 0;

	pfs_itrace("pfs upgrade version from %llu to %llu\n",
	    mnt->mnt_disk_version, mnt->mnt_run_version);
	phyck = mnt->mnt_chunkv[0]->ck_phyck;
	phyck->ck_magic = chunk_magic_make(0);
	phyck->ck_checksum = crc32c_compute(phyck, sizeof(*phyck),
	    offsetof(struct pfs_chunk_phy, ck_checksum));
	return pfsdev_pwrite(mnt->mnt_ioch_desc, phyck, PBD_SECTOR_SIZE, 0);
}

bool
pfs_version_has_features(pfs_mount_t *mnt, uint64_t features)
{
	uint64_t rv = mnt->mnt_run_version;

	PFS_ASSERT(rv <= pfs_current_version);
	return (pfs_feature_table[rv] & features) == features;
}

bool
pfs_version_has_features(uint64_t rv, uint64_t features)
{
	PFS_ASSERT(rv <= pfs_current_version);
	return (pfs_feature_table[rv] & features) == features;
}


uint64_t
pfs_version_get()
{
	return pfs_current_version;
}
