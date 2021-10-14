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

#ifndef _PFS_NAMEI_H_
#define _PFS_NAMEI_H_

#include "pfs_impl.h"

typedef struct pfs_inode pfs_inode_t;
struct stkent;

struct instack {
	struct stkent	*s_vec;
	int		s_i;
	int		s_size;
	char		s_path[PFS_MAX_PATHLEN];/* formatted path */
	char		*s_nextpos;		/* to locate component */
};

typedef	struct nameinfo {
	/* a copy of path from user */
	char		ni_buf[PFS_MAX_PATHLEN];
	/* decomposed path components */
	char		*ni_pbd;
	char		*ni_path;
	/*
	 * While resolving dotdot we should jump to parent dir,
	 * so we copy ni_ino's de_name into ni_name_buf and let ni_srch_name
	 * point to it.
	 */
	char		*ni_srch_name;
	char		ni_name_buf[PFS_MAX_NAMELEN];

	pfs_ino_t	ni_par_ino;
	pfs_ino_t	ni_ino;
	uint64_t	ni_par_btime;
	uint64_t	ni_btime;
	int		ni_tgt_type;
	/*
	 * When resolving inner path components we can't step
	 * forward or backward, the path is broken.
	 */
	bool		ni_broken_path;

	struct instack	ni_instk;
} nameinfo_t;

typedef struct pfs_mount	pfs_mount_t;

/* nameinfo-related func */
int	pfs_namei_init(nameinfo_t *ni, const char *path, int type);
int	pfs_namei_lookup(pfs_mount_t *mnt, nameinfo_t *ni, int oflags,
	    pfs_inode_t **dirinp, pfs_inode_t **tgtinp, int *typep);
int	pfs_namei_check_stale(pfs_mount_t *mnt, nameinfo_t *ni, int type);
void	pfs_namei_lookup_done(nameinfo_t *ni);
void	pfs_namei_fini(nameinfo_t *ni);

static inline bool
pfs_namei_broken_path(nameinfo_t *ni)
{
	return ni->ni_broken_path;
}

static inline int
pfs_path_enter(pfs_mount_t *mnt, nameinfo_t *ni, int oflags,
    pfs_inode_t **dirinp, pfs_inode_t **tgtinop, int *typep)
{
	/*
	 * The searching result is just a indicator since it releases meta
	 * lock in the middle. Any updates on meta may happen before rechecking
	 * under meta lock.
	 *
	 * However, in most cases, we can still trust in the result if it means
	 * 'parent directory exists but target not', that is for simplicity of
	 * codes. If target file is newly-created during path lookup, the
	 * result of inexistence still make sense.
	 *
	 * @dirinp and @tgtinp shall be synced before any further access.
	 */
	return pfs_namei_lookup(mnt, ni, oflags, dirinp, tgtinop, typep);
}

static inline void
pfs_path_exit(nameinfo_t *ni)
{
	pfs_namei_lookup_done(ni);
}

static inline int
pfs_path_check(pfs_mount_t *mnt, nameinfo_t *ni, int type)
{
	return pfs_namei_check_stale(mnt, ni, type);
}

#endif /* _PFS_NAMEI_H */
