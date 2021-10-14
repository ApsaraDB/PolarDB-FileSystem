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

#ifndef	_PFS_DIR_H_
#define	_PFS_DIR_H_

#include <dirent.h>

#include "pfs_impl.h"
#include "pfs_file.h"
#include "pfs_namei.h"
#include "pfs_api.h"

#define PFS_DIR_END	1	// end of direntry
#define PFS_DE_UNLINKED	2

#define INVALID_EXTDENO	0	// root deno is sentinel
#define DE_ISEXT(de)	(de->de_ino != INVALID_INO && de->de_dirino == INVALID_INO)

typedef struct pfs_tx pfs_tx_t;
typedef struct pfs_mount pfs_mount_t;

typedef struct pfs_direntry_phy {	/* diretory entry */
	char		de_name[PFS_MAX_NAMELEN_OLD];
	union {
	pfs_ino_t	de_ino;		/* (head de) ino for entry */
	uint64_t	de_headdeno;	/* (ext de) head deno */
	};				/* XXX: mo_number is u64 */
	pfs_ino_t	de_dirino;
	uint64_t	de_extdeno;
} pfs_direntry_phy_t;

struct __dirstream {
	struct direntplus d_deplus;	/* should be the first member,
					 * depended on by pfs_readdir */

	int		d_mntid;
	pfs_mount_t	*d_mnt;
	int64_t		d_epoch;
	pfs_ino_t	d_ino;		/* dir ino */

	/*
	 * When read dir, first copy all direntry numbers
	 * into d_deno_vect, then iterate over the vector
	 * and discard all deleted entries. This approach
	 * is intended to provide a consistent view of a
	 * big directory and still unable to include new
	 * added direntries.
	 */
	uint64_t	*d_deno_vect;
	uint64_t	d_deno_index;
	uint64_t	d_deno_count;
};

typedef struct __dirstream DIR;
struct dirent;

/* maintain lifetime of directories' meminode */
void	pfs_memdir_load(pfs_mount_t *mnt);
void	pfs_memdir_unload(pfs_mount_t *mnt);

/* directory tree resolving & updating */
int	pfs_memdir_xlookup(pfs_mount_t *mnt, nameinfo_t *ni, int oflags);
int	pfs_memdir_xremove(pfs_mount_t *mnt, nameinfo_t *ni);
int	pfs_memdir_xrename(pfs_mount_t *mnt, nameinfo_t *oldni, nameinfo_t *newni);

/* dirstream */
int	pfs_memdir_xopen(pfs_mount_t *mnt, nameinfo_t *ni, DIR **dirp);
int	pfs_memdir_xread(pfs_mount_t *mnt, DIR *dir, struct dirent *den_result,
	    struct direntplus **result, bool isplus);
int	pfs_memdir_close(pfs_mount_t *mnt, DIR *dir);

/* current working directory */
int	pfs_memdir_xsetwd(pfs_mount_t *mnt, nameinfo_t *ni);
int	pfs_memdir_xgetwd(char *buf, size_t len);

/* others */
int	pfs_memdir_xdu(pfs_mount_t *mnt, nameinfo_t *ni, int all, int level,
	    int depth, pfs_printer_t *printer, const char *path);

/* meta-dir api */
void	pfs_direntry_getname(pfs_mount_t *mnt, pfs_direntry_phy_t *headde,
	    char *buf, size_t len);
int	pfs_dir_add(pfs_mount_t *mnt, pfs_ino_t dirino, const char *name, bool isdir,
	    pfs_ino_t *inop, uint64_t *btimep);
int	pfs_dir_del(pfs_mount_t *mnt, pfs_ino_t dirino, pfs_ino_t ino,
	    const char *name, bool isdir);
int	pfs_dir_rename(pfs_mount_t *mnt,
	    pfs_ino_t odirino, pfs_ino_t oino, const char *oldname,
	    pfs_ino_t ndirino, pfs_ino_t nino, const char *newname);
int	pfs_dir_path(pfs_mount_t *mnt, pfs_ino_t ino, char *path, size_t len,
	    uint64_t btime);
int	pfs_dir_info(pfs_mount_t *mnt, pfs_ino_t dirino, char *dename,
	    size_t len, pfs_ino_t *parinop);

#endif	/* _PFS_DIR_H_ */
