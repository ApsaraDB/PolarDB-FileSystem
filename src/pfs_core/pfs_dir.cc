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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pfs_dir.h"
#include "pfs_file.h"
#include "pfs_inode.h"
#include "pfs_meta.h"
#include "pfs_tx.h"
#include "pfs_api.h"
#include "pfs_mount.h"
#include "pfs_stat.h"
#include "pfs_namecache.h"

#define d_sysde		d_deplus.dp_sysde	/* code compatible */

static char		work_dir[PFS_MAX_PATHLEN];
pthread_rwlock_t	work_dir_rwlock;

static int pfs_direntry_init(pfs_mount_t *, pfs_direntry_phy_t *, pfs_ino_t, pfs_ino_t, const char *);
static void pfs_direntry_fini(pfs_mount_t *, pfs_direntry_phy_t *);
static int pfs_direntry_setname(pfs_mount_t *, pfs_direntry_phy_t *, const char *);

static void __attribute__((constructor))
init_pfs_work_dir_rwlock()
{
	rwlock_init(&work_dir_rwlock, NULL);
}

static inline const char *
extname_forward(const char *name, size_t step)
{
	return (strlen(name) + 1 <= step ? NULL : name + step);
}

void
pfs_direntry_getname(pfs_mount_t *mnt, pfs_direntry_phy_t *headde,
    char *buf, size_t len)
{
	pfs_direntry_phy_t *de = headde;
	size_t ncopy = 0;
	size_t densize = sizeof(de->de_name);

	PFS_ASSERT(len >= PFS_MAX_NAMELEN);

	for (;;) {
		PFS_ASSERT(ncopy + densize <= PFS_MAX_NAMELEN);
		memcpy(buf + ncopy, de->de_name, densize);
		ncopy += densize;

		if (de->de_extdeno == INVALID_EXTDENO)
			break;
		de = pfs_meta_get_direntry(mnt, de->de_extdeno, NULL);
		PFS_VERIFY(de != NULL);
	}
}

static int
pfs_direntry_setname_ext(pfs_mount_t *mnt, uint64_t deno, uint64_t headdeno,
    const char *newname, uint64_t *pextdeno)
{
	int err = 0;
	pfs_tx_t *tx;
	pfs_txop_t *top;
	pfs_direntry_phy_t *de;
	size_t densize = sizeof(de->de_name);

	/* case 1: newname fits in current direntry chain */
	if (deno == INVALID_EXTDENO && newname == NULL) {
		*pextdeno = INVALID_EXTDENO;
		return 0;
	}

	PFS_ASSERT(pfs_version_has_features(mnt, PFS_FEATURE_EXTNAME));

	tx = pfs_tls_get_tx();
	err = pfs_tx_new_op(tx, top);
	PFS_VERIFY(err == 0);
	/* case 2: extend direntry chain for longer name */
	if (deno == INVALID_EXTDENO && newname != NULL) {
		de = pfs_meta_alloc_direntry(mnt, top);
		if (de == NULL)
			ERR_RETVAL(EPFS_FILE_2MANY);
		pfs_direntry_init(mnt, de, INVALID_INO, (pfs_ino_t)headdeno, newname);
		err = pfs_direntry_setname_ext(mnt, INVALID_EXTDENO, headdeno,
			extname_forward(newname, densize), &de->de_extdeno);
		*pextdeno = MONO_CURR(de);
	}

	/* case 3: truncate redundant extde for shorter name */
	if (deno != INVALID_EXTDENO && newname == NULL) {
		de = pfs_meta_get_direntry(mnt, deno, top);
		PFS_ASSERT(DE_ISEXT(de));
		PFS_ASSERT(de->de_headdeno == headdeno);
		err = pfs_direntry_setname_ext(mnt, de->de_extdeno, headdeno,
			NULL, &de->de_extdeno);
		pfs_direntry_fini(mnt, de);
		pfs_meta_free_direntry(mnt, de, NULL);
		*pextdeno = INVALID_EXTDENO;
	}

	/* case 4: copy name component */
	if (deno != INVALID_EXTDENO && newname != NULL) {
		de = pfs_meta_get_direntry(mnt, deno, top);
		PFS_ASSERT(DE_ISEXT(de));
		PFS_ASSERT(de->de_headdeno == headdeno);
		pfs_direntry_setname(mnt, de, newname);
		err = pfs_direntry_setname_ext(mnt, de->de_extdeno, headdeno,
			extname_forward(newname, densize), &de->de_extdeno);
		*pextdeno = MONO_CURR(de);
	}
	pfs_tx_done_op(tx, top);
	return err;
}

static int
pfs_direntry_setname(pfs_mount_t *mnt, pfs_direntry_phy_t *de, const char *newname)
{
	size_t densize = sizeof(de->de_name);

	strncpy(de->de_name, newname, densize);
	if (DE_ISEXT(de)) {
		PFS_ASSERT(pfs_version_has_features(mnt, PFS_FEATURE_EXTNAME));
		return 0;
	}
	PFS_ASSERT(strcmp(newname, ".") != 0 && strcmp(newname, "..") != 0);
	return pfs_direntry_setname_ext(mnt, de->de_extdeno, MONO_CURR(de),
		extname_forward(newname, densize), &de->de_extdeno);
}

static int
pfs_direntry_init(pfs_mount_t *mnt, pfs_direntry_phy_t *de, pfs_ino_t dirino,
    pfs_ino_t deino, const char *name)
{
	PFS_ASSERT(de->de_name[0] == '\0');
	PFS_ASSERT(de->de_ino == INVALID_INO);
	PFS_ASSERT(de->de_dirino == INVALID_INO);
	PFS_ASSERT(de->de_extdeno == INVALID_EXTDENO);

	de->de_ino = deino;	/* also de_headdeno */
	de->de_dirino = dirino;
	return pfs_direntry_setname(mnt, de, name);
}

static void
pfs_direntry_fini(pfs_mount_t *mnt, pfs_direntry_phy_t *de)
{
	int err;

	err = pfs_direntry_setname(mnt, de, "");
	PFS_VERIFY(err == 0);

	PFS_ASSERT(de->de_name[0] == '\0');
	PFS_ASSERT(de->de_extdeno == INVALID_EXTDENO);
	de->de_ino = INVALID_INO;
	de->de_dirino = INVALID_INO;
}

static inline bool
pfs_dir_isstale(pfs_mount_t *mnt, DIR *dir)
{
	return !mnt || mnt != dir->d_mnt || mnt->mnt_epoch != dir->d_epoch;
}

int
pfs_dir_info(pfs_mount_t *mnt, pfs_ino_t dirino, char *buf, size_t len,
    pfs_ino_t *parinop)
{
	int rv;
	pfs_direntry_phy_t *de;
	pfs_inode_phy_t *in;
	char namebuf[PFS_MAX_NAMELEN];

	/* ROOT_DIR's parent is itself. */
	if (dirino == 0) {
		if (buf) {
			PFS_ASSERT(len > 0);
			buf[0] = '\0';
		}
		*parinop = 0;
		return 0;
	}

	in = pfs_meta_get_inode(mnt, dirino, NULL);
	if (in->in_type != PFS_INODET_DIR)
		ERR_RETVAL(ENOTDIR);
	if (in->in_deno == INVALID_DENO)
		return PFS_DE_UNLINKED;

	de = pfs_meta_get_direntry(mnt, in->in_deno, NULL);
	PFS_ASSERT(MONO_CURR(de) == in->in_deno);
	PFS_ASSERT(de->de_ino == dirino);

	if (buf) {
		pfs_direntry_getname(mnt, de, namebuf, sizeof(namebuf));
		rv = strncpy_safe(buf, namebuf, len);
		if (rv < 0)
			ERR_RETVAL(ENAMETOOLONG);
	}
	*parinop = de->de_dirino;
	return 0;
}

int
pfs_memdir_xlookup(pfs_mount_t *mnt, nameinfo_t *ni, int oflags)
{
	pfs_inode_t *dirin;
	int err;

	if ((oflags & O_CREAT) != 0) {
		tls_write_begin(mnt);
		err = pfs_path_enter(mnt, ni, oflags, &dirin, NULL, NULL);

		if (err == 0) {
			err = pfs_path_check(mnt, ni, ni->ni_tgt_type);
			if (err == 0 && oflags & O_EXCL) {
				pfs_etrace("pathname exists!\n");
				err = -EEXIST;
			}
		} else if (err == -ENOENT && !pfs_namei_broken_path(ni)) {
			pfs_inode_lock(dirin);
			do {
				err = pfs_inode_sync_first(dirin, PFS_INODET_DIR,
				    ni->ni_par_btime, false);
				if (err < 0)
					break;
				err = pfs_path_check(mnt, ni, PFS_INODET_DIR);
				if (err < 0)
					break;

				err = pfs_inode_dir_find(dirin, ni->ni_srch_name,
				    &ni->ni_ino, NULL, NULL);
				if (err == 0)
					err = -EAGAIN;
				if (err < 0 && err != -ENOENT)
					break;
				err = pfs_inode_dir_add(dirin, ni->ni_srch_name,
				    ni->ni_tgt_type == PFS_INODET_DIR, &ni->ni_ino,
				    &ni->ni_btime);
			} while (0);
			pfs_inode_unlock(dirin);
		}

		pfs_path_exit(ni);
		tls_write_end(err);
	} else {
		tls_read_begin(mnt);
		err = pfs_path_enter(mnt, ni, oflags, NULL, NULL, NULL);
		if (err == 0)
			err = pfs_path_check(mnt, ni, ni->ni_tgt_type);

		pfs_path_exit(ni);
		tls_read_end(err);
	}
	return err;
}

int
pfs_dir_add(pfs_mount_t *mnt, pfs_ino_t dirino, const char *name, bool isdir,
    pfs_ino_t *ino, uint64_t *btime)
{
        int err;
	pfs_direntry_phy_t *de;
	pfs_inode_phy_t *dirin, *dein;
	pfs_txop_t *detop, *deintop, *dirintop;
	pfs_tx_t *tx = pfs_tls_get_tx();

	err = 0;
	if ((err = pfs_tx_new_op(tx, detop)) < 0 ||
		(err = pfs_tx_new_op(tx, deintop)) < 0 ||
		(err = pfs_tx_new_op(tx, dirintop)) < 0) {
		return err;
	}

	/* ensure the name is nonexistent. */
	dirin = pfs_meta_get_inode(mnt, dirino, dirintop);
	if (dirin->in_type == PFS_INODET_NONE)
		ERR_RETVAL(ENOENT);
	if (dirin->in_type != PFS_INODET_DIR)
		ERR_RETVAL(ENOTDIR);

	/* allocate a new direntry and a new inode */
	de = pfs_meta_alloc_direntry(mnt, detop);
	dein = pfs_meta_alloc_inode(mnt, deintop);
	if (de == NULL)
		ERR_RETVAL(EPFS_FILE_2MANY);
	if (dein == NULL)
		ERR_RETVAL(EPFS_FILE_2MANY);

	err = pfs_direntry_init(mnt, de, dirino, MONO_CURR(dein), name);
	if (err < 0)
		return err;
	pfs_inodephy_init(dein, MONO_CURR(de), isdir);

	/* insert the new direntry into the entry chain */
	err = pfs_meta_list_insert(mnt, GETMO(dirin), GETMO(de));
	if (err < 0)
		return err;
	*ino = MONO_CURR(dein);
	dirin->in_size += sizeof(pfs_metaobj_phy_t);
	INPHY_UPDATE_TIME(dirin, IN_MTIME | IN_CTIME);
	INPHY_UPDATE_TIME(dein, IN_MTIME | IN_CTIME);
	dein->in_btime = gettimeofday_us();
	*btime = dein->in_btime;
	pfs_tx_done_op(tx, dirintop);
	pfs_tx_done_op(tx, detop);
	pfs_tx_done_op(tx, deintop);

	return 0;
}

int
pfs_dir_del(pfs_mount_t *mnt, pfs_ino_t dirino, pfs_ino_t ino,
    const char *name, bool isdir)
{
	int err;
	pfs_inode_phy_t	*dirin, *dein;
	pfs_direntry_phy_t *de;
	pfs_txop_t *detop, *deintop, *dirintop;
	pfs_tx_t *tx = pfs_tls_get_tx();
	char nm[PFS_MAX_NAMELEN];

	err = 0;
	if ((err = pfs_tx_new_op(tx, detop)) < 0 ||
	    (err = pfs_tx_new_op(tx, deintop)) < 0 ||
	    (err = pfs_tx_new_op(tx, dirintop)) < 0) {
		return err;
	}

	dirin = pfs_meta_get_inode(mnt, dirino, dirintop);
	if (dirin->in_type == PFS_INODET_NONE)
		ERR_RETVAL(ENOENT);
	if (dirin->in_type != PFS_INODET_DIR)
		ERR_RETVAL(ENOTDIR);
	dein = pfs_meta_get_inode(mnt, ino, deintop);
	if (dein->in_type == PFS_INODET_NONE)
		ERR_RETVAL(ENOENT);
	if (isdir) {
		if (dein->in_type != PFS_INODET_DIR)
			ERR_RETVAL(ENOTDIR);
		if (MONO_FIRST(dein) != 0)
			ERR_RETVAL(ENOTEMPTY);
	} else {
		if (dein->in_type != PFS_INODET_FILE)
			ERR_RETVAL(EISDIR);
	}
	PFS_ASSERT(dein->in_deno != INVALID_DENO);
	de = pfs_meta_get_direntry(mnt, dein->in_deno, detop);
	if (de->de_ino == INVALID_INO)
		ERR_RETVAL(ENOENT);
	if (dein->in_type == PFS_INODET_DIR && MONO_FIRST(dein) != 0)
		ERR_RETVAL(ENOTEMPTY);

	PFS_ASSERT(de->de_ino == ino);

	pfs_namecache_delete_by_deno(mnt, MONO_CURR(de));

	/* Free the entry and unlink it from the entry chain. */
	err = pfs_meta_list_delete(mnt, GETMO(dirin), GETMO(de));
	if (err < 0)
		return err;
	dirin->in_size -= sizeof(pfs_metaobj_phy_t);

	if (name != NULL) {
		pfs_direntry_getname(mnt, de, nm, sizeof(nm));
		PFS_ASSERT(strcmp(name, nm) == 0);
	}

	pfs_direntry_fini(mnt, de);
	pfs_meta_free_direntry(mnt, de, NULL);

	/*
	 * Decrement link. If the link is non zero, unlink
	 * is done according to standard. Otherwise, the inode should be freed.
	 *
	 * Currently, only one link for each file is supported,
	 * so in_deno points to its direntry.
	 */
	dein->in_deno = INVALID_DENO;
	--dein->in_nlink;
	PFS_ASSERT(dein->in_nlink == 0);

	pfs_tx_done_op(tx, dirintop);
	pfs_tx_done_op(tx, detop);
	pfs_tx_done_op(tx, deintop);

	return 0;
}

static void
pfs_dir_open(pfs_mount_t *mnt, pfs_ino_t ino, DIR *dir)
{
	pfs_inode_phy_t *in;
	pfs_direntry_phy_t *de;
	uint64_t deno;

	dir->d_mntid = mnt->mnt_id;
	dir->d_epoch = mnt->mnt_epoch;
	dir->d_mnt = mnt;
	dir->d_sysde.d_ino = 0;
	dir->d_sysde.d_name[0] = '\0';
	memset(&dir->d_deplus.dp_stat, 0, sizeof(struct stat));
	dir->d_deplus.dp_pvtid = UINT_MAX;
	dir->d_deno_index = 0;
	dir->d_deno_count = 0;
	dir->d_deno_vect = NULL;

	in = pfs_meta_get_inode(mnt, ino, NULL);
	PFS_VERIFY(in != NULL);
	PFS_ASSERT((in->in_size % sizeof(pfs_metaobj_phy_t)) == 0);
	dir->d_ino = ino;
	dir->d_deno_count = in->in_size / sizeof(pfs_metaobj_phy_t);
	/*
	 * FIXME:
	 * root directory's in_size doesn't include pfs-paxos
	 * and pfs-journal, fix it.
	 */
	if (ino == 0)
		dir->d_deno_count += 2;
	if (dir->d_deno_count > 0) {
		dir->d_deno_vect = (uint64_t *)pfs_mem_malloc(
		    sizeof(uint64_t) * dir->d_deno_count, M_DENO_VECT);
		PFS_VERIFY(dir->d_deno_vect != NULL);
	}
	/*
	 * Store all deno in vector to make a current view of the
	 * directory. When read dir, the view is refined, with
	 * outdated entries removed.
	 */
	deno = MONO_FIRST(in);
	while (MONO_VALID(deno)) {
		PFS_ASSERT(dir->d_deno_index < dir->d_deno_count);
		dir->d_deno_vect[dir->d_deno_index++] = deno;

		de = pfs_meta_get_direntry(mnt, deno, NULL);
		deno = MONO_NEXT(de);
	}

	/* double check index and reset it to 0 */
	PFS_ASSERT(dir->d_deno_index == dir->d_deno_count);
	dir->d_deno_index = 0;
}

static int
pfs_dir_read(pfs_mount_t *mnt, DIR *dir, struct dirent *den_result, bool isplus)
{
	pfs_inode_phy_t *in;
	pfs_direntry_phy_t *de;
	uint64_t deno, deno_index;
	int err;

	PFS_ASSERT(!den_result || !isplus);
	if (!den_result)
		den_result = &dir->d_sysde;
	do {
		deno_index = __atomic_fetch_add(&dir->d_deno_index, 1,
		    __ATOMIC_ACQ_REL);
		if (deno_index >= dir->d_deno_count)
			return PFS_DIR_END;
		deno = dir->d_deno_vect[deno_index];
		de = pfs_meta_get_direntry(mnt, deno, NULL);
		if (de->de_ino == INVALID_INO || de->de_dirino != dir->d_ino) {
			/*
			 * de may be deleted or moved by other process.
			 * skip it in that case.
			 */
			pfs_etrace("direntry %ld is out of dir %ld, "
			    "possible new dir %ld\n", MONO_CURR(de),
			    dir->d_ino, de->de_dirino);
			de = NULL;
		}
	} while (de == NULL);

	den_result->d_ino = de->de_ino;
	/**
	 * Here we do not output the inner type to avoid visiting inode.
	 */
	den_result->d_type = DT_UNKNOWN;
	pfs_direntry_getname(mnt, de, den_result->d_name,
	    sizeof(den_result->d_name));
	pfs_dbgtrace("readdir %p to %s\n", dir, den_result->d_name);
	if (isplus) {
		err = pfs_inodephy_stat(mnt, de->de_ino, NULL,
		    &dir->d_deplus.dp_stat);
		/* phyin live longer than direntry, and must be valid at
		 * this moment
		 * */
		PFS_ASSERT(err == 0);
		in = pfs_meta_get_inode(mnt, de->de_ino, NULL);
		dir->d_deplus.dp_pvtid = pfs_inodephy_get_pvtid(mnt, in);
	}
	return 0;
}

static inline void
pfs_dir_close(pfs_mount_t *mnt, DIR *dir)
{
	pfs_mem_free(dir->d_deno_vect, M_DENO_VECT);
	dir->d_deno_index = 0;
	dir->d_deno_count = 0;
	dir->d_deno_vect = NULL;
	return;
}

static int64_t
pfs_dir_du(pfs_mount_t *mnt, pfs_ino_t ino, int all, int level, int depth,
    pfs_printer_t *printer, const char *path)
{
	int err, n;
	uint8_t type;
	pfs_inode_phy_t *in;
	int64_t dusum, subsum;
	char depath[PFS_MAX_PATHLEN];
	DIR *dir;

	pfs_meta_lock(mnt);
	in = pfs_meta_get_inode(mnt, ino, NULL);
	type = in->in_type;	/* TOCTTOU */
	if (type == PFS_INODET_NONE) {
		PFS_ASSERT(type == PFS_INODET_NONE);
		/* inode is removed during traversal */
		pfs_meta_unlock(mnt);
		return 0;
	} else if (type == PFS_INODET_FILE) {
		dusum = pfs_inodephy_diskusage(mnt, in);
		pfs_meta_unlock(mnt);
	} else {
		PFS_ASSERT(type == PFS_INODET_DIR);
		dir = (DIR *)pfs_mem_malloc(sizeof(*dir), M_DIR);
		if (!dir) {
			pfs_meta_unlock(mnt);
			ERR_RETVAL(ENOMEM);
		}
		pfs_dir_open(mnt, ino, dir);
		pfs_meta_unlock(mnt);

		for (dusum = 0; ; dusum += subsum) {
			pfs_meta_lock(mnt);
			err = pfs_dir_read(mnt, dir, NULL, false);
			pfs_meta_unlock(mnt);
			if (err != 0)
				break;

			n = snprintf(depath, sizeof(depath), "%s/%s", path,
			    dir->d_sysde.d_name);
			if (n >= (ssize_t)sizeof(depath)) {
				pfs_etrace("too long file name %s/%s\n", path,
				    dir->d_sysde.d_name);
				err = -ENAMETOOLONG;
				break;
			}

			subsum = pfs_dir_du(mnt, dir->d_sysde.d_ino, all,
			    level + 1, depth, printer, depath);
			if (subsum < 0) {
				err = subsum;
				break;
			}
		}

		if (err == PFS_DIR_END)
			err = 0;
		PFS_ASSERT(!pfs_dir_isstale(mnt, dir));
		pfs_dir_close(mnt, dir);
		pfs_mem_free(dir, M_DIR);
		if (err < 0)
			return err;
	}

	/*
	 * If target in the first level is a regular file, print its info.
	 * If depth's value is -1, direntries in all levels are printed.
	 */
	if ((size_t)level <= (size_t)depth &&
	    (level == 0 || type == PFS_INODET_DIR || all)) {
		/* unit of du's output should be KB */
		err = pfs_printf(printer, "%ld\t%s\n", (dusum >> 10), path);
		if (err < 0)
			return err;
	}
	return dusum;
}

static int
pfs_dir_move(pfs_mount_t *mnt, pfs_ino_t odirino, uint64_t deno,
    pfs_ino_t ndirino, const char *newname)
{
	int err;
	pfs_direntry_phy_t *de;
	pfs_inode_phy_t *in;
	pfs_inode_phy_t *odirin, *ndirin;
	pfs_txop_t *odirintop, *ndirintop, *detop, *intop;
	pfs_tx_t *tx = pfs_tls_get_tx();

	err = 0;
	if ((err = pfs_tx_new_op(tx, odirintop)) < 0 ||
		(err = pfs_tx_new_op(tx, ndirintop)) < 0 ||
		(err = pfs_tx_new_op(tx, detop)) < 0 ||
		(err = pfs_tx_new_op(tx, intop)) < 0) {
		return err;
	}

	odirin = pfs_meta_get_inode(mnt, odirino, odirintop);
	ndirin = pfs_meta_get_inode(mnt, ndirino, ndirintop);
	PFS_ASSERT(odirin->in_type == PFS_INODET_DIR);
	PFS_ASSERT(ndirin->in_type == PFS_INODET_DIR);
	de = pfs_meta_get_direntry(mnt, deno, detop);
	if (de->de_ino == INVALID_INO)
		ERR_RETVAL(ENOENT);
	in = pfs_meta_get_inode(mnt, de->de_ino, intop);

	pfs_namecache_delete_by_deno(mnt, MONO_CURR(de));

	/* unlink entry from olddir's entry chain. */
	err = pfs_meta_list_delete(mnt, GETMO(odirin), GETMO(de));
	if (err < 0)
		return err;
	odirin->in_size -= sizeof(pfs_metaobj_phy_t);
	INPHY_UPDATE_TIME(odirin, IN_MTIME);

	/* insert into newdir's entry chain */
	err = pfs_direntry_setname(mnt, de, newname);
	if (err < 0)
		return err;
	err = pfs_meta_list_insert(mnt, GETMO(ndirin), GETMO(de));
	if (err < 0)
		return err;
	ndirin->in_size += sizeof(pfs_metaobj_phy_t);
	INPHY_UPDATE_TIME(ndirin, IN_MTIME);

	/* update moved entry and its inode */
	de->de_dirino = ndirino;
	INPHY_UPDATE_TIME(in, IN_CTIME);

	pfs_tx_done_op(tx, ndirintop);
	pfs_tx_done_op(tx, odirintop);
	pfs_tx_done_op(tx, detop);
	pfs_tx_done_op(tx, intop);

	return 0;
}

static int
pfs_memdir_before_rename(pfs_mount_t *mnt, nameinfo_t *oldnamei,
    nameinfo_t *newnamei, bool *isdir, pfs_inode_t **odirinp,
    pfs_ino_t *oinop, pfs_inode_t **ndirinp, pfs_ino_t *ninop)
{
	int type, err;
	pfs_inode_t *odirin, *ndirin, *oin, *nin;

	err = pfs_path_enter(mnt, oldnamei, 0, &odirin, &oin, &type);
	if (err < 0)
		return err;
	if (oin->in_ino == 0)
		ERR_RETVAL(EBUSY);

	/*
	 * new path can only be two status: exist or not-exist
	 */
	newnamei->ni_tgt_type = type;
	err = pfs_path_enter(mnt, newnamei, 0, &ndirin, &nin, NULL);
	if (err == 0) {
		if (nin->in_ino == 0)
			ERR_RETVAL(EBUSY);
	} else if (err == -ENOENT) {
		if (pfs_namei_broken_path(newnamei))
			return err; 	/* name path broken in the middle */
		nin = NULL;
	} else
		return err;

	*isdir = (type == PFS_INODET_DIR);
	*odirinp = odirin;
	*ndirinp = ndirin;
	*oinop = oin->in_ino;
	if (nin)
		*ninop = nin->in_ino;	/* may be NULL */
	return 0;
}

static void
pfs_memdir_after_rename(nameinfo_t *oldnamei, nameinfo_t *newnamei,
    pfs_inode_t *odirin, pfs_inode_t *ndirin, int err)
{
	pfs_path_exit(oldnamei);
	pfs_path_exit(newnamei);
}

int
pfs_dir_rename(pfs_mount_t *mnt,
    pfs_ino_t odirino, pfs_ino_t oino, const char *oldname,
    pfs_ino_t ndirino, pfs_ino_t nino, const char *newname)
{
	pfs_inode_phy_t		*odirin, *ndirin, *oldin, *newin;
	int			err;
	pfs_ino_t		dirino;

	odirin = pfs_meta_get_inode(mnt, odirino, NULL);
	if (odirin->in_type == PFS_INODET_NONE)
		ERR_RETVAL(ENOENT);
	if (odirin->in_type != PFS_INODET_DIR)
		ERR_RETVAL(ENOTDIR);
	ndirin = pfs_meta_get_inode(mnt, ndirino, NULL);
	if (ndirin->in_type == PFS_INODET_NONE)
		ERR_RETVAL(ENOENT);
	if (ndirin->in_type != PFS_INODET_DIR)
		ERR_RETVAL(ENOTDIR);

	oldin = pfs_meta_get_inode(mnt, oino, NULL);
	if (nino != INVALID_INO)
		newin = pfs_meta_get_inode(mnt, nino, NULL);
	else
		newin = NULL;

	/*
	 * check whether newpath is a subdir of oldpath.
	 */
	if (oldin->in_type == PFS_INODET_DIR) {
		dirino = ndirino;
		while (dirino > 0 && dirino != oino) {
			err = pfs_dir_info(mnt, dirino, NULL, 0, &dirino);
			if (err < 0)
				return err;
			PFS_ASSERT(err != PFS_DE_UNLINKED);
		}
		if (dirino == oino) {
			pfs_etrace("can't rename %s(%ld) to subdirectory of"
			    " itself\n", oldname, oino);
			ERR_RETVAL(EINVAL);
		}
		/* reach ROOT_DIR */
		PFS_ASSERT(dirino == 0);
	}

	if (newin) {
		PFS_ASSERT(newin->in_deno != INVALID_DENO);
		switch (newin->in_type) {
		case PFS_INODET_DIR:
			err = pfs_dir_del(mnt, ndirino, nino, NULL, true);
			break;

		case PFS_INODET_FILE:
			err = pfs_dir_del(mnt, ndirino, nino, NULL, false);
			break;

		default:
			PFS_ASSERT("not reachable" == NULL);
			ERR_RETVAL(EINVAL);
		}
		if (err < 0)
			return err;
	}

	/* move to new path */
	PFS_ASSERT(oino > 0 && nino != 0);
	PFS_ASSERT(oldin->in_deno != INVALID_DENO);
	return pfs_dir_move(mnt, odirino, oldin->in_deno, ndirino, newname);
}

int
pfs_memdir_xopen(pfs_mount_t *mnt, nameinfo_t *ni, DIR **dirp)
{
	int err;
	DIR *dir;
	pfs_inode_t *in = NULL;

	dir = (DIR *)pfs_mem_malloc(sizeof(*dir), M_DIR);
	if (!dir) {
		ERR_RETVAL(ENOMEM);
	}
	MNT_STAT_BEGIN();
	tls_read_begin(mnt);
	err = pfs_path_enter(mnt, ni, 0, NULL, &in, NULL);

	if (err == 0) {
		pfs_inode_lock(in);
		err = pfs_inode_sync_first(in, ni->ni_tgt_type,
		    ni->ni_btime, false);
		if (err == 0)
			err = pfs_path_check(mnt, ni, ni->ni_tgt_type);
		if (err == 0)
			pfs_dir_open(mnt, in->in_ino, dir);
		pfs_inode_unlock(in);
	}

	pfs_path_exit(ni);
	tls_read_end(err);

	if (err == 0)
		*dirp = dir;
	else {
		pfs_mem_free(dir, M_DIR);
		*dirp = NULL;
	}
	MNT_STAT_END(MNT_STAT_DIR_OPENDIR);
	return err;
}

int
pfs_memdir_xread(pfs_mount_t *mnt, DIR *dir, struct dirent *den_result,
    struct direntplus **result, bool isplus)
{
	int err;

	if (pfs_dir_isstale(mnt, dir))
		ERR_RETVAL(EBADF);

	MNT_STAT_BEGIN();
	tls_read_begin_flags(mnt, false);
	err = pfs_dir_read(mnt, dir, den_result, isplus);
	tls_read_end(err);

	if (err == 0) {
		*result = (struct direntplus *)&dir->d_deplus;
	} else if (err == PFS_DIR_END) {
		*result = NULL;
		pfs_dbgtrace("readdir %p to the end\n", dir);
		err = 0;
	}
	MNT_STAT_END(MNT_STAT_DIR_READDIR);
	return err;
}

int
pfs_memdir_xremove(pfs_mount_t *mnt, nameinfo_t *ni)
{
	pfs_inode_t *dirin = NULL, *in = NULL;
	int err, sttype;

	MNT_STAT_BEGIN();
	tls_write_begin(mnt);
	err = pfs_path_enter(mnt, ni, 0, &dirin, &in, NULL);

	if (err == 0) {
		pfs_inode_lock(dirin);
		err = pfs_inode_sync_first(dirin, PFS_INODET_DIR,
		    ni->ni_par_btime, false);
		if (err == 0)
			err = pfs_path_check(mnt, ni, ni->ni_tgt_type);
		if (err == 0)
			err = pfs_inode_dir_del(dirin, in->in_ino,
			    ni->ni_srch_name,
			    ni->ni_tgt_type == PFS_INODET_DIR);
		pfs_inode_unlock(dirin);
	}

	pfs_path_exit(ni);
	tls_write_end(err);
	sttype = (ni->ni_tgt_type == PFS_INODET_DIR) ?
	    MNT_STAT_DIR_REMOVE : MNT_STAT_FILE_UNLINK;
	MNT_STAT_END(sttype);

	return err;
}

int
pfs_memdir_xrename(pfs_mount_t *mnt, nameinfo_t *oldni, nameinfo_t *newni)
{
	pfs_inode_t *odirin, *ndirin;
	pfs_ino_t oino, nino;
	bool isdir = false;
	int type, err;

	MNT_STAT_BEGIN();
	tls_write_begin(mnt);

	odirin = ndirin = NULL;
	oino = nino = INVALID_INO;
	err = pfs_memdir_before_rename(mnt, oldni, newni, &isdir,
	    &odirin, &oino, &ndirin, &nino);
	if (err < 0)
		goto out;

	/* 1. lock and check validity of search result */
	/*
	 * Locking order is relaxed. That's because rename() is the only
	 * api that needs locks of two inodes, however, we protect it
	 * with rename_mtx.
	 *
	 * Two locks of inodes may be acquired here, so we release meta-lock
	 * by force to eliminate the possibility of deadlock. It's ok since
	 * the validity of searching result will be checked in pfs_path_check()
	 */
	pfs_inode_lock(odirin);
	err = pfs_inode_sync_first(odirin, PFS_INODET_DIR,
	    oldni->ni_par_btime, true);
	if (err < 0)
		goto unlock_1;
	if (ndirin != odirin) {
		pfs_inode_lock(ndirin);
		err = pfs_inode_sync_first(ndirin, PFS_INODET_DIR,
		    newni->ni_par_btime, true);
		if (err < 0)
			goto unlock_2;
	}

	type = isdir ? PFS_INODET_DIR : PFS_INODET_FILE;
	err = pfs_path_check(mnt, oldni, type);
	if (err < 0)
		goto unlock_2;
	if (nino == INVALID_INO)
		type = PFS_INODET_DIR;
	err = pfs_path_check(mnt, newni, type);
	if (err < 0)
		goto unlock_2;

	if (nino == INVALID_INO) {
		// check again whether new target file exists under meta lock
		err = pfs_inode_dir_find(ndirin, newni->ni_srch_name,
		    &nino, NULL, NULL);
		if (err == 0)
			err = -EAGAIN;
		if (err < 0 && err != -ENOENT)
			goto unlock_2;
		PFS_VERIFY(err == -ENOENT && nino == INVALID_INO);
	}

	/* 2. do rename */
	err = pfs_inode_dir_rename(mnt, isdir, odirin, oino,
	    oldni->ni_srch_name, ndirin, nino, newni->ni_srch_name);

	/* 3. unlock and out */
unlock_2:
	if (ndirin && ndirin != odirin)
		pfs_inode_unlock(ndirin);
unlock_1:
	pfs_inode_unlock(odirin);
out:
	pfs_memdir_after_rename(oldni, newni, odirin, ndirin, err);
	tls_write_end(err);
	MNT_STAT_END(MNT_STAT_DIR_RENAME);
	return err;
}

int
pfs_memdir_close(pfs_mount_t *mnt, DIR *dir)
{
	bool stale;

	stale = pfs_dir_isstale(mnt, dir);
	if (!stale)
		pfs_dir_close(mnt, dir);

	pfs_mem_free(dir, M_DIR);
	if (stale)
		ERR_RETVAL(EBADF);
	return 0;
}

static ssize_t
dir_path_impl(pfs_mount_t *mnt, int64_t deno, char *path, size_t len)
{
	ssize_t nused;
	size_t n, namelen;
	pfs_direntry_phy_t *de;
	pfs_inode_phy_t *dirin;
	char namebuf[PFS_MAX_NAMELEN];

	if (deno == 0) {
		n = snprintf(path, len, "/%s", mnt->mnt_pbdname);
		return (n >= len) ?  -ENAMETOOLONG : n;
	}

	de = pfs_meta_get_direntry(mnt, deno, NULL);
	if (de->de_ino == INVALID_INO)
		ERR_RETVAL(ENOENT);
	pfs_direntry_getname(mnt, de, namebuf, sizeof(namebuf));
	namelen = 1 + strlen(namebuf); /* "/" + dename */
	if (namelen >= len)
		ERR_RETVAL(ENAMETOOLONG);

	dirin = pfs_meta_get_inode(mnt, de->de_dirino, NULL);
	PFS_ASSERT(dirin->in_deno != INVALID_DENO);
	nused = dir_path_impl(mnt, dirin->in_deno, path, len - namelen);
	if (nused < 0)
		return nused;

	PFS_ASSERT(nused >= 0 && namelen + nused < len);
	n = snprintf(&path[nused], len - nused, "/%s", namebuf);
	PFS_VERIFY(n == namelen);
	return nused + namelen;
}

int
pfs_dir_path(pfs_mount_t *mnt, pfs_ino_t ino, char *path, size_t len,
    uint64_t btime)
{
	int err;
	ssize_t nused;
	pfs_inode_phy_t *in;

	in = pfs_meta_get_inode(mnt, ino, NULL);
	if (in->in_type == PFS_INODET_NONE || in->in_btime != btime)
		ERR_RETVAL(ENOENT);

	/* unlinking */
	if (in->in_deno == INVALID_DENO)
		return PFS_DE_UNLINKED;

	nused = dir_path_impl(mnt, in->in_deno, path, len);
	err = (nused < 0) ? (int)nused : 0;
	if (err < 0)
		return err;

	/* ROOT_DIR should add one slash at the end */
	PFS_ASSERT((size_t)nused == strlen(path));
	if (ino == 0) {
		if ((size_t)nused + 1 >= len)
			ERR_RETVAL(ENAMETOOLONG);
		path[nused] = '/';
		path[nused + 1] = '\0';
	}

	return 0;
}

int
pfs_memdir_xdu(pfs_mount_t *mnt, nameinfo_t *ni, int all, int level, int depth,
    pfs_printer_t *printer, const char *path)
{
	int err;
	int64_t nblksum;
	MNT_STAT_BEGIN();
	tls_read_begin(mnt);
	err = pfs_path_enter(mnt, ni, 0, NULL, NULL, NULL);

	if (err == 0) {
		err = pfs_path_check(mnt, ni, ni->ni_tgt_type);
		if (err == 0) {
			nblksum = pfs_dir_du(mnt, ni->ni_ino, all, level, depth,
			    printer, path);
			err = (nblksum < 0) ? (int)nblksum : 0;
		}
	}

	pfs_path_exit(ni);
	tls_read_end(err);
	MNT_STAT_END(MNT_STAT_DIR_DU);
	return err;
}

static int
pfs_dir_setwd(pfs_mount_t *mnt, pfs_ino_t ino, uint64_t btime)
{
	int err, ncopy;
	char pathbuf[PFS_MAX_PATHLEN];

	/* get absoulte path of work directory */
	err = pfs_dir_path(mnt, ino, pathbuf, PFS_MAX_PATHLEN,
	    btime);
	if (err < 0)
		return err;
	PFS_ASSERT(err != PFS_DE_UNLINKED);

	ncopy = strncpy_safe(work_dir, pathbuf, PFS_MAX_PATHLEN);
	PFS_VERIFY(ncopy > 0);
	return 0;
}

int
pfs_memdir_xsetwd(pfs_mount_t *mnt, nameinfo_t *ni)
{
	int err;
	pfs_inode_t *in = NULL;
	tls_read_begin(mnt);
	rwlock_wrlock(&work_dir_rwlock);
	err = pfs_path_enter(mnt, ni, 0, NULL, &in, NULL);

	if (err == 0) {
		pfs_inode_lock(in);
		err = pfs_inode_sync_first(in, ni->ni_tgt_type, ni->ni_btime, false);
		if (err == 0)
			err = pfs_path_check(mnt, ni, ni->ni_tgt_type);
		if (err == 0)
			err = pfs_dir_setwd(mnt, in->in_ino, ni->ni_btime);
		pfs_inode_unlock(in);
	}

	pfs_path_exit(ni);
	rwlock_unlock(&work_dir_rwlock);
	tls_read_end(err);
	return err;
}

static int
pfs_dir_getwd(char *buf, size_t len)
{
	int n;

	PFS_ASSERT(len > 0);
	/*
	 * XXX: return "" if never chdir before.
	 * MySQL will access the buf without checking return value for now.
	 * Return error here without trace to avoid redundant error log.
	 */
	if (work_dir[0] == '\0') {
		pfs_itrace("work_dir is empty\n");
		buf[0] = '\0';
		return -ENOENT;
	}

	n = strncpy_safe(buf, work_dir, len);
	if (n < 0)
		ERR_RETVAL(ERANGE);
	return 0;
}

int
pfs_memdir_xgetwd(char *buf, size_t len)
{
	int err;

	/*
	 * XXX:
	 * we don't check whether work_dir is valid,
	 * so metadata lock isn't necessary.
	 */
	//tls_read_begin(mnt);
	rwlock_rdlock(&work_dir_rwlock);
	err = pfs_dir_getwd(buf, len);
	rwlock_unlock(&work_dir_rwlock);
	//tls_read_end(err);
	return err;
}

void
pfs_memdir_load(pfs_mount_t *mnt)
{
	pfs_inode_t *rootin;

	/* trigger create() */
	rootin = pfs_inode_get(mnt, 0);
	PFS_VERIFY(rootin != NULL);
}

void
pfs_memdir_unload(pfs_mount_t *mnt)
{
	pfs_inode_t *rootin;

	rootin = pfs_get_inode(mnt, 0);
	if (rootin == NULL)	/* maybe mount failed */
		return;
	pfs_put_inode(mnt, rootin);

	/* trigger destroy() */
	pfs_inode_put(rootin);
}
