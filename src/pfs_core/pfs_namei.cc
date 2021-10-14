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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pfs_dir.h"
#include "pfs_impl.h"
#include "pfs_inode.h"
#include "pfs_meta.h"
#include "pfs_mount.h"
#include "pfs_namecache.h"
#include "pfs_namei.h"

#define INSTK_INC	8

struct stkent {
	pfs_inode_t	*se_in;
	uint64_t	se_btime;
};

static void
instk_init(struct instack *stk)
{
	stk->s_vec = NULL;
	stk->s_i = 0;
	stk->s_size = 0;
	memset(stk->s_path, 0, sizeof(stk->s_path));
	stk->s_nextpos = stk->s_path;
}

static void
instk_fini(struct instack *stk)
{
	PFS_ASSERT(stk->s_i == 0);
	if (stk->s_vec != NULL) {
		pfs_mem_free(stk->s_vec, M_INSTK_VEC);
		stk->s_vec = NULL;
		stk->s_size = 0;
	}
}

static int
instk_push(struct instack *stk, pfs_mount_t *mnt, pfs_ino_t ino, uint64_t btime,
    const char *name)
{
	pfs_inode_t *in;
	size_t bufsz;
	int rv;

	if (stk->s_i == 0) {
		PFS_ASSERT(stk->s_path[0] == '\0');
		PFS_ASSERT(stk->s_nextpos == stk->s_path);
	}

	if (stk->s_vec == NULL || stk->s_i >= stk->s_size) {
		stk->s_size += INSTK_INC;
		stk->s_vec = (struct stkent *)pfs_mem_realloc(stk->s_vec,
		    stk->s_size * sizeof(*stk->s_vec), M_INSTK_VEC);
		if (stk->s_vec == NULL)
			ERR_RETVAL(ENOMEM);
	}

	/* increase reference count */
	in = pfs_inode_get(mnt, ino);
	if (in == NULL)
		ERR_RETVAL(ENOMEM);

	/* append path component */
	bufsz = sizeof(stk->s_path) - (stk->s_nextpos - stk->s_path);
	rv = snprintf(stk->s_nextpos, bufsz, "/%s", name);
	PFS_VERIFY(rv > 0 && (size_t)rv < bufsz);
	stk->s_nextpos += rv;
	if (ino == 0)
		*stk->s_nextpos = '/';

	stk->s_vec[stk->s_i].se_in = in;
	stk->s_vec[stk->s_i].se_btime = btime;
	stk->s_i++;
	return 0;
}

static void
instk_pop(struct instack *stk)
{
	char *pos = stk->s_nextpos;
	pfs_inode_t *in;

	PFS_ASSERT(stk->s_i > 0);

	/* truncate last path component */
	if (stk->s_i == 1) {
		/* pop root */
		pos = stk->s_path;
	} else if (stk->s_i == 2) {
		/* pop to root */
		pos = strrchr(stk->s_path, '/');
		pos += 1;
	} else {
		pos = strrchr(stk->s_path, '/');
	}
	*pos = '\0';
	if (stk->s_i == 2) {
		pos--;
	}
	stk->s_nextpos = pos;

	/* decrease reference count */
	in = stk->s_vec[--stk->s_i].se_in;
	pfs_inode_put(in);

	if (stk->s_i == 0) {
		PFS_ASSERT(stk->s_path[0] == '\0');
		PFS_ASSERT(stk->s_nextpos == stk->s_path);
	}
}

static inline struct stkent *
instk_top(struct instack *stk)
{
	PFS_ASSERT(stk->s_i > 0);
	return &stk->s_vec[stk->s_i - 1];
}

static inline size_t
instk_size(struct instack *stk)
{
	return stk->s_i;
}

static inline struct stkent *
instk_parent_of_top(struct instack *stk)
{
	PFS_ASSERT(stk->s_i > 0);
	if (stk->s_i == 1)
		return &stk->s_vec[stk->s_i - 1];
	return &stk->s_vec[stk->s_i - 2];
}

static bool
instk_isvalid(pfs_mount_t *mnt, struct instack *stk, int type)
{
	struct stkent *se;
	pfs_inode_t *in;
	pfs_inode_phy_t *phyin;
	pfs_direntry_phy_t *de;
	pfs_ino_t ino;
	int i, err;
	char realpath[PFS_MAX_PATHLEN];
	uint64_t btime;

	PFS_ASSERT(stk->s_i > 0);
	/* starting point of tracing back to root */
	se = instk_top(stk);
	ino = se->se_in->in_ino;
	btime = se->se_btime;

	/* 1. check path string under metalock */
	err = pfs_dir_path(mnt, ino, realpath, sizeof(realpath), btime);
	if (err < 0 || err == PFS_DE_UNLINKED)
		return false;
	if (strcmp(stk->s_path, realpath) != 0)
		return false;

	/* 2. check phyin chain under metalock */
	i = stk->s_i - 1;
	do {
		se = &stk->s_vec[i];
		in = se->se_in;
		btime = se->se_btime;
		// inode may be stale here if namecache hit
		if (in->in_ino != ino)
			return false;

		phyin = pfs_meta_get_inode(mnt, ino, NULL);
		if (phyin->in_type == PFS_INODET_NONE ||
		    phyin->in_deno == INVALID_DENO)
			return false;
		if (type != PFS_INODET_NONE && phyin->in_type != type)
			return false;
		type = PFS_INODET_DIR;
		if (phyin->in_btime != btime)
			return false;

		de = pfs_meta_get_direntry(mnt, phyin->in_deno, NULL);
		ino = de->de_dirino;
	} while (--i >= 0);
	PFS_ASSERT(ino == INVALID_INO);

	return true;
}
/*
 * pfs_namei_init
 *
 * Init nameinfo with valid pbdpath or relative path
 */
int
pfs_namei_init(nameinfo_t *ni, const char *path, int type)
{
	char *nmstart, *nmend;
	int err, n, len, wdlen;

	memset(ni, 0, sizeof(nameinfo_t));

	/*
	 * Make up a full path. For an absolute path, it is
	 * trivial. For a relative path, current work dir is
	 * added as the prefix.
	 */
	len = (int)sizeof(ni->ni_buf);
	if (path[0] == '\0') {
		ERR_RETVAL(EINVAL);
	} else if (path[0] == '/') {
		/* absoulte path */
		n = snprintf(ni->ni_buf, len, "%s", path);
	} else {
		/* relative path */
		err = pfs_memdir_xgetwd(ni->ni_buf, len);
		if (err < 0) {
			pfs_etrace("failed to getwd: %s\n", strerror(-err));
			return err;
		}

		wdlen = strlen(ni->ni_buf);
		n = snprintf(ni->ni_buf + wdlen, len - wdlen, "/%s", path);
		n += wdlen;
	}
	if (n >= len)
		ERR_RETVAL(ENAMETOOLONG);
	PFS_ASSERT(ni->ni_buf[0] == '/');

	/*
	 * Extract pbd name and move it to the front of ni_buf.
	 */
	nmstart = &ni->ni_buf[1];
	while (*nmstart == '/')
		nmstart++;
	nmend = strchr(nmstart, '/');
	if (nmend == NULL)
		ERR_RETVAL(EINVAL);
	len = nmend - nmstart;
	PFS_ASSERT(len > 0);
	PFS_ASSERT(*nmend == '/');
	if (len >= PFS_MAX_PBDLEN)
		ERR_RETVAL(ENAMETOOLONG);
	memmove(ni->ni_buf, nmstart, len);
	ni->ni_buf[len] = '\0';
	ni->ni_pbd = ni->ni_buf;

	/*
	 * Point to the normal path. Note that
	 * nmend is asserted above that it begins
	 * with '/'.
	 */
	ni->ni_path = nmend;
	ni->ni_ino = 0;		/* starting from root */
	ni->ni_par_ino = 0;	/* root's parent is itself. */
	memset(ni->ni_name_buf, 0, sizeof(ni->ni_name_buf));
	ni->ni_srch_name = ni->ni_name_buf;
	ni->ni_broken_path = true;
	if (ni->ni_path[strlen(ni->ni_path) - 1] == '/') {
		/*
		 * Intened to lookup a file but the name path
		 * is of directoy form.
		 * TODO:
		 * If ni_path doesn't exist, errno should be
		 * ENOENT, not EISDIR.
		 */
		if (type == PFS_INODET_FILE)
			ERR_RETVAL(EISDIR);
		type = PFS_INODET_DIR;
	}
	ni->ni_tgt_type = type;
	ni->ni_par_btime = 0;
	ni->ni_btime = 0;

	instk_init(&ni->ni_instk);

	return 0;
}

void
pfs_namei_fini(nameinfo_t *ni)
{
	struct instack *stk = &ni->ni_instk;
	PFS_ASSERT(instk_size(stk) == 0 && stk->s_vec == NULL);
}

/*
 * Absoulte path consists of components which are separated by slashes.
 * namei_lookup() starts from root directory and resolves those components
 * step by step. Only directory is allowed to step forward or backward. And
 * step direction is decided by those components including dot, dotdot and
 * normal entryname.
 * 1. dot:	stay and do nothing.
 * 2. dotdot:	step backward to parent dir and root dir's parent is itself.
 * 3. entryname:step forward to subentry.
 *
 * During resolving inner component, an error means that path is broken and
 * ni_broken_path is set true.
 * After resolving last component, the path is complete(not broken) even
 * the last doesn't exist. If the last component doesn't exist and oflags
 * includes O_CREAT, it will be created properly.
 *
 * Locking and unlocking inode may happen multiple times during path resolving.
 * To avoid deadlock between inode-lock and meta-lock, we release meta-lock
 * by force in this period. The validity of searching result will be checked in
 * pfs_namei_check_stale().
 *
 * XXX: lookup() is non-reentrant, currently we don't check it.
 */
int
pfs_namei_lookup(pfs_mount_t *mnt, nameinfo_t *ni, int oflags,
    pfs_inode_t **dirinp, pfs_inode_t **tgtinp, int *typep)
{
	int type, err = 0;
	char *name = NULL;
	const char *badname = NULL;
	char *path, *savedptr = NULL;
	pfs_ino_t tgtino;
	size_t maxnamelen;
	pfs_inode_t *in;
	struct instack *stk = &ni->ni_instk;
	struct stkent *se;
	pfs_inode_phy_t *phyin;
	uint64_t btime;

	if (pfs_version_has_features(mnt, PFS_FEATURE_EXTNAME))
		maxnamelen = PFS_MAX_NAMELEN;
	else
		maxnamelen = PFS_MAX_NAMELEN_OLD;

	/* root directory is starting point */
	pfs_meta_lock(mnt);
	phyin = pfs_meta_get_inode(mnt, 0, NULL);
	btime = phyin->in_btime;
	pfs_meta_unlock(mnt);
	err = instk_push(stk, mnt, 0, btime, mnt->mnt_pbdname);
	if (err < 0)
		return err;
	se = instk_top(stk);
	type = PFS_INODET_DIR;

	for (path = ni->ni_path; ; path = NULL) {
		name = strtok_r(path, "/", &savedptr);
		if (name == NULL) {
			ni->ni_broken_path = false;
			break;
		}

		if (badname) {
			/* Name with no direntry is already seen. */
			PFS_ASSERT(err == -ENOENT);
			pfs_dbgtrace("dir %ld doesn't have entry '%s'\n",
			    ni->ni_par_ino, badname);
			break;
		}

		if (strlen(name) >= maxnamelen) {
			pfs_etrace("name too long: %s\n", name);
			err = -ENAMETOOLONG;
			break;
		}

		PFS_ASSERT(se == instk_top(stk));
		PFS_ASSERT(ni->ni_par_ino >= 0 && ni->ni_ino >= 0);
		/* 1. dot */
		if (strcmp(name, ".") == 0) {
			if (type != PFS_INODET_DIR) {
				pfs_etrace("\'%s\' is not a dir\n", name);
				err = -ENOTDIR;
				break;
			}
			continue;
		}

		/* 2. dotdot */
		if (strcmp(name, "..") == 0) {
			if (type != PFS_INODET_DIR) {
				pfs_etrace("\'%s\' is not a dir\n", name);
				err = -ENOTDIR;
				break;
			}

			if (instk_size(stk) > 1)
				instk_pop(stk);
			se = instk_top(stk);

			ni->ni_ino = ni->ni_par_ino;
			pfs_meta_lock(mnt);
			err = pfs_dir_info(mnt, ni->ni_ino, ni->ni_name_buf,
			    sizeof(ni->ni_name_buf), &ni->ni_par_ino);
			pfs_meta_unlock(mnt);
			// no delayed removal on directory currently
			PFS_ASSERT(err != PFS_DE_UNLINKED);
			if (err < 0)
				break;
			ni->ni_srch_name = ni->ni_name_buf;
			continue;
		}

		/* 3. normal entryname, namecache is prior to dirindex */
		in = se->se_in;
		btime = se->se_btime;
		pfs_meta_lock(mnt);
		err = pfs_namecache_lookup(mnt, in->in_ino, name, &tgtino);
		if (err == 0) {
			phyin = pfs_meta_get_inode(mnt, tgtino, NULL);
			type = phyin->in_type;
			btime = phyin->in_btime;
		}
		pfs_meta_unlock(mnt);
		if (err == -ENOENT) {
			pfs_inode_lock(in);
			err = pfs_inode_sync_first(in, PFS_INODET_DIR,
			    btime, true);
			if (err == 0) {
				pfs_meta_lock(mnt);
				err = pfs_inode_dir_find(in, name,
				    &tgtino, &type, &btime);
				pfs_meta_unlock(mnt);
			}
			pfs_inode_unlock(in);
		}
		ni->ni_par_ino = ni->ni_ino;
		ni->ni_srch_name = name;
		if (err == 0) {
			err = instk_push(stk, mnt, tgtino, btime, name);
			if (err < 0)
				break;
			se = instk_top(stk);
			PFS_ASSERT(type != PFS_INODET_NONE);
			ni->ni_ino = tgtino;
		} else {
			ni->ni_ino = INVALID_INO;
			if (err != -ENOENT)
				break;

			/*
			 * For no entry error, it is neccessary to figure out
			 * if this error occurs in the middle of name lookup.
			 * The error is saved here and lookup is continued.
			 */
			badname = name;
		}
	}

	if (err == -ENOENT && !pfs_namei_broken_path(ni)) {
		PFS_ASSERT(ni->ni_par_ino >= 0);
		PFS_ASSERT(ni->ni_ino == INVALID_INO);
		if (oflags & O_CREAT)
			PFS_ASSERT(ni->ni_tgt_type == PFS_INODET_DIR ||
			    ni->ni_tgt_type == PFS_INODET_FILE);

		/* 'in' points to mem-inode of the last parent directory */
		se = instk_top(stk);
		ni->ni_par_btime = se->se_btime;
		if (dirinp)
			*dirinp = se->se_in;
		if (tgtinp)
			*tgtinp = NULL;
		if (typep)
			*typep = type;
	}
	if (err < 0)
		return err;

	/*
	 * target exists, do some check on it.
	 */
	PFS_ASSERT(!ni->ni_broken_path && ni->ni_ino != INVALID_INO);
	if ((oflags & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT)) {
		ERR_RETVAL(EEXIST);
	}

	if (type != PFS_INODET_NONE && ni->ni_tgt_type != PFS_INODET_NONE &&
	    type != ni->ni_tgt_type) {
		err = (type == PFS_INODET_DIR) ? -EISDIR : -ENOTDIR;
		pfs_etrace("target file type mismatched. request %d actual %d\n",
		    ni->ni_tgt_type, type);
		return err;
	}

	se = instk_parent_of_top(stk);
	ni->ni_par_btime = se->se_btime;
	if (dirinp)
		*dirinp = se->se_in;
	se = instk_top(stk);
	ni->ni_btime = se->se_btime;
	if (tgtinp)
		*tgtinp = se->se_in;
	if (typep)
		*typep = type;
	return 0;
}

int
pfs_namei_check_stale(pfs_mount_t *mnt, nameinfo_t *ni, int type)
{
	struct stkent *se;
	if (!instk_isvalid(mnt, &ni->ni_instk, type)) {
		se = instk_top(&ni->ni_instk);
		pfs_itrace("path to ino %ld btime %lu changed, retry.\n",
		    se->se_in->in_ino, se->se_btime);
		return -EAGAIN;
	}
	return 0;
}

void
pfs_namei_lookup_done(nameinfo_t *ni)
{
	struct instack *stk = &ni->ni_instk;
	while (instk_size(stk) > 0)
		instk_pop(stk);
	instk_fini(stk);
}
