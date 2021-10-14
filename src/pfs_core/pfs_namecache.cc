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

#include "pfs_impl.h"
#include "pfs_memory.h"
#include "pfs_trace.h"
#include "pfs_mount.h"
#include "pfs_namecache.h"
#include "pfs_option.h"
#include "pfs_admin.h"
#include "lib/fnv_hash.h"
#include "pfs_config.h"

#include <sys/queue.h>
#include <sys/time.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

/* Estimated average bucket length */
#define SEARCH_DEPTH	4UL

#define NCHHASH(hash) \
		(&nchashtbl[(hash) & nchash_mask])

#define NCHHASH_EXPAND(hash) \
		(&expand_info->nchashtbl[(hash) & expand_info->nchash_mask])

#define NCHHASH_IDX(hash) \
		((hash) & nchash_mask)

#define DENOHASH(hash) \
		(&denohashtbl[(hash) & nchash_mask])

#define DENOHASH_EXPAND(hash) \
		(&expand_info->denohashtbl[(hash) & expand_info->nchash_mask])

struct namecache {
	LIST_ENTRY(namecache) nc_hash;  /* hash chain */
	LIST_ENTRY(namecache) nc_deno_hash;  /* deno hash chain */
	TAILQ_ENTRY(namecache) nc_lru_link;  /* lru chain */
	pfs_mount_t *nc_mnt;            /* mount data */
	pfs_ino_t nc_parent_ino;        /* inode of parent of name */
	pfs_ino_t nc_ino;               /* inode the name refers to */
	int64_t nc_deno;				/* direntry number */
	uint64_t nc_promoted;			/* last timestamp the item promoted */
	unsigned nc_nlen;          		/* length of name */
	char nc_name[0];                /* segment name */
};

typedef LIST_HEAD(nchashhead, namecache) nchashhead_t;

static pthread_rwlock_t nch_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t lru_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static nchashhead_t *nchashtbl;         /* Hash Table */
static nchashhead_t *denohashtbl;       /* Hash Table by deno id */
static TAILQ_HEAD(nclist, namecache)  nc_lru;
static u_long nchash_sz;                /* Size of hash table */
static u_long nchash_mask;              /* Mask of hash table */
static u_long numcache;
static u_long nummiss;
static u_long numchecks;
static u_long numhits;
static u_long numdelbydeno;
static u_long numdelbyname;
static u_long numevicts;
static u_long numrejects;

#ifdef NAMECACHE_RESIZE_DEBUG
/*
 * Default value is very small, type following command to change it.
 *
 *  pfsadm config -s 3-1 nc_max 4096
 *
 * Read log file to see if hash bucket is resized.
 */
#define DEFAULT_NC_SIZE		4
#define DEFAULT_NC_MAX		16
#else
#define DEFAULT_NC_SIZE		8192
#define DEFAULT_NC_MAX		32768
#endif

/* Number of names kept in hash table */
static int64_t nc_max = DEFAULT_NC_MAX;
static int64_t nc_enable = PFS_OPT_ENABLE;
static int64_t nc_lru_window = 100000; /* microseconds */
static int64_t nc_max_bucket_len = SEARCH_DEPTH * 50; /* microseconds */
static int nc_expanding;

struct expand_info_ctl {
	u_long 			expand_bucket;
	nchashhead_t	*nchashtbl;			/* Hash Table */
	nchashhead_t	*denohashtbl;		/* Hash Table */
	u_long			nchash_sz;			/* size of hash table */
	u_long			nchash_mask;        /* mask of hash table */
};

static expand_info_ctl *expand_info;

PFS_OPTION_REG(nc_max, pfs_check_ival_normal);
PFS_OPTION_REG(nc_enable, pfs_check_ival_switch);
PFS_OPTION_REG(nc_lru_window, pfs_check_ival_normal);
PFS_OPTION_REG(nc_max_bucket_len, pfs_check_ival_normal);

static void rehash_namecache(void);

static inline u_long
get_nc_max(void)
{
#define NC_HARD_LIMIT 131072
	if (nc_max < NC_HARD_LIMIT)
		return nc_max;
	return NC_HARD_LIMIT;
}

static void
hash_init(u_long elements, u_long *hsize, u_long *hmask)
{
	u_long hashsize;

	for (hashsize = 1; hashsize < elements; hashsize <<= 1) {
		continue;
	}
	*hmask = hashsize - 1;
	*hsize = hashsize;
}

static void *
hash_alloc(u_long hashsize)
{
	nchashhead_t *hashtbl;
	u_long i;

	hashtbl = (nchashhead_t *)pfs_mem_malloc(
		(u_long)hashsize * sizeof(*hashtbl), M_NAMECACHE);
	for (i = 0; i < hashsize; i++) {
		LIST_INIT(&hashtbl[i]);
	}
	return hashtbl;
}

static void __attribute__((constructor))
pfs_nchinit(void)
{
	hash_init(DEFAULT_NC_SIZE, &nchash_sz, &nchash_mask);
	nchashtbl = (nchashhead_t *)hash_alloc(nchash_sz);
	denohashtbl = (nchashhead_t *)hash_alloc(nchash_sz);
	TAILQ_INIT(&nc_lru);
}

static inline u_long
calc_hash(pfs_mount_t *mnt, pfs_ino_t ino, const char *name, size_t namelen)
{
	u_int32_t hash;

	hash = fnv_32_buf(name, namelen, FNV1_32_INIT);
	hash = fnv_32_buf(&ino, sizeof(ino), hash);
	hash = fnv_32_buf(&mnt, sizeof(mnt), hash);
	return hash;
}

static inline u_long
calc_deno_hash(pfs_mount_t *mnt, int64_t deno)
{
	u_int32_t hash;

	hash = fnv_32_buf(&deno, sizeof(deno), FNV1_32_INIT);
	hash = fnv_32_buf(&mnt, sizeof(mnt), hash);
	return hash;
}

/*
 * Precondition: both hash table and lru locks should be locked
 * by current thread.
 */
static void
remove_entry(struct namecache *ncp)
{
	TAILQ_REMOVE(&nc_lru, ncp, nc_lru_link);
	LIST_REMOVE(ncp, nc_hash);
	LIST_REMOVE(ncp, nc_deno_hash);
	numcache--;
}

static void
remove_entry_and_save(struct namecache *ncp, struct nclist *todel)
{
	TAILQ_REMOVE(&nc_lru, ncp, nc_lru_link);
	LIST_REMOVE(ncp, nc_hash);
	LIST_REMOVE(ncp, nc_deno_hash);
	TAILQ_INSERT_HEAD(todel, ncp, nc_lru_link);
	numcache--;
}

static void
evict_entries(struct nclist *todel)
{
	struct namecache *ncp;

	while (numcache > (u_long) get_nc_max()) {
		/* Remove least used entry */
		ncp = TAILQ_LAST(&nc_lru, nclist);
		if (ncp == NULL) /* Is this possible? should panic */
			break;
		remove_entry_and_save(ncp, todel);
		numevicts++;
	}
}

static void
free_entry_list(struct nclist *todel)
{
	struct namecache *ncp;

	while (!TAILQ_EMPTY(todel)) {
		ncp = TAILQ_FIRST(todel);
		TAILQ_REMOVE(todel, ncp, nc_lru_link);
		pfs_mem_free(ncp, M_NAMECACHE);
	}
}

static inline uint64_t
get_current_time(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static inline bool
should_promote(uint64_t now, struct namecache *ncp)
{
	int64_t diff = (now - ncp->nc_promoted);
	return (diff < 0 || diff >= nc_lru_window);
}

static void
promote_entry(struct namecache *ncp, uint64_t now)
{
	if (TAILQ_FIRST(&nc_lru) != ncp) {
		TAILQ_REMOVE(&nc_lru, ncp, nc_lru_link);
		TAILQ_INSERT_HEAD(&nc_lru, ncp, nc_lru_link);
		ncp->nc_promoted = now;
	}
}

static inline nchashhead_t *
get_namehash_head_by_idx(u_long i)
{
	nchashhead_t *nhh;

	if (!nc_expanding || i >= expand_info->expand_bucket)
		nhh = &nchashtbl[i];
	else
		nhh = &expand_info->nchashtbl[i];
	return nhh;
}

static inline nchashhead_t *
get_namehash_head(u_long hash)
{
	u_long idx;
	nchashhead_t *nhh;

	idx = NCHHASH_IDX(hash);
	if (!nc_expanding || idx >= expand_info->expand_bucket)
		nhh = &nchashtbl[idx];
	else
		nhh = NCHHASH_EXPAND(hash);
	return nhh;
}

static inline nchashhead_t *
get_denohash_head_by_idx(u_long i)
{
	nchashhead_t *dhh;

	if (!nc_expanding || i >= expand_info->expand_bucket)
		dhh = &denohashtbl[i];
	else
		dhh = &expand_info->denohashtbl[i];
	return dhh;
}

static inline nchashhead_t *
get_denohash_head(u_long hash)
{
	u_long idx;
	nchashhead_t *dhh;

	idx = NCHHASH_IDX(hash);
	if (!nc_expanding || idx >= expand_info->expand_bucket)
		dhh = &denohashtbl[idx];
	else
		dhh = DENOHASH_EXPAND(hash);
	return dhh;
}

static inline bool
should_rehash(void)
{
	return ((u_long)get_nc_max() > nchash_sz * SEARCH_DEPTH && !nc_expanding);
}

void
pfs_namecache_enter(pfs_mount_t *mnt, pfs_ino_t parent_ino,
  pfs_ino_t child_ino, const char *name, int64_t deno)
{
	struct nclist todel;
	struct namecache *ncp, *ncp2;
	nchashhead_t *dhh;
	nchashhead_t *nhh;
	u_long hash, hash2;
	size_t namelen;
	uint64_t now;
	int bucket_len = 0;

	/* pfs_option_set can not handle value <= 0 */
	if (nc_enable == PFS_OPT_DISABLE)
		return;

	if (name[0] == '\0') {
		return;
	} else if (name[0] == '.') {
		if (name[1] == '\0')
			return;
		if (name[1] == '.' && name[2] == '\0')
			return;
	}

	namelen = strlen(name);

	TAILQ_INIT(&todel);
	ncp = (struct namecache *) pfs_mem_malloc(sizeof(*ncp) + namelen + 1,
		M_NAMECACHE);
	if (ncp == NULL) {
		/* Not enough memory, but we can keep going */
		return;
	}
	ncp->nc_mnt = mnt;
	ncp->nc_parent_ino = parent_ino;
	ncp->nc_ino = child_ino;
	ncp->nc_deno = deno;
	ncp->nc_nlen = namelen;
	memcpy(ncp->nc_name, name, namelen+1);

	hash = calc_hash(mnt, parent_ino, name, namelen);
	hash2 = calc_deno_hash(mnt, deno);

	rwlock_wrlock(&nch_lock);

	nhh = get_namehash_head(hash);
	dhh = get_denohash_head(hash2);

	/* Check if entry already exists */
	LIST_FOREACH(ncp2, nhh, nc_hash) {
		bucket_len++;
		if (ncp2->nc_mnt == mnt && ncp2->nc_parent_ino == parent_ino &&
			ncp2->nc_nlen == namelen &&
			!memcmp(ncp2->nc_name, name, namelen)) {
			if (child_ino != ncp2->nc_ino || deno != ncp2->nc_deno) {
				/* We don't support replacing, it is an error */
				rwlock_unlock(&nch_lock);
				pfs_etrace("Error! pfs_namecache_enter intends to replace"
						   " namecache, but we don't have such case.");
				PFS_ASSERT(false);
			}
			break;
		}
	}

	now = get_current_time();

	if (ncp2 == NULL) {
		if (bucket_len >= nc_max_bucket_len) {
			numrejects++;
			goto rehash;
		}

		LIST_INSERT_HEAD(nhh, ncp, nc_hash);
		LIST_INSERT_HEAD(dhh, ncp, nc_deno_hash);
		numcache++;
		mutex_lock(&lru_lock);
		TAILQ_INSERT_HEAD(&nc_lru, ncp, nc_lru_link);
		ncp->nc_promoted = now;
		evict_entries(&todel);
		mutex_unlock(&lru_lock);

		ncp = NULL;
	} else if (should_promote(now, ncp2)) {
		mutex_lock(&lru_lock);
		promote_entry(ncp2, now);
		mutex_unlock(&lru_lock);
	}

rehash:
	if (should_rehash())
		rehash_namecache(); /* Note, rehash unlocks nch_lock */
	else
		rwlock_unlock(&nch_lock);
	if (ncp) {
		pfs_mem_free(ncp, M_NAMECACHE);
	}

	free_entry_list(&todel);
	return;
}

#if 0
void
pfs_namecache_delete(pfs_mount_t *mnt, pfs_ino_t parent_ino,
    const char *name)
{
	struct namecache *ncp;
	nchashhead_t *nhh;
	u_long hash;
	size_t namelen;

	namelen = strlen(name);
	hash = calc_hash(mnt, parent_ino, name, namelen);

	rwlock_wrlock(&nch_lock);

	nhh = get_namehash_head(hash);

	LIST_FOREACH(ncp, nhh, nc_hash) {
		if (ncp->nc_mnt == mnt && ncp->nc_parent_ino == parent_ino &&
			ncp->nc_nlen == namelen &&
			!memcmp(ncp->nc_name, name, namelen)) {
			break;
		}
	}

	if (ncp != NULL) {
		mutex_lock(&lru_lock);
		remove_entry(ncp);
		mutex_unlock(&lru_lock);
	}
	rwlock_unlock(&nch_lock);
	if (ncp) {
		pfs_mem_free(ncp, M_NAMECACHE);
		__sync_fetch_and_add(&numdelbyname, 1);
	}
}
#endif

void
pfs_namecache_delete_by_deno(pfs_mount_t *mnt, int64_t deno)
{
	struct namecache *ncp;
	nchashhead_t *dhh;
	u_long hash;

	hash = calc_deno_hash(mnt, deno);
	rwlock_wrlock(&nch_lock);

	dhh = get_denohash_head(hash);

	LIST_FOREACH(ncp, dhh, nc_deno_hash) {
		if (ncp->nc_mnt == mnt && ncp->nc_deno == deno) {
			break;
		}
	}

	if (ncp != NULL) {
		mutex_lock(&lru_lock);
		remove_entry(ncp);
		mutex_unlock(&lru_lock);
	}
	rwlock_unlock(&nch_lock);
	if (ncp) {
		pfs_mem_free(ncp, M_NAMECACHE);
		__sync_fetch_and_add(&numdelbydeno, 1);
	}
}

int
pfs_namecache_lookup(pfs_mount_t *mnt, pfs_ino_t parent_ino, const char *name,
	pfs_ino_t *child_ino)
{
	struct namecache *ncp;
	nchashhead_t *nhh;
	u_long hash;
	size_t namelen;
	u_long checks = 0;
	uint64_t now;

	if (nc_enable == PFS_OPT_DISABLE) {
		return -ENOENT;
	}

	if (name[0] == '.') {
		if (name[1] == '\0') {
			*child_ino = parent_ino;
			return 0;
		}
	}

	namelen = strlen(name);
	hash = calc_hash(mnt, parent_ino, name, namelen);

	rwlock_rdlock(&nch_lock);

	nhh = get_namehash_head(hash);

	LIST_FOREACH(ncp, nhh, nc_hash) {
		checks++;
		if (ncp->nc_mnt == mnt && ncp->nc_parent_ino == parent_ino &&
			ncp->nc_nlen == namelen && !memcmp(ncp->nc_name, name, namelen)) {
			break;
		}
	}

	now = get_current_time();
	if (ncp == NULL) {
		rwlock_unlock(&nch_lock);
		__sync_fetch_and_add(&numchecks, checks);
		__sync_fetch_and_add(&nummiss, 1);
		return -ENOENT;
	} else if (should_promote(now, ncp)) {
		mutex_lock(&lru_lock);
		promote_entry(ncp, now);
		mutex_unlock(&lru_lock);
	}

	*child_ino = ncp->nc_ino;
	rwlock_unlock(&nch_lock);
	__sync_fetch_and_add(&numchecks, checks);
	__sync_fetch_and_add(&numhits, 1);

	return 0;
}

void
pfs_namecache_clear_mount(pfs_mount_t *mnt)
{
	struct nclist todel;
	nchashhead_t *nhh;
	struct namecache *ncp, *next;

	TAILQ_INIT(&todel);
	rwlock_wrlock(&nch_lock);
	while(nc_expanding) {
		rwlock_unlock(&nch_lock);
		usleep(10);
		rwlock_wrlock(&nch_lock);
	}
	for (u_long i = 0; i < nchash_sz; ++i) {
		nhh = get_namehash_head_by_idx(i);
		for (ncp = LIST_FIRST(nhh); ncp; ncp = next) {
			next = LIST_NEXT(ncp, nc_hash);
			if (ncp->nc_mnt == mnt) {
				mutex_lock(&lru_lock);
				remove_entry_and_save(ncp, &todel);
				mutex_unlock(&lru_lock);
			}
		}
	}
	rwlock_unlock(&nch_lock);
	free_entry_list(&todel);
}

static void
free_expand_info(void)
{
	u_long i;

	if (expand_info == NULL)
		return;

	if (expand_info->nchashtbl) {
		for (i = 0; i < expand_info->nchash_sz; ++i) {
			PFS_ASSERT(LIST_EMPTY(&expand_info->nchashtbl[i]));
		}
		pfs_mem_free(expand_info->nchashtbl, M_NAMECACHE);
	}

	if (expand_info->denohashtbl) {
		for (i = 0; i < expand_info->nchash_sz; ++i) {
			PFS_ASSERT(LIST_EMPTY(&expand_info->denohashtbl[i]));
		}
		pfs_mem_free(expand_info->denohashtbl, M_NAMECACHE);
	}

	pfs_mem_free(expand_info, M_NAMECACHE);
	expand_info = NULL;
}

#define DEFAULT_HASH_BULK_MOVE 1
static u_long hash_bulk_move = DEFAULT_HASH_BULK_MOVE;

static void *
maintenance_thread(void *)
{
	struct namecache *ncp;
	nchashhead_t *nhh, *dhh;
	u_long hash;
	u_long i;
	int done = 0;

#define SWAP(a, b, t) do {	\
		t = a;				\
		a = b;				\
		b = t;				\
	} while (0)

	pfs_itrace("Begin expanding name cache, from size %ld to size %ld\n",
		nchash_sz, expand_info->nchash_sz);
	while (!done) {
		rwlock_wrlock(&nch_lock);
		for (i = 0; i < hash_bulk_move; ++i) {
			/* Process name hash */
			while ((ncp = LIST_FIRST(&nchashtbl[expand_info->expand_bucket]))
					!= NULL) {
				/* Remove from old hash bucket */
				LIST_REMOVE(ncp, nc_hash);
				/* Recalc hash and insert into new bucket */
				hash = calc_hash(ncp->nc_mnt, ncp->nc_parent_ino, ncp->nc_name,
					ncp->nc_nlen);
				nhh = NCHHASH_EXPAND(hash);
				LIST_INSERT_HEAD(nhh, ncp, nc_hash);
			}

			/* Process deno hash */
			while ((ncp = LIST_FIRST(&denohashtbl[expand_info->expand_bucket]))
					!= NULL) {
				/* Remove from old hash bucket */
				LIST_REMOVE(ncp, nc_deno_hash);
				/* recalc hash and insert into new bucket */
				hash = calc_deno_hash(ncp->nc_mnt, ncp->nc_deno);
				dhh = DENOHASH_EXPAND(hash);
				LIST_INSERT_HEAD(dhh, ncp, nc_deno_hash);
			}

			expand_info->expand_bucket++;

			if (expand_info->expand_bucket == nchash_sz) {
				nchashhead_t *tmp_nhh;
				u_long tmp_n;

				SWAP(nchashtbl, expand_info->nchashtbl, tmp_nhh);
				SWAP(denohashtbl, expand_info->denohashtbl, tmp_nhh);
				SWAP(nchash_sz, expand_info->nchash_sz, tmp_n);
				SWAP(nchash_mask, expand_info->nchash_mask, tmp_n);
				free_expand_info();
				nc_expanding = false;
				done = 1;
				break;
			}
		}
		rwlock_unlock(&nch_lock);
	}
	pfs_itrace("Done expanding name cache\n");

	return NULL;
}

static void
rehash_namecache(void)
{
	u_long n, hsize, hmask;

	if (!should_rehash()) {
		rwlock_unlock(&nch_lock);
		return;
	}
	n = (get_nc_max() + SEARCH_DEPTH - 1) / SEARCH_DEPTH;
	hash_init(n, &hsize, &hmask);
	expand_info = (struct expand_info_ctl *)
		pfs_mem_malloc(sizeof(*expand_info), M_NAMECACHE);
	if (expand_info == NULL) {
		/* Bad news, but we can keep running. */
		rwlock_unlock(&nch_lock);
		return;
	}

	expand_info->expand_bucket = 0;
	expand_info->nchashtbl = (nchashhead_t *)hash_alloc(hsize);
	expand_info->denohashtbl = (nchashhead_t *)hash_alloc(hsize);
	expand_info->nchash_sz = hsize;
	expand_info->nchash_mask = hmask;

	if (expand_info->nchashtbl == NULL || expand_info->denohashtbl == NULL) {
		/* Bad news, but we can keep running. */
		free_expand_info();
		rwlock_unlock(&nch_lock);
		return;
	}

	nc_expanding = true;

	rwlock_unlock(&nch_lock);

	/* Start a thread to do the expansion */
	int ret = 0;
	pthread_t tid;
	ret = pthread_create(&tid, NULL, maintenance_thread, NULL);

	if (ret != 0) {
		rwlock_wrlock(&nch_lock);
		free_expand_info();
		nc_expanding = false;
		rwlock_unlock(&nch_lock);
	} else {
		ret = pthread_detach(tid);
		PFS_ASSERT(ret == 0);
	}
}

void
pfs_namecache_stat(namecache_stat *stat)
{
	stat->hashsize = nchash_sz;
	stat->numcache = numcache;
	stat->numchecks = numchecks;
	stat->nummiss = nummiss;
	stat->numdelbydeno = numdelbydeno;
	stat->numdelbyname = numdelbyname;
	stat->numhits = numhits;
	stat->numevicts = numevicts;
	stat->numrejects = numrejects;
}

int
pfs_get_namecache_enable(void)
{
	return nc_enable;
}

void
pfs_set_namecache_enable(int en)
{
	nc_enable = en;
}

static void
dump_namecache_entry(FILE *fp, struct namecache *ncp)
{
	fprintf(fp,
		"\tnc_mnt:%p, parent_ino:%ld, ino:%ld, deno:%ld, %s\n",
		ncp->nc_mnt, ncp->nc_parent_ino, ncp->nc_ino, ncp->nc_deno,
		ncp->nc_name);
}

#define	DUMP_PERFORMANCE_DATA	1
#define	DUMP_HASH_TABLE			2
#define	DUMP_DENO_HASH_TABLE	3

int
pfs_namecache_dump(int type, admin_buf_t *ab)
{
	nchashhead_t *nhh;
	struct namecache *ncp;
	u_long i;

	switch (type) {
	case DUMP_PERFORMANCE_DATA:
		pfs_adminbuf_printf(ab, "hashsize:\t%ld\n", nchash_sz);
		pfs_adminbuf_printf(ab, "numcache:\t%ld\n", numcache);
		pfs_adminbuf_printf(ab, "numchecks:\t%ld\n", numchecks);
		pfs_adminbuf_printf(ab, "nummiss:\t%ld\n", nummiss);
		pfs_adminbuf_printf(ab, "numhits:\t%ld\n", numhits);
		pfs_adminbuf_printf(ab, "numevicts:\t%ld\n", numevicts);
		pfs_adminbuf_printf(ab, "numdelbydeno:\t%ld\n", numdelbydeno);
#if 0
		pfs_adminbuf_printf(ab, "numdelbyname:\t%ld\n", numdelbyname);
#endif
		pfs_adminbuf_printf(ab, "numrejects:\t%ld\n", numrejects);
		break;
	case DUMP_HASH_TABLE:
	case DUMP_DENO_HASH_TABLE:
		rwlock_rdlock(&nch_lock);
		for (i = 0; i < nchash_sz; ++i) {
			char *buf;
			size_t buf_size;
			FILE *fp = open_memstream(&buf, &buf_size);
			if (fp == NULL) {
				pfs_etrace("Can not create memstream, errno=%d\n", errno);
				break;
			}
			fprintf(fp, "bucket: %ld\n", i);
			if (type == DUMP_HASH_TABLE) {
				nhh = get_namehash_head_by_idx(i);
				LIST_FOREACH(ncp, nhh, nc_hash) {
					dump_namecache_entry(fp, ncp);
				}
			} else {
				nhh = get_denohash_head_by_idx(i);
				LIST_FOREACH(ncp, nhh, nc_deno_hash) {
					dump_namecache_entry(fp, ncp);
				}
			}
			rwlock_unlock(&nch_lock);
			fclose(fp);
			pfs_adminbuf_printf(ab, "%s", buf);
			free(buf);
			rwlock_rdlock(&nch_lock);
		}
		rwlock_unlock(&nch_lock);
	}
	return 0;
}

int
pfs_namecache_dumpbin(struct cmdinfo *ci, admin_buf_t *ab)
{
	struct namecache_stat *stat;
	struct timeval *tv;

	tv = (struct timeval *)pfs_adminbuf_reserve(ab, sizeof(*tv));
	if (tv == NULL)
		ERR_RETVAL(ENOBUFS);

	gettimeofday(tv, NULL);
	pfs_adminbuf_consume(ab, sizeof(*tv));

	stat = (struct namecache_stat *)pfs_adminbuf_reserve(ab, sizeof(*stat));
	if (stat == NULL)
		ERR_RETVAL(ENOBUFS);

	pfs_namecache_stat(stat);
	pfs_adminbuf_consume(ab, sizeof(*stat));
	return 0;
}
