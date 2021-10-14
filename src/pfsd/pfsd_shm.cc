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

#include <pthread.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "pfsd_proto.h"
#include "pfsd_common.h"
#include "pfsd_shm.h"

#ifdef PFSD_SERVER
#include "pfsd_zlog.h"
#include "pfsd_chnl.h"
#endif

/* To be configurable, now it's for polar-pg */
size_t g_shm_unit_size[PFSD_SHM_MAX] = {
    4 * 1024, 8 * 1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024,
    PFSD_MAX_IOSIZE
};
pfsd_shm_t *g_shm[PFSD_SHM_MAX];
char g_shm_fname[PFSD_SHM_MAX][FILE_MAX_FNAME];

/* mutex used only by pfsd */
static pthread_mutex_t *g_chnl_mutex[PFSD_SHM_MAX];

static void pfsd_channel_init(pfsd_iochannel_t *);
static int pfsd_shm_init(pfsd_shm_t *shm, int shm_index, int nch, int nreq,
    size_t req_size);

#ifdef PFSD_SERVER
int
pfsd_shm_init(const char *dir, const char *pbdname, size_t nch)
{
	if (nch == 0)
		return -1;

	assert (g_shm[0] == NULL);

	int shmfd = -1;
	void *shmaddr[PFSD_SHM_MAX] = {NULL};

	size_t total = 0;
	/* init communicate shm */
	for (int si = 0; si < PFSD_SHM_MAX; ++si) {
		size_t unit_size = g_shm_unit_size[si];
		size_t nc = nch;
		int nreq = PFSD_SHM_MAX_REQUESTS;
		while (nc * nreq * unit_size >= (65UL * 1024 * 1024)) {
			/* avoid too much memory or channels for big io */
			if (nc > 1)
				nc /= 2;
			else if (nreq > 1)
				nreq /= 2;
			else
				break;
		}

		/* create or attach shm */
		struct stat st;
		size_t shmsize = pfsd_shm_size(nc, nreq, unit_size);
		total += shmsize;
		char *path = g_shm_fname[si];
		(void)pfsd_make_shm_path(si, dir, pbdname, path,
		    sizeof(g_shm_fname[si])-1);
retry:
		shmfd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0664);
		if (shmfd < 0) {
			pfsd_error("shm_open %s failed with error %d", path,
			    errno);
			goto finish;
		} else {
			chmod(path, 0777);
		}

		if (fstat(shmfd, &st) < 0) {
			pfsd_error("fstat shm failed with error %d", errno);
			goto finish;
		}

		if (st.st_size == 0) {
			if (ftruncate(shmfd, shmsize) == -1) {
				pfsd_error("ftruncate shm failed with error %d",
				    errno);
				goto finish;
			}
		}

		shmaddr[si] = mmap(NULL, shmsize, PROT_READ | PROT_WRITE,
		    MAP_SHARED, shmfd, 0);
		if (shmaddr[si] == MAP_FAILED) {
			pfsd_error("mmap failed with error %d", errno);
			goto finish;
		}
		close(shmfd);
		shmfd = -1;

		pfsd_info("ch %lu, unit %lu, sizeof pfsd_shm %gM", nc,
		    unit_size, shmsize/1024.0/1024.0);

		g_shm[si] = (pfsd_shm_t*)shmaddr[si];
		if (g_shm[si]->sh_magic == PFSD_SHM_MAGIC &&
		    g_shm[si]->sh_version != PFSD_SHM_VERSION) {
			/* not compatiable, unlink and retry */
			pfsd_warn("shm not compatiable, "
			    "will remove %s and recreate", path);
			munmap(g_shm[si], g_shm[si]->sh_size);
			unlink(path);

			goto retry;
		}

		if (pfsd_shm_init(g_shm[si], si, (int)nc, nreq, unit_size) != 0) {
			pfsd_error("pfsd_shm_init failed!");
			goto finish;
		}
	}

	pfsd_info("total pfsd_shm %gM", total/1024.0/1024.0);
	return 0;
finish:
	if (shmfd >= 0)
		close(shmfd);

	for (int si = 0; si < PFSD_SHM_MAX; ++si) {
		if (g_shm[si] != NULL) {
			munmap(g_shm[si], g_shm[si]->sh_size);
			g_shm[si] = NULL;
		}
	}

	pfsd_error("failed init shm: %s", strerror(errno));
	return -1;
}

static int
pfsd_shm_init(pfsd_shm_t *shm, int index, int nch, int nreq, size_t unit_size)
{
	if (shm == NULL || nch <= 0)
		return -1;

	assert (IS_2_POWER(nreq));

	g_chnl_mutex[index] = (pthread_mutex_t *)malloc(nch * sizeof(pthread_mutex_t));
	for (int ci = 0; ci < nch; ++ci) {
		int r = pthread_mutex_init(&g_chnl_mutex[index][ci], NULL);
		PFSD_ASSERT(r == 0);
	}

	shm->sh_index = index;
	if (shm->sh_magic == PFSD_SHM_MAGIC) {
		if (shm->sh_version != PFSD_SHM_VERSION) {
			pfsd_error("but version mismatch: exist %u, now %u",
			    shm->sh_version, PFSD_SHM_VERSION);
			return -1;
		}

		if (shm->sh_nch != nch) {
			pfsd_error("but nchannel mismatch: exist %u, now %u",
			    shm->sh_nch, nch);
			return -1;
		}

		if (shm->sh_unitsize != unit_size) {
			pfsd_error("but unit_size mismatch: exist %lu, now %lu",
			    shm->sh_unitsize, unit_size);
			return -1;
		}

		/* 
		 * Update epoch, when worker thread handle stale request,
		 * will return ESTALE; sdk detect ESTALE, it'll retry silently. 
		 */

		/* 
		 * Why incr by 2? Because channel and worker threads are M:N,
		 * not 1:1. when pfsd restart, to avoid a request be fetched by
		 * multi threads, we set req->shm_epoch 1 plus sh_epoch.
		 * In bad case, if pfsd restart again, we must assure sh_epoch
		 * is bigger than req->shm_epoch, so we plus 2 here.
		 */
		shm->sh_epoch += 2;
		char *channels = (char *)(shm + 1);
		for (int ci = 0; ci < nch; ++ci)  {
			pfsd_iochannel_t *ch =
			    (pfsd_iochannel_t *)(channels + ci * pfsd_channel_size(nreq, unit_size));
			ch->ch_epoch = shm->sh_epoch;
		}

		return 0;
	}

	/* reinit shm */
	memset(shm, 0, sizeof(*shm));

	/* init version */
	shm->sh_version = PFSD_SHM_VERSION;
	shm->sh_unitsize = unit_size;
	shm->sh_epoch = 0;

	shm->sh_size = pfsd_shm_size(nch, nreq, unit_size);
	shm->sh_nch = nch;
	char *channels = (char *)(shm + 1);
	for (int ci = 0; ci < nch; ++ci) {
		pfsd_iochannel_t *ch =
		    (pfsd_iochannel_t *)(channels + ci * pfsd_channel_size(nreq, unit_size));
		ch->ch_unitsize = unit_size;
		ch->ch_index = ci;
		ch->ch_epoch = shm->sh_epoch;
		ch->ch_max_req = nreq;
		pfsd_channel_init(ch);
	}

	/* init magic */
	__sync_synchronize();
	shm->sh_magic = PFSD_SHM_MAGIC;

	return 0;
}
#endif // PFSD_SERVER

/* It's for shm tool debug */
int
pfsd_shm_attach(const char *dir, const char *pbdname, int wr_attach)
{
	if (pbdname == NULL)
		return -1;

	assert (g_shm[0] == NULL);

	int shmfd = -1;
	void *shmaddr[PFSD_SHM_MAX] = {NULL};
	int mflag = PROT_READ;

	if (wr_attach)
		mflag |= PROT_WRITE;

	/* init communicate shm */
	for (int si = 0; si < PFSD_SHM_MAX; ++si) {
		/* attach shm */
		struct stat st;
		char path[PFS_MAX_PATHLEN] = "";
		(void)pfsd_make_shm_path(si, dir, pbdname, path, sizeof(path)-1);
		shmfd = open(path, (wr_attach ? O_RDWR : O_RDONLY) | O_CLOEXEC,
		    0664);
		if (shmfd < 0) {
			fprintf(stderr,
			    "[pfsd]shm_open %s failed with error %d\n",
			    path, errno);
			goto finish;
		}

		if (fstat(shmfd, &st) < 0) {
			fprintf(stderr,
			    "[pfsd]fstat shm failed with error %d\n", errno);
			goto finish;
		}

		shmaddr[si] = mmap(NULL, st.st_size, mflag, MAP_SHARED, shmfd, 0);
		if (shmaddr[si] == MAP_FAILED) {
			fprintf(stderr, "[pfsd]mmap failed with error %d\n",
			    errno);
			goto finish;
		}

		close(shmfd);
		shmfd = -1;

		g_shm[si] = (pfsd_shm_t*)shmaddr[si];
	}

	return 0;
finish:
	if (shmfd >= 0)
		close(shmfd);

	for (int si = 0; si < PFSD_SHM_MAX; ++si) {
		if (g_shm[si] != NULL) {
			munmap(g_shm[si], g_shm[si]->sh_size);
			g_shm[si] = NULL;
		}
	}

	fprintf(stderr, "[pfsd] %s failed\n", __FUNCTION__);
	return -1;
}

void
pfsd_print_shm(pfsd_shm_t *shm)
{
	if (shm->sh_magic != PFSD_SHM_MAGIC) {
		fprintf(stdout, "\033[1;31;40m");
		fprintf(stdout, "Wrong magic %x,, expect %x may be corrupted!",
		    shm->sh_magic, PFSD_SHM_MAGIC);
		fflush(NULL);
		exit(-1);
	}

	fprintf(stdout, "magic %x\n", shm->sh_magic);
	fprintf(stdout, "version %u\n", shm->sh_version);
	fprintf(stdout, "epoch %u\n", shm->sh_epoch);
	fprintf(stdout, "size %d\n", shm->sh_size);
	fprintf(stdout, "req_size %luKB\n", shm->sh_unitsize/1024);
	fprintf(stdout, "nchannels %d\n", shm->sh_nch);
}

void
pfsd_print_channel(pfsd_shm_t *shm, int ci)
{
	if (ci < 0 || ci >= shm->sh_nch)
		return;

	char *channels = (char *)(shm + 1);
	size_t unit_size = ((pfsd_iochannel_t *)channels)->ch_unitsize;
	int nreq = ((pfsd_iochannel_t *)channels)->ch_max_req;

	pfsd_iochannel_t *ch = (pfsd_iochannel_t *)(channels + ci * pfsd_channel_size(nreq, unit_size));
	if (ch->ch_magic != PFSD_SHM_MAGIC) {
		fprintf(stdout, "\033[1;31;40m");
		fprintf(stdout,
		    "Wrong magic %x,, expect %x, channel may be corrupted!",
		    ch->ch_magic, PFSD_SHM_MAGIC);
		fflush(NULL);
		exit(-1);
	}

	uint64_t used_bitmap = ~(ch->ch_free_bitmap);
	if (used_bitmap == 0)
		return;

	if (ffsl(long(used_bitmap)) > ch->ch_max_req)
		return;

	fprintf(stdout, "\033[1;35;40m");
	fprintf(stdout, "\t---------------------------  channel %d "
	    "-------------------------\n", ci);
	fprintf(stdout, "\tmagic %x | ", ch->ch_magic);
	fprintf(stdout, "epoch %u | ", ch->ch_epoch);
	fprintf(stdout, "index %d | ", ch->ch_index);
	fprintf(stdout, "req_size %luKB | ", ch->ch_unitsize/1024);
	fprintf(stdout, "max_req %d\n", ch->ch_max_req);

	int used = 0;

	used_bitmap = ~(ch->ch_free_bitmap);
	fprintf(stdout, "\tused bitmap %#lx\n", used_bitmap);
	fprintf(stdout, "\033[1;32;40m");
	while (used_bitmap != 0) {
		int index = ffsl(long(used_bitmap));
		assert(index > 0);
		index--; /* ffsl return 1-based */

		if (index >= ch->ch_max_req)
			break;

		++used;
		pfsd_request_t *r = &ch->ch_requests[index];
		if (r->state == REQ_FREE || !pfsd_request_alive(r)) {
			fprintf(stdout, "\033[1;31;40m");
			if (r->state == REQ_FREE) {
				fprintf(stdout,
				    "\tWrong state! used but in REQ_FREE state\n");
			} else {
				fprintf(stdout, "\tOwner %d dead!\n", r->owner);
			}
		}

		unsigned char *buf = ch->ch_buf + (r - ch->ch_requests) * ch->ch_unitsize;
		pfsd_request_print(r, buf);
		fprintf(stdout, "\033[1;32;40m");

		/* iterate next index */
		uint64_t mask = 0x1UL << index;
		used_bitmap &= ~mask;
	}
	fprintf(stdout, "\033[0m");

	/* check if something broken */
	uint64_t free_bitmap = ch->ch_free_bitmap;
	fprintf(stdout, "\tfree bitmap %#lx\n", free_bitmap);
	fprintf(stdout, "\033[1;31;40m");
	while (free_bitmap != 0) {
		int index = ffsl(long(free_bitmap));
		assert(index > 0);
		index--; /* ffsl return 1-based */

		if (index >= ch->ch_max_req)
			break;

		pfsd_request_t *r = &ch->ch_requests[index];
		if (r->state != REQ_FREE) {
			fprintf(stdout, "Wrong state! freed but in %s state\n",
			    pfsd_req_state_string(r->state));
			unsigned char *buf = ch->ch_buf + (r - ch->ch_requests) * ch->ch_unitsize;
			pfsd_request_print(r, buf);
			fprintf(stdout, "\033[1;31;40m");
		}

		/* iterate next index */
		uint64_t mask = 0x1UL << index;
		free_bitmap &= ~mask;
	}
	fprintf(stdout, "\033[0m");

	fprintf(stdout, "\tused requests %.2f%%\n", used / (0.01 * ch->ch_max_req));
}

void
pfsd_print_all_channels(pfsd_shm_t *shm)
{
	for (int i = 0; i < shm->sh_nch; ++i)
		pfsd_print_channel(shm, i);
}

#ifdef PFSD_SERVER
static void
pfsd_channel_init(pfsd_iochannel_t *ch)
{
	ch->ch_magic = PFSD_SHM_MAGIC;

	/* init free bitmap */
	ch->ch_free_bitmap = 0;
	for (int index = 0; index < ch->ch_max_req; ++index) {
		ch->ch_free_bitmap |= (0x1UL << index);
	}

	for (int i = 0; i < ch->ch_max_req; ++i) {
		ch->ch_requests[i].owner = PFSD_INVALID_PID;
		ch->ch_requests[i].connid = -1;
		ch->ch_requests[i].state = REQ_FREE;
	}
}

int
pfsd_shm_destroy(pfsd_shm_t *shm)
{
	if (shm == NULL)
		return -1;

	char *channels = (char *)(shm + 1);
	size_t unit_size = ((pfsd_iochannel_t *)channels)->ch_unitsize;
	int nreq = ((pfsd_iochannel_t *)channels)->ch_max_req;

	memset(shm, 0, shm->sh_size);
	return 0;
}
#endif // PFSD_SERVER

#ifdef PFSD_CLIENT
pfsd_request_t *
pfsd_shm_get_request(pfsd_iochannel_t *ch, int connid)
{
	pid_t pid = getpid();

	PFSD_ASSERT (ch->ch_magic == PFSD_SHM_MAGIC);
	int index;
	int64_t old_val;
	int64_t new_val;
	pfsd_request_t *req;
	uint64_t mask = uint64_t(-1);
	uint64_t bmp;

retry:
	/* if ch_free_bitmap say it's free, maybe it's already allocated. */
	bmp = ch->ch_free_bitmap;
	bmp &= mask;
	index = ffsl((long)bmp) - 1;
	if (index < 0) {
		return NULL;
	}

	mask &= ~(0x1UL << index);
	req = &ch->ch_requests[index];

	old_val = req->val;
	if (pfsd_request_get_state(old_val) != REQ_FREE) {
		goto retry;
	}

	new_val = 0;
	new_val = pfsd_request_set_pid(new_val, pid);
	new_val = pfsd_request_set_connid(new_val, (int8_t)connid);
	new_val = pfsd_request_set_state(new_val, REQ_ALLOC);

	if (!__sync_bool_compare_and_swap(&req->val, old_val, new_val)) {
		goto retry;
	} else {
		/* 
		 * Success changing state from REQ_FREE to REQ_ALLOC.
		 * If pg crash at here, the bitmap is not updated,
		 * pfsd will recycle it. No problems
		 */
		(void)__sync_and_and_fetch(&ch->ch_free_bitmap, ~(0x1UL << index));

		req->shm_epoch = ch->ch_epoch;
		int r = sem_init(&ch->ch_responses[index].r_sem,
		    PTHREAD_PROCESS_SHARED, 0);
		PFSD_ASSERT (r == 0);
	}

	return req;
}

int
pfsd_shm_put_request(pfsd_iochannel_t *ch, pfsd_request_t *req)
{
	if (ch == NULL || req == NULL)
		return -1;

	PFSD_ASSERT(ch->ch_magic == PFSD_SHM_MAGIC);

	int index = req - ch->ch_requests;
	pid_t pid = getpid();

	if ((ch->ch_free_bitmap & (0x1UL << index)) != 0) {
		PFSD_CLIENT_ELOG("req(%d) channel bitmap(0x%lx) invalid. Maybe "
		    "this is a child process request but it is already umounted "
		    "in the master process. Current process will exit and please "
		    "review whether umount was happend before.", index,
		    ch->ch_free_bitmap);
		exit(-1);
	}

	PFSD_ASSERT(req->owner == pid);

	/*
	 * If pg crash at here, req hasn't be put to free bitmap,
	 * It can't be reused. But main process will recycle it eventually.
	 */
	(void)__sync_or_and_fetch(&ch->ch_free_bitmap, (0x1UL << index));

	int64_t old_val = req->val;
	int64_t new_val = pfsd_request_set_state(old_val, REQ_FREE);
	if (!__sync_bool_compare_and_swap(&req->val, old_val, new_val)) {
		PFSD_CLIENT_ELOG("old val %lx, now val %lx, put request failed, "
		    "may be some bugs", old_val, req->val);
		PFSD_ASSERT(!"put request failed");
	}

	return 0;
}

/* req must be returned by pfsd_shm_get_request */
void
pfsd_shm_send_request(pfsd_iochannel_t *ch, pfsd_request_t *req)
{
	PFSD_ASSERT(ch->ch_magic == PFSD_SHM_MAGIC);

	int index = req - ch->ch_requests;
	PFSD_ASSERT(index >= 0 && index < ch->ch_max_req);
	PFSD_ASSERT(req->owner == getpid());

	int64_t old_val = req->val;
	int64_t new_val = pfsd_request_set_state(old_val, REQ_WAIT_REPLY);
	if (!__sync_bool_compare_and_swap(&req->val, old_val, new_val)) {
		PFSD_CLIENT_ELOG("old val %lx, now val %lx, send request failed, "
		    "may be some bugs", old_val, req->val);
		PFSD_ASSERT(!"send request failed");
	}
}
#endif // PFSD_CLIENT

#ifdef PFSD_SERVER
pfsd_request_t *
pfsd_shm_fetch_request(pfsd_iochannel_t *ch)
{
	PFSD_ASSERT(ch->ch_magic == PFSD_SHM_MAGIC);

	pfsd_request_t *req = NULL;

	/* Check if has requests without lock */
	uint64_t used_bitmap = ~(ch->ch_free_bitmap);
	if (used_bitmap == 0)
		return NULL;

	pfsd_shm_t *shm = pfsd_channel_shm(ch);
	int sh_index = shm->sh_index;
	PFSD_MUTEX_LOCK_EX(g_chnl_mutex[sh_index][ch->ch_index], NULL);
	used_bitmap = ~(ch->ch_free_bitmap);
	while (used_bitmap != 0) {
		int index = ffsl(long(used_bitmap));
		assert(index > 0);
		index--; /* ffsl return 1-based */

		if (index >= ch->ch_max_req)
			break;

		pfsd_request_t *r = &ch->ch_requests[index];
		/*
		 * If client dead, and pfsd handling request, set IN_PROGRESS
		 * state, then restart. pfsd needs to continue process the
		 * IN_PROGRESS request, return ESTALE, set to WAIT_RELEASE.
		 * it will be recycled by main thread.
		 */
		int64_t old_val;
	retry:
		old_val = __atomic_load_n(&r->val, __ATOMIC_ACQUIRE);
		if (r->state == REQ_IN_PROGRESS || r->state == REQ_WAIT_REPLY) {
			/* if pfsd restart */
			if (r->shm_epoch < ch->ch_epoch) {
				/* avoid some other worker fetch me */
				r->shm_epoch = ch->ch_epoch + 1;

				bool cas;
				int64_t new_val = pfsd_request_set_state(old_val,
				    REQ_IN_PROGRESS);
				cas = __sync_bool_compare_and_swap(&r->val,
				    old_val, new_val);
				if (!cas)
					goto retry;
				req = r;
				break;
			}

			if (r->state == REQ_WAIT_REPLY &&
			    r->shm_epoch == ch->ch_epoch) {
				bool cas;
				int64_t new_val = pfsd_request_set_state(old_val,
				    REQ_IN_PROGRESS);
				cas = __sync_bool_compare_and_swap(&r->val,
				    old_val, new_val);
				if (!cas)
					goto retry;
				req = r;
				break;
			}
		}

		/* iterate next index */
		uint64_t mask = 0x1UL << index;
		used_bitmap &= ~mask;
	}
	PFSD_MUTEX_UNLOCK(g_chnl_mutex[sh_index][ch->ch_index]);
	/*
	 * if pfsd crashed here, when restart, increase epoch, sdk will recycle
	 * old request. But what if pfsd and sdk both dead? pfsd should reset
	 * each channel's bitmap and incr epoch under mutex protect?
	 */
	return req;
}

/* worker thread done request, response is ready. */
void
pfsd_shm_done_request(pfsd_iochannel_t *ch, int req_index)
{
	PFSD_ASSERT(ch->ch_magic == PFSD_SHM_MAGIC);
	PFSD_ASSERT(req_index >= 0 && req_index < ch->ch_max_req);

	/*
	 * If pfsd crashed here, when restart, it'll upgrade epoch, and process
	 * request return ESTALE. When clients see ESTALE, they'll retry or
	 * abort request.
	 */
	pfsd_request_t *req = &ch->ch_requests[req_index];
	int64_t old_val = req->val;
	int64_t new_val = old_val;
	old_val = pfsd_request_set_state(old_val, REQ_IN_PROGRESS);
	new_val = pfsd_request_set_state(new_val, REQ_WAIT_RELEASE);
	if (!__sync_bool_compare_and_swap(&req->val, old_val, new_val)) {
		pfsd_fatal("req_i %d, %p, wrong state %s", req_index, req,
		    pfsd_req_state_string(req->state));
		PFSD_ASSERT(0);
	}
	/* 
	 * If pfsd crashed here, client must check request state and wait sem
	 * simutaneously. So client must use sem_timedwait and check state
	 * repeatedly.
	 */
	sem_post(&ch->ch_responses[req_index].r_sem);
}

void
pfsd_shm_recycle_request(pfsd_iochannel_t *ch)
{
	if (ch->ch_magic != PFSD_SHM_MAGIC) {
		pfsd_error("wrong magic %u for ch %p", ch->ch_magic, ch);
		PFSD_ASSERT(0);
	}

	const int limit = 16;
	int recycled = 0;

	pfsd_shm_t *shm = pfsd_channel_shm(ch);
	int sh_index = shm->sh_index;
	PFSD_MUTEX_LOCK(g_chnl_mutex[sh_index][ch->ch_index]);

	uint64_t used_bitmap = uint64_t(-1);
	while (used_bitmap != 0) {
		if (recycled >= limit)
			break;

		int index = ffsl(long(used_bitmap));
		assert(index > 0);
		index--; /* ffsl return 1-based */

		if (index >= ch->ch_max_req)
			break;
	retry:
		pfsd_request_t *req = &ch->ch_requests[index];
		int64_t old_val = __atomic_load_n(&req->val, __ATOMIC_ACQUIRE);
		int state = req->state;
		int connid = req->connid;
		if ((state == REQ_WAIT_RELEASE || state == REQ_ALLOC)
		    && (!pfsd_request_alive(req)
		    || pfsd_is_conn_closed(connid))) {
			/* check if inflight */
			bool cas;
			pid_t owner = req->owner;
			int64_t new_val = 0;
			(void)__sync_or_and_fetch(&ch->ch_free_bitmap,
			    (0x1UL << index));
			new_val = pfsd_request_set_pid(new_val, PFSD_INVALID_PID);
			new_val = pfsd_request_set_connid(new_val, -1);
			new_val = pfsd_request_set_state(new_val, REQ_FREE);
			cas = __sync_bool_compare_and_swap(&req->val, old_val, new_val);
			if (cas) {
				++recycled;
				pfsd_info("request conn %d owner %d dead",
				    connid, owner);
			} else
				goto retry;
			//Here we do not investigate other states. Do not print
			//logs to avoid large number of repeated logs.
		}

		/* iterate next index */
		uint64_t mask = 0x1UL << index;
		used_bitmap &= ~mask;
	}

	PFSD_MUTEX_UNLOCK(g_chnl_mutex[sh_index][ch->ch_index]);
}
#endif // PFSD_SERVER

int
pfsd_shm_cli_abort_request(pfsd_shm_t *shm, int conn_id, pid_t pid)
{
	return pfsd_shm_abort_request(shm, conn_id, pid, false, false);
}

int
pfsd_shm_svr_abort_request(pfsd_shm_t *shm, int conn_id, bool forced)
{
	return pfsd_shm_abort_request(shm, conn_id, PFSD_INVALID_PID, forced, true);
}

int
pfsd_shm_abort_request(pfsd_shm_t *shm, int conn_id, pid_t pid, bool forced, bool is_svr)
{
	PFSD_ASSERT (shm->sh_magic == PFSD_SHM_MAGIC);

	int total_aborts = 0;
	char *channels = (char *)(shm + 1);
	int nreq = ((pfsd_iochannel_t *)channels)->ch_max_req;
	for (int i = 0; i < shm->sh_nch; ++i) {
		pfsd_iochannel_t *ch = (pfsd_iochannel_t *)(channels + i*pfsd_channel_size(nreq, shm->sh_unitsize));
		PFSD_ASSERT (ch->ch_magic == PFSD_SHM_MAGIC);

		for (;;) {
			int waiting_req = 0;

			if (is_svr) {
				PFSD_MUTEX_LOCK_EX(
				    g_chnl_mutex[shm->sh_index][ch->ch_index],
				    total_aborts);
			}

			uint64_t used_bitmap = uint64_t(-1);
			while (used_bitmap != 0) {
				int index = ffsl(long(used_bitmap));
				assert(index > 0);
				index--; /* ffsl return 1-based */

				if (index >= ch->ch_max_req)
					break;
			retry:
				pfsd_request_t *r = &ch->ch_requests[index];
				int64_t old_val = __atomic_load_n(&r->val,
				    __ATOMIC_ACQUIRE);
				bool pid_matched = (pid == PFSD_INVALID_PID || pid == r->owner);
				int state = r->state;
				if (pid_matched && r->connid == conn_id) {
					if (forced || state == REQ_ALLOC ||
					    state == REQ_WAIT_RELEASE) {
						pid_t owner = r->owner;

						(void)__sync_or_and_fetch(
						    &ch->ch_free_bitmap,
						    (0x1UL << index));
						bool cas;
						int64_t new_val = 0;
						new_val = pfsd_request_set_pid(
						    new_val, PFSD_INVALID_PID);
						new_val = pfsd_request_set_connid(
						    new_val, -1);
						new_val = pfsd_request_set_state(
						    new_val, REQ_FREE);
						cas = __sync_bool_compare_and_swap(
						    &r->val, old_val, new_val);
						if (cas) {
#ifdef PFSD_SERVER
							pfsd_info(
							    "connid %d recycle %d's request at (%d,%d)",
							    conn_id, owner,
							    ch->ch_index, index);
#else
							PFSD_CLIENT_LOG(
							    "connid %d recycle %d's request at (%d,%d)",
							    conn_id, owner,
							    ch->ch_index, index);
#endif
							total_aborts++;
						} else
							goto retry;
					} else if (state != REQ_FREE) {
						waiting_req++;
					}
				}

				/* iterate next index */
				uint64_t mask = 0x1UL << index;
				used_bitmap &= ~mask;
			}

			if (is_svr)
				PFSD_MUTEX_UNLOCK(g_chnl_mutex[shm->sh_index][ch->ch_index]);

			if (waiting_req == 0) {
				break;
			}

#ifdef PFSD_SERVER
			pfsd_info("inflight io %d", waiting_req);
#else
			PFSD_CLIENT_LOG("inflight io %d", waiting_req);
#endif
			usleep(100);
		}
	}

	return total_aborts;
}

#ifdef PFSD_CLIENT

#define SEC2NANOSEC  (1000 * 1000 * 1000)

static int64_t io_wait_deadline = (1); /* wait IO for at most 1 s */

void
pfsd_wait_io(pfsd_request_t *req, sem_t *sem)
{
	long loop = 0;
	while (__sync_add_and_fetch(&req->state, 0) != REQ_WAIT_RELEASE) {
		loop++;

		struct timespec abstv;
		clock_gettime(CLOCK_REALTIME, &abstv);
		abstv.tv_sec += io_wait_deadline;

		errno = 0;
		/*
		 * Wait 1s is just fine, because sem_t is nothing else but just
		 * for control cpu usage in sdk.
		 */
		int e = sem_timedwait(sem, &abstv);
		if (e == 0) {
			/* 
			 * Can't judge state. If pfsd change state to 
			 * REQ_WAIT_RELEASE, but before sem_post, and sdk got
			 * TIMEOUT from sem_timedwait, enter next loop,
			 * see REQ_WAIT_RELEASE and exit, then process response
			 * and free this request. Another thread pick this
			 * request, when before it wait io, pfsd call sem_post
			 * on 'previous' request. But the req state is
			 * undetermined. However, sdk shouldn't judge state when
			 * return from sem_timedwait, it just loop again to
			 * check state.
			 */
			if (req->state != REQ_WAIT_RELEASE) {
				/* Rarely happen, just log it for analyse */
				PFSD_CLIENT_LOG(
				    "Return from sem_timedwait: "
				    "owner %d type %s state %s connid %d "
				    "epoch %u",
				    req->owner,
				    pfsd_req_type_string(req->type),
				    pfsd_req_state_string(req->state),
				    (int)req->connid,
				    req->shm_epoch);
			}
		} else if (errno != ETIMEDOUT && errno != EINTR) {
			PFSD_CLIENT_ELOG(
			    "pid %d got error [%s] when wait for req type %d",
			    getpid(), strerror(errno), req->type);
		}
	}

	pid_t owner = req->owner;
	if (owner != getpid()) {
		PFSD_CLIENT_ELOG("current pid %d NOT match request owner %d",
		    getpid(), owner);
		PFSD_ASSERT(req->owner == getpid());
	}
}

int
pfsd_sdk_alloc_request(int32_t connid, size_t iosize, pfsd_shm_t *shm[],
    int nshm, pfsd_iochannel_t **och, pfsd_request_t **oreq)
{
	assert (och && oreq);
	*och = NULL;
	*oreq = NULL;

	if (iosize > PFSD_MAX_IOSIZE) {
		PFSD_CLIENT_ELOG("pfsd_sdk_get_request too big iosize %ld",
		    iosize);
		errno = EFBIG;
		return -1;
	}

	pfsd_iochannel_t *ch = NULL;
	pfsd_request_t *req = NULL;
	int si = 0;

get_req:
	for (si = 0; req == NULL && si < nshm; ++si) {
		if (shm[si]->sh_unitsize < iosize)
			continue;

		char* const channels = (char*)(shm[si] + 1);
		size_t const unit_size = g_shm_unit_size[si];
		assert (unit_size > 0);
		int nreq = ((pfsd_iochannel_t*)channels)->ch_max_req;
		/* rand select a channel */
		int chidx = rand() % shm[si]->sh_nch;
		for (int tried = 0; tried < shm[si]->sh_nch; ++tried) {
			ch = (pfsd_iochannel_t *)(channels + chidx * pfsd_channel_size(nreq, unit_size));
			req = pfsd_shm_get_request(ch, connid);
			if (req != NULL)
				break;

			/* try next channel */
			chidx = (chidx + 1) % shm[si]->sh_nch;
		}
	}

	if (req == NULL) {
		usleep(10);
		goto get_req;
	}

	*och = ch;
	*oreq = req;

	return 0;
}

#endif // PFSD_CLIENT

