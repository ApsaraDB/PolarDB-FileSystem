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

#include <sys/time.h>

#include "pfs_stat.h"
#include "pfs_mount.h"
#include "pfs_impl.h"
#include "pfs_admin.h"
#include "pfs_tls.h"
#include "pfs_option.h"
#include "pfs_config.h"

static int64_t		mountstat_enable = PFS_OPT_ENABLE;
PFS_OPTION_REG(mountstat_enable, pfs_check_ival_switch);

#define MNT_STAT_SIZE (8 << 10)

// Highest 44 bits represent the total time cost(us) and the reset 20 bits
// represent the total count.
typedef uint64_t pfs_mntstat_t;

#define COUNT_SHIFT (20ull)

static pfs_mntstat_t mount_stat[MNT_STAT_SIZE][MNT_STAT_TYPE_COUNT];

static pfs_mntstat_t mount_file_type_stat
    [MNT_STAT_SIZE][MNT_STAT_FILE_SPEC_TYPE_COUNT][FILE_TYPE_COUNT];

#define IO_TYPE 7
static uint32_t mount_file_type_stat_iosize
    [MNT_STAT_SIZE][IO_TYPE][FILE_TYPE_COUNT];

static uint32_t mount_threads_stat[MNT_STAT_SIZE][MNT_STAT_TH_TYPE_COUNT];

static int mountstat_nthreads = 0;

typedef struct {
	int cl_api_type;
	int cl_file_type;
	//Todo: enable set cl_stat > 1 for repeatedly trapping.
	int cl_stat;
} color_args_t;

enum {
	COLOR_SETTING	= -1,
	COLOR_INITED 	= 0,
	COLOR_SET   	= 1,
};

static color_args_t color_slots[FILE_COLOR_TYPE_NCOUNT];

static const char* mountstat_name[MNT_STAT_TYPE_COUNT] = {
    "open",
    "creat",
    "read+pread",
    "write+pwrite",
    "lseek",
    "stat",
    "truncate",
    "fallocate",
    "unlink",
    "du",
    "rename",
    "rmdir",
    "opendir",
    "readdir",
    "mount_sync",
    "inode_reload",
    "inode_cond_wait",
    "journal_poll",
    "journal_replay",
    "journal_trim",
    "journal_write",
    "inode_get",
    "inode_put",
    "dev_sleep",
    "dev_nobuf",
    "dev_throttle",
    "dev_read",
    "dev_write",
    "dev_trim",
    "meta_rdlock",
    "meta_wrlock",
};

static const char* mountstat_api_name[MNT_STAT_FILE_SPEC_TYPE_COUNT] = {
    "dev_read",
    "dev_write",
    "read",
    "write",
    "pread",
    "pwrite",

    "tx_write",

    "open",
    "open_creat",
    "lseek",
    "fstat",
    "ftruncate",
    "fallocate",
    "unlink",
    "stat",
    "truncate",
    "creat",
    "fsync",
    "fdatasync",
    "inode_cond_wait",
};

static const char* mountstat_threads_name[MNT_STAT_TH_TYPE_COUNT] = {
    "pfs_threads",
    "pfs_act_threads",
};

static int
pfs_get_api_type_index(char* api_type, int api_type_len)
{
	int api_type_index = -1;
	int i;
	if (strlen(api_type) == 0)
		return api_type_index;
	for (i = 0; i < FILE_TYPE_COUNT; ++i) {
		if (strncmp(api_type, mountstat_api_name[i], api_type_len)
		    == 0) {
			api_type_index = i;
			break;
		}
	}
	return api_type_index;
}

void
pfs_mntstat_init()
{
	//Do nothing to support multi-mount.
}

static bool
pfs_mntstat_enable()
{
	return (mountstat_enable == PFS_OPT_ENABLE);
}

void
pfs_mntstat_prepare(struct timeval* stat_begin, int api_type)
{
	uint32_t store_pos, ver;
	if (!pfs_mntstat_enable()) {
		stat_begin->tv_sec = 0;
		return;
	}
	gettimeofday(stat_begin, NULL);
	store_pos = (uint32_t)(stat_begin->tv_sec % MNT_STAT_SIZE);
	ver = pfs_tls_get_stat_ver();
	if (ver != store_pos) {
		pfs_tls_set_stat_ver(store_pos);
		__atomic_fetch_add(
		    &mount_threads_stat[store_pos][MNT_STAT_TH_ACTIVE], 1,
		    __ATOMIC_RELAXED);
	}
	pfs_tls_set_stat_api_type(api_type);
}

void
pfs_mntstat_set_file_type(int file_type)
{
	int api_type, i, color_set = COLOR_SET;
	if (pfs_tls_get_stat_file_type() == FILE_PFS_INITED) {
		api_type = pfs_tls_get_stat_api_type();
		for (i = 0; i < FILE_COLOR_TYPE_NCOUNT; ++i) {
			if (color_slots[i].cl_stat == COLOR_SET &&
			    color_slots[i].cl_api_type == api_type &&
			    color_slots[i].cl_file_type == file_type &&
			    __atomic_compare_exchange_n(&color_slots[i].cl_stat,
			    &color_set, COLOR_INITED, false,
			    __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)) {
				file_type = FILE_COLOR_0 + i;
				goto out;
			}
			color_set = COLOR_SET;
		}
	}
out:
	pfs_tls_set_stat_file_type(file_type);
}

static inline void
pfs_stat_add(int64_t stat_time, int stat_type, uint64_t stat_latency)
{
	__atomic_fetch_add(&mount_stat[stat_time % MNT_STAT_SIZE][stat_type],
	    (stat_latency << COUNT_SHIFT) | 1ull, __ATOMIC_RELAXED);
}

static inline void
pfs_file_type_stat_add(int64_t stat_time, int stat_type, int file_type,
    uint64_t stat_latency)
{
	__atomic_fetch_add(
	    &mount_file_type_stat
	    [stat_time % MNT_STAT_SIZE][stat_type][file_type],
	    (stat_latency << COUNT_SHIFT) | 1ull, __ATOMIC_RELAXED);
}

static inline void
pfs_file_type_stat_add_iosize(int64_t stat_time, int io_type, int file_type,
    uint32_t io_size)
{
	__atomic_fetch_add(
	    &mount_file_type_stat_iosize
	    [stat_time % MNT_STAT_SIZE][io_type][file_type], io_size,
	    __ATOMIC_RELAXED);
}

static void
pfs_mntstat_threads_get(int64_t stat_time, int stat_type, uint32_t* value)
{
	*value = mount_threads_stat[stat_time % MNT_STAT_SIZE][stat_type];
}

static void
pfs_stat_get(int64_t stat_time, int stat_type, uint64_t *count,
    double *latency_avg)
{
	pfs_mntstat_t st;
	st = mount_stat[stat_time % MNT_STAT_SIZE][stat_type];
	*count = st & ((1 << COUNT_SHIFT) - 1);
	if (*count == 0)
		*latency_avg = 0.0;
	else
		*latency_avg = (st >> COUNT_SHIFT) / double(*count);
}

static void
pfs_file_type_stat_get(int64_t stat_time, int stat_type, int file_type,
    uint64_t *count, double *latency_avg)
{
	pfs_mntstat_t st =
	    mount_file_type_stat[stat_time % MNT_STAT_SIZE][stat_type][file_type];
	*count = st & ((1 << COUNT_SHIFT) - 1);
	if (*count == 0)
		*latency_avg = 0.0;
	else
		*latency_avg = (st >> COUNT_SHIFT) / double(*count);
}

static void
pfs_file_type_stat_get_iosize(int64_t stat_time, int stat_type, int file_type,
    uint64_t count, double *iosize)
{
	int io_type;
	if (count == 0 || stat_type >= IO_TYPE) {
		*iosize = 0.0;
		return;
	}

	io_type = stat_type;
	*iosize = mount_file_type_stat_iosize[stat_time % MNT_STAT_SIZE]
	    [io_type][file_type]/double(count);
}

void
pfs_mntstat_nthreads_change(int delta)
{
	__atomic_fetch_add(&mountstat_nthreads, delta, __ATOMIC_RELAXED);
}

void
pfs_mntstat_sync(struct timeval* stat_time)
{
	if (pfs_mntstat_enable())
		__atomic_store_n(
		    &mount_threads_stat
		    [stat_time->tv_sec % MNT_STAT_SIZE][MNT_STAT_TH_NCOUNT],
		    (uint32_t)mountstat_nthreads, __ATOMIC_RELAXED);
}

void
pfs_mntstat_reinit(struct timeval* stat_begin)
{
	// This may lead some invalid result when we enable->disable->enable.
	//if (!pfs_mntstat_enable())
	//	return;

	//0 : current, 1 : safety_guard
	memset(mount_stat[(stat_begin->tv_sec + 2) % MNT_STAT_SIZE], 0,
	    sizeof(*mount_stat));
	memset(mount_stat[(stat_begin->tv_sec + 3) % MNT_STAT_SIZE], 0,
	    sizeof(*mount_stat));
	memset(mount_file_type_stat[(stat_begin->tv_sec + 2) % MNT_STAT_SIZE],
	    0, sizeof(*mount_file_type_stat));
	memset(mount_file_type_stat[(stat_begin->tv_sec + 3) % MNT_STAT_SIZE],
	    0, sizeof(*mount_file_type_stat));
	memset(mount_file_type_stat_iosize
	    [(stat_begin->tv_sec + 2) % MNT_STAT_SIZE], 0,
	    sizeof(*mount_file_type_stat_iosize));
	memset(mount_file_type_stat_iosize
	    [(stat_begin->tv_sec + 3) % MNT_STAT_SIZE], 0,
	    sizeof(*mount_file_type_stat_iosize));
	memset(&mount_threads_stat[(stat_begin->tv_sec + 2) % MNT_STAT_SIZE],
	    0, sizeof(*mount_threads_stat));
	memset(&mount_threads_stat[(stat_begin->tv_sec + 3) % MNT_STAT_SIZE],
	    0, sizeof(*mount_threads_stat));
}

void
pfs_mntstat_store(struct timeval* stat_begin, struct timeval* stat_end,
    int stat_type, bool file_type_spec, uint32_t io_size)
{
	struct timeval stat_end_data;
	uint64_t stat_latency;
	int file_type, io_type;

	if (!pfs_mntstat_enable() || stat_begin->tv_sec == 0)
		return;

	if (!stat_end) {
		stat_end = &stat_end_data;
		gettimeofday(stat_end, NULL);
	}
	stat_latency = (stat_end->tv_sec - stat_begin->tv_sec) * 1000000 +
	    stat_end->tv_usec - stat_begin->tv_usec;
	if (!file_type_spec) {
		pfs_stat_add(stat_end->tv_sec, stat_type, stat_latency);
		if (stat_type == MNT_STAT_DEV_READ) {
			stat_type = MNT_STAT_BACK_READ;
			file_type_spec = true;
		} else if (stat_type == MNT_STAT_DEV_WRITE) {
			stat_type = MNT_STAT_BACK_WRITE;
			file_type_spec = true;
		}else if (stat_type == MNT_STAT_SYNC_INODE_WAIT) {
			stat_type = MNT_STAT_INODE_WAIT;
			file_type_spec = true;
		}
	}
	if (file_type_spec) {
		file_type = pfs_tls_get_stat_file_type();
		if (FILE_PFS_INITED == file_type)
			return;
		PFS_VERIFY(file_type < FILE_TYPE_COUNT);
		PFS_VERIFY(stat_type < MNT_STAT_FILE_SPEC_TYPE_COUNT);
		pfs_file_type_stat_add(stat_end->tv_sec, stat_type,
		    file_type, stat_latency);
		if (io_size != 0) {
			PFS_ASSERT(stat_type < IO_TYPE);
			io_type = stat_type;
			pfs_file_type_stat_add_iosize(stat_end->tv_sec,
			    io_type, file_type, io_size);
		}
	}
}

int
pfs_mntstat_snap(admin_buf_t *ab, int64_t begin_time, int64_t time_range,
    char* file_type_pattern, int file_type_pattern_len)
{
	struct timeval now;
	int i, j, err = 0;
	uint64_t count;
	double latency_avg;
	struct tm tm;
	uint32_t nthreads;
	int64_t  now_time;
	bool first = true;
	char time_buf[128];
	double io_size;
	bool file_type_filter[FILE_TYPE_COUNT] = {false};
	int file_type_index = pfs_get_file_type_index_pat(file_type_pattern,
	    file_type_pattern_len, file_type_filter);

	static const char mon_name[][4] = {
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	err = gettimeofday(&now, NULL);
	PFS_VERIFY(err == 0);
	now.tv_sec -= 2;
	now_time = now.tv_sec;
	if (begin_time == 0)
		begin_time = now_time;
	else if (now_time - begin_time >= MNT_STAT_SIZE - 4)
		begin_time = now_time - (MNT_STAT_SIZE - 4);

	if (time_range == 0)
		time_range = MNT_STAT_SIZE;

	while (begin_time <= now_time) {
		if (time_range < 0)
			break;
		localtime_r(&begin_time, &tm);
		snprintf(time_buf, sizeof(time_buf), "%.3s%3d %.2d:%.2d:%.2d",
		    mon_name[tm.tm_mon], tm.tm_mday, tm.tm_hour, tm.tm_min,
		    tm.tm_sec);

		for(j = 0; j < FILE_TYPE_COUNT; ++j) {
			if (file_type_index >= 0 && !file_type_filter[j])
				continue;
			for (i = 0; i < MNT_STAT_FILE_SPEC_TYPE_COUNT; ++i) {
				pfs_file_type_stat_get(begin_time, i, j,
				    &count, &latency_avg);
				if (count == 0)
					continue;
				pfs_file_type_stat_get_iosize(begin_time, i,
				    j, count, &io_size);
				if (first) {
					pfs_adminbuf_printf(ab,
					    "\nFile_type: %s\n"
					    "Date            "
					    "File_type       "
					    "Operation       "
					    "Ops        "
					    "Latency(us) "
					    "Io_size(bytes) \n",
					    pfs_get_file_type_name(j)
					);
					first = false;
				}
				pfs_adminbuf_printf(ab,
				    "%s %-15s %-15s %-10ld %-11.2f %-11.2f\n",
				    time_buf, pfs_get_file_type_name(j),
				    mountstat_api_name[i], count, latency_avg,
				    io_size);
			}
			first = true;
		}
		first = true;
		for (i = 0; i < MNT_STAT_TYPE_COUNT && file_type_index < 0;
		    ++i) {
			pfs_stat_get(begin_time, i, &count, &latency_avg);
			if (count == 0)
				continue;
			if (first) {
				pfs_adminbuf_printf(ab,
				    "\nSummarize\n"
				    "Date            "
				    "File_type       "
				    "Operation       "
				    "Ops        "
				    "Latency(us) "
				    "Io_size(bytes) \n"
				);
				first = false;
			}
			pfs_adminbuf_printf(ab,
			    "%s %-15s %-15s %-10ld %-11.2f N/A\n",
			    time_buf, "all", mountstat_name[i], count,
			    latency_avg);
		}
		if (!first) {
			//We only show threads count when mount_stat enabled.
			for(i = 0; i < MNT_STAT_TH_TYPE_COUNT; ++i) {
				pfs_mntstat_threads_get(begin_time, i, &nthreads);
				pfs_adminbuf_printf(ab,
				    "%s %-15s %-15s %-10u N/A         N/A\n",
				    time_buf, "all", mountstat_threads_name[i],
				    nthreads);
			}
		}
		first = true;
		++begin_time;
		--time_range;
	}
	return err;
}

int
pfs_mntstat_sample(char* sample_pattern, int sample_pattern_len)
{
	if (!pfs_mntstat_enable())
		ERR_RETVAL(EBUSY);
	char* sep = strchr(sample_pattern, ':');
	int color_inited = COLOR_INITED, i = 0, file_type, api_type;
	if (sep == NULL || sep > sample_pattern + sample_pattern_len ||
	    sep <= sample_pattern ||
	    sep + 1 >= sample_pattern + sample_pattern_len)
		ERR_RETVAL(EINVAL);
	*sep = '\0';

	file_type = pfs_get_file_type_index(sample_pattern,
	    sep - sample_pattern);
	if (file_type < 0)
		ERR_RETVAL(EINVAL);
	api_type = pfs_get_api_type_index(sep + 1,
	    sample_pattern + sample_pattern_len - (sep + 1));
	if (api_type < 0)
		ERR_RETVAL(EINVAL);
	do {
		i = 0;
		for (; i < FILE_COLOR_TYPE_NCOUNT; ++i) {
			if (color_slots[i].cl_stat == COLOR_INITED &&
			    __atomic_compare_exchange_n(&color_slots[i].cl_stat,
			    &color_inited, COLOR_SETTING, false,
			    __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)) {
				color_slots[i].cl_api_type = api_type;
				color_slots[i].cl_file_type = file_type;
				__atomic_store_n(&color_slots[i].cl_stat,
				    COLOR_SET, __ATOMIC_RELEASE);
				break;
			}
			color_inited = COLOR_INITED;
		}
		if (FILE_COLOR_TYPE_NCOUNT == i)
			sleep(1);
	} while (FILE_COLOR_TYPE_NCOUNT == i);
	return 0;
}

void
pfs_mntstat_clear()
{
	pfs_tls_set_stat_file_type(FILE_PFS_INITED);
	pfs_tls_set_stat_api_type(MNT_STAT_API_NONE);
}
