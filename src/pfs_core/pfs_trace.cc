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

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "pfs_admin.h"
#include "pfs_impl.h"
#include "pfs_trace.h"

//static int tracelvl_threshold = PFS_TRACE_ERROR;

#define	PFS_TRACE_LEN	1024
#define	PFS_TRACE_NUM	16384	/* must be power of 2 */
typedef struct pfs_tracebuf {
	char		tb_trace[PFS_TRACE_LEN];
} pfs_tracebuf_t;
static pfs_tracebuf_t	pfs_trace_buf[PFS_TRACE_NUM];
static uint64_t		pfs_trace_idx = 0;

char			pfs_trace_pbdname[PFS_MAX_PBDLEN];

bool
pfs_check_ival_trace_level(void *data)
{
	int64_t integer_val = *(int64_t*)data;
	if ((integer_val != PFS_TRACE_OFF) &&
	    (integer_val != PFS_TRACE_ERROR) &&
	    (integer_val != PFS_TRACE_WARN) &&
	    (integer_val != PFS_TRACE_INFO) &&
	    (integer_val != PFS_TRACE_DBG) &&
	    (integer_val != PFS_TRACE_VERB))
		return false;
	return true;
}

/* print level of trace */
int64_t trace_plevel = PFS_TRACE_INFO;
PFS_OPTION_REG(trace_plevel, pfs_check_ival_trace_level);

/*
 * Create a dummy tracectl to INIT trace sector.
 * Otherwise, if pfs_verbtrace() isn't called, trace sector may be not created
 * when compiling.
 */
static tracectl_t dummy_tracectl = {
	__FILE__, "dummy", __LINE__,
	PFS_TRACE_DBG,
	false,
	"dummy\n",
};
static tracectl_t *dummy_tracectl_ptr DATA_SET_ATTR(_tracectl) = &dummy_tracectl;

static inline const char *
pfs_trace_levelname(int level)
{
	switch (level) {
	case PFS_TRACE_ERROR:	return "ERR";
	case PFS_TRACE_WARN:	return "WRN";
	case PFS_TRACE_INFO:	return "INF";
	case PFS_TRACE_DBG:	return "DBG";
	default:		return "UNKNOWN";
	}
	return NULL;	/* unreachable */
}

/*
 * pfs_trace_redirect
 *
 * 	Redirect trace to log file. Before the redirection, log is
 * 	is printed on stderr tty. After redirection, stderr points
 * 	to the log file.
 */
void
pfs_trace_redirect(const char *pbdname, int hostid)
{
	int fd, nprint;
	char logfile[128];

	nprint = snprintf(logfile, sizeof(logfile), "/var/log/pfs-%s.log",
	    pbdname);
	if (nprint >= (int)sizeof(logfile)) {
		fprintf(stderr, "log file name too long, truncated as %s\n",
		    logfile);
		return;
	}

	/*
	 * Open the log file, redirect stderr to the log file,
	 * and finally close the log file fd. stderr now is the
	 * only user of the log file.
	 */
	fd = open(logfile, O_CREAT | O_WRONLY | O_APPEND, 0666);
	if (fd < 0) {
		fprintf(stderr, "cant open file %s\n", logfile);
		return;
	}
	if (dup2(fd, 2) < 0) {
		fprintf(stderr, "cant dup fd %d to stderr\n", fd);
		close(fd);
		fd = -1;
		return;
	}
	chmod(logfile, 0666);
	close(fd);

	pfs_itrace("host %d redirect trace to %s\n", hostid, logfile);
}

pfs_log_func_t *pfs_log_functor;

void
pfs_vtrace(int level, const char *fmt, ...)
{
	static const char mon_name[][4] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};

	struct timeval tv;
	struct tm tm;
	uint64_t ti;
	int len;
	char *buf;
	int errno_save = errno;
	va_list ap;

	ti = __atomic_fetch_add(&pfs_trace_idx, 1, __ATOMIC_ACQ_REL);
	ti = (ti & (PFS_TRACE_NUM - 1));
	buf = pfs_trace_buf[ti].tb_trace;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	len = snprintf(buf, PFS_TRACE_LEN, "[PFS_LOG] "
	    "%.3s%3d %.2d:%.2d:%.2d.%06ld %s [%ld] ",
	    mon_name[tm.tm_mon], tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec,
	    pfs_trace_levelname(level),
	    (long)syscall(SYS_gettid));
	if (len < PFS_TRACE_LEN) {
		va_start(ap, fmt);
		vsnprintf(buf + len, PFS_TRACE_LEN - len, fmt, ap);
		va_end(ap);
	}

	if (pfs_log_functor != NULL)
		pfs_log_functor(buf);
	else
		fputs(buf, stderr);

	errno = errno_save;
}

static bool
pfs_trace_match(tracectl_t *tc, const char *file, int line)
{
	/*
	 * File is not wildcard and doesn't match.
	 */
	if (strcmp(file, "*") != 0 && strcmp(file, tc->tc_file) != 0)
		return false;

	/*
	 * Line is not wildcard and doesn't match.
	 */
	if (line && line != tc->tc_line)
		return false;

	return true;
}

int
pfs_trace_list(const char *file, int line, admin_buf_t *ab)
{
	DATA_SET_DECL(tracectl, _tracectl);
	tracectl_t **tcp, *tc;
	int n;

	/*
	 * Walk through the tracectl set to show the trace point
	 * with corresponding line & file
	 */
	n = pfs_adminbuf_printf(ab, "function\t\tfile\t\tline\t\tlevel\n");
	if (n < 0)
		return n;

	DATA_SET_FOREACH(tcp, _tracectl) {
		tc = *tcp;
		if (!pfs_trace_match(tc, file, line))
			 continue;

		n = pfs_adminbuf_printf(ab,
		    "%-26s\t%-20s\t%-6d\t%-3d\t%c\t%s",
		    tc->tc_func, tc->tc_file, tc->tc_line, tc->tc_level,
		    tc->tc_enable ? 'y' : '-',
		    tc->tc_format);
		if (n < 0)
			return n;
	}
	return 0;
}

int
pfs_trace_set(const char *file, int line, bool enable, admin_buf_t *ab)
{
	DATA_SET_DECL(tracectl, _tracectl);
	tracectl_t **tcp, *tc;
	int n;

	DATA_SET_FOREACH(tcp, _tracectl) {
		tc = *tcp;
		if (!pfs_trace_match(tc, file, line))
			 continue;

		tc->tc_enable = enable;
	}

	n = pfs_adminbuf_printf(ab, "succeeded\n");
	return n < 0 ? n : 0;
}

int
pfs_trace_handle(int sock, msg_header_t *mh, msg_trace_t *tr)
{
	int err;
	admin_buf_t *ab;

	ab = pfs_adminbuf_create(sock, mh->mh_type, mh->mh_op + 1, 32 << 10);
	if (ab == NULL) {
		ERR_RETVAL(ENOMEM);
	}

	switch (mh->mh_op) {
	case TRACE_LIST_REQ:
		err = pfs_trace_list(tr->tr_file, tr->tr_line, ab);
		break;

	case TRACE_SET_REQ:
		err = pfs_trace_set(tr->tr_file, tr->tr_line, tr->tr_enable, ab);
		break;

	default:
		err = -1;
		break;
	}
	pfs_adminbuf_destroy(ab, err);

	return err;
}
