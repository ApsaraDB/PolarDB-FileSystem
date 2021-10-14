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

#include <sys/eventfd.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pfs_api.h"
#include "pfs_admin.h"
#include "pfs_trace.h"
#include "pfs_impl.h"
#include "pfs_util.h"
#include "pfs_command.h"
#include "pfs_option.h"

typedef struct msg_errinject {
	char		ei_file[PFS_MAX_PATHLEN];
	int32_t		ei_line;
	int32_t		ei_error;
} msg_errinject_t;

typedef struct admin_buf {
	pfs_printer	b_printer;
	int		b_sock;
	msg_header_t	*b_header;
	char		*b_dataptr;
	size_t		b_datasiz;
	size_t		b_datalen;
} admin_buf_t;

typedef struct admin_event	admin_event_t;
typedef struct admin_info	admin_info_t;
typedef struct event_ops	event_ops_t;

static 	void 	admin_set_event(admin_info_t *ai, admin_event_t *ep,
	            int fd, event_ops_t *ops, void *data);
static 	void 	admin_clr_event(admin_info_t *ai, admin_event_t *ep);
static 	admin_event_t *admin_get_free_event(admin_info_t *ai);
static int 	pfs_adminbuf_vprintf(void *abbuf, const char *fmt, va_list ap);

static	void	event_handle_newconn(admin_event_t *, admin_info_t *);
static	void	event_cancel_newconn(admin_event_t *, admin_info_t *);
static	void	event_handle_stopadmin(admin_event_t *, admin_info_t *);
static	void	event_cancel_stopadmin(admin_event_t *, admin_info_t *);
static	void	event_handle_cmddone(admin_event_t *, admin_info_t *);
static	void	event_cancel_cmddone(admin_event_t *, admin_info_t *);

typedef struct event_ops {
	void	(*eop_handle)(admin_event_t *ep, admin_info_t *ai);
	void	(*eop_cancel)(admin_event_t *ep, admin_info_t *ai);
} event_ops_t;
static event_ops_t eventops_newconn = {
	.eop_handle	= event_handle_newconn,
	.eop_cancel	= event_cancel_newconn,
};
static event_ops_t eventops_stopadmin = {
	.eop_handle	= event_handle_stopadmin,
	.eop_cancel	= event_cancel_stopadmin,
};
static event_ops_t eventops_cmddone = {
	.eop_handle	= event_handle_cmddone,
	.eop_cancel	= event_cancel_cmddone,
};

/*
 * Admin task is to be done by the admin thread.
 */
typedef struct admin_event {
	/*
	 * object invariant:
	 * if e_ops is valid, it means the event is in use.
	 * if e_pollfd is valid, it means the event is inited.
	 */
	int		e_fd;		/* the fd to notify the task is pending */
	event_ops_t	*e_ops;
	void		*e_data;
	struct pollfd 	*e_pollfd;
} admin_event_t;
#define	ADMIN_NEVENT	18

typedef struct admin_info {
	pthread_t	ai_thrid;
	char 		ai_sockpath[PFS_MAX_PATHLEN];
	int		ai_sockfd;
	int		ai_exitfd;
	int		ai_stop;
	int		ai_nworkevt;	/* # of in use events */
	struct pollfd	ai_pollfd[ADMIN_NEVENT];
	admin_event_t	ai_event[ADMIN_NEVENT];
} admin_info_t;

int
uds_recv(int sock, void *buf, int len, int flags)
{
	int n, rsum;
	char *p = (char *)buf;

	for (rsum = 0; rsum < len;  rsum += n) {
		n = recv(sock, p + rsum, len - rsum, flags);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				n = 0;
				continue;
			}
			ERR_RETVAL(EIO);
		}
		if (n == 0) {
			/*
			 * The socket is closed by the other end.
			 * Abort the receive.
			 */
			break;
		}
	}
	return rsum;
}

int
uds_send(int sock, void *buf, int len, int flags)
{
	int n, ssum;
	char *p = (char *)buf;

	for (ssum = 0; ssum < len; ssum += n) {
		n = send(sock, p + ssum, len - ssum, flags);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				n = 0;
				continue;
			}
			pfs_etrace("uds send failed! n:%d, len:%d, errno:%d\n",
			     n, len, errno);
			ERR_RETVAL(EIO);
		}
	}
	return ssum;
}

static int
conn_handle_errorinject(int clisock, msg_header_t *mh, admin_info_t *ai)
{
	return 0;
}

static int
conn_handle_command(int clisock, msg_header_t *mh, admin_info_t *ai)
{
	int n, err;
	msg_command_t msgcmd;
	size_t size;
	struct cmdinfo *ci = NULL;
	admin_event_t *ep = NULL;
	int evtfd = -1;

	switch (mh->mh_op) {
	case CMD_READ_REQ:
		size = sizeof(struct cmd_read);
		break;

	case CMD_DU_REQ:
		size = sizeof(struct cmd_du);
		break;

	case CMD_LSOF_REQ:
		size = sizeof(struct cmd_lsof);
		break;

	case CMD_MEMSTAT_REQ:
		size = sizeof(struct cmd_memstat);
		break;

	case CMD_INFO_REQ:
		size = sizeof(struct cmd_info);
		break;

	case CMD_DEVSTAT_REQ:
		size = sizeof(struct cmd_devstat);
		break;
	case CMD_MOUNTSTAT_REQ:
		size = sizeof(struct cmd_mountstat);
		break;

#if 0
	case CMD_STAT_REQ:
		size = sizeof(struct cmd_stat);
		break;
#endif

	case CMD_NAMECACHE_STAT_REQ:
		size = sizeof(struct cmd_namecachestat);
		break;

	case CMD_NAMECACHE_BINSTAT_REQ:
		size = sizeof(struct cmd_namecachebinstat);
		break;

	default:
		pfs_etrace("unknonw cmd op %d\n", mh->mh_op);
		return -1;
	}
	if (size != (size_t)mh->mh_datalen)
		ERR_GOTO(EINVAL, out);
	n = uds_recv(clisock, &msgcmd, size, 0);
	if (n != (int)size)
		ERR_GOTO(EIO, out);

	ep = admin_get_free_event(ai);
	if (ep == NULL) {
		ERR_GOTO(EUSERS, out);
	}
	evtfd = eventfd(0, 0);
	if (evtfd < 0)
		ERR_GOTO(ENOBUFS, out);
	ci = (struct cmdinfo *)pfs_mem_malloc(sizeof(*ci), M_CMDINFO);
	if (ci == NULL)
		ERR_GOTO(ENOMEM, out);

	ci->ci_clisock = dup(clisock);
	if (ci->ci_clisock < 0)
		ERR_GOTO(EBADF, out);
	ci->ci_donefd = evtfd;
	ci->ci_msgcmd = msgcmd;	/* structure copy */
	ci->ci_cmdop = mh->mh_op;
	ci->ci_stopcmd = false;
	err = pthread_create(&ci->ci_tid, NULL, pfs_command_entry, (void *)ci);
	if (err) {
		pfs_etrace("cant create cmmand thread");
		ERR_GOTO(err, out);
	}
	admin_set_event(ai, ep, evtfd, &eventops_cmddone, ci);
	pfs_verbtrace("accept cmd %d socket %d\n", ci->ci_cmdop, ci->ci_clisock);
	return 0;

out:
	if (evtfd >= 0) {
		close(evtfd);
		evtfd = -1;
	}
	if (ci) {
		if (ci->ci_clisock >= 0) {
			close(ci->ci_clisock);
			ci->ci_clisock = -1;
		}
		pfs_mem_free(ci, M_CMDINFO);
	}
	return err;
}

static int
conn_handle_trace(int clisock, msg_header_t *mh, admin_info_t *ai)
{
	int err, n;
	msg_trace_t msgtr;

	if (mh->mh_datalen != sizeof(msg_trace_t)) {
		pfs_etrace("wrong message size %u vs %zd\n",
		    (unsigned)mh->mh_datalen, sizeof(msg_trace_t));
		ERR_RETVAL(EINVAL);
	}

	memset(&msgtr, 0, sizeof(msgtr));
	n = uds_recv(clisock, &msgtr, sizeof(msgtr), 0);
	if (n != (int)sizeof(msgtr)) {
		pfs_etrace("recv message failed %d vs %zd\n",
		    n, sizeof(msg_trace_t));
		ERR_RETVAL(EIO);
	}

	err = pfs_trace_handle(clisock, mh, &msgtr);
	return err;
}

static int
conn_handle_option(int clisock, msg_header_t *mh, admin_info_t *ai)
{
	int err, n;
	msg_option_t msgopt;

	if (mh->mh_datalen != sizeof(msg_option_t)) {
		pfs_etrace("wrong message size %u vs %zd\n",
		    (unsigned)mh->mh_datalen, sizeof(msg_option_t));
		ERR_RETVAL(EINVAL);
	}

	memset(&msgopt, 0, sizeof(msgopt));
	n = uds_recv(clisock, &msgopt, sizeof(msgopt), 0);
	if (n != (int)sizeof(msgopt)) {
		pfs_etrace("recv message failed %d vs %zd\n",
		    n, sizeof(msg_option_t));
		ERR_RETVAL(EIO);
	}

	err = pfs_option_handle(clisock, mh, &msgopt);
	return err;
}

static void
event_handle_newconn(admin_event_t *ep, admin_info_t *ai)
{
	int clisock;
	int err = 0, n;
	msg_header_t msghdr, *mh = &msghdr;

	if (ai->ai_stop)
		return;

	clisock = accept(ep->e_fd, NULL, NULL);
	if (clisock < 0) {
		pfs_etrace("accept failed: %s\n", strerror(errno));
		return;
	}

	n = uds_recv(clisock, mh, sizeof(*mh), 0);
	if (n != (int)sizeof(*mh)) {
		close(clisock);
		pfs_etrace("recv error %d: %s\n", errno, strerror(errno));
		return;
	}

	switch (mh->mh_type) {
	case ADM_TRACE:
		err = conn_handle_trace(clisock, mh, ai);
		break;

	case ADM_ERRINJECT:
		err = conn_handle_errorinject(clisock, mh, ai);
		break;

	case ADM_COMMAND:
		err = conn_handle_command(clisock, mh, ai);
		break;

	case ADM_OPTION:
		err = conn_handle_option(clisock, mh, ai);
		break;

	default:
		err = -1;
		break;
	}

	if (err) {
		pfs_etrace("failed to handle msg type=%d, op=%d\n",
		    msghdr.mh_type, msghdr.mh_op);
	}
	close(clisock);
}

static void
event_cancel_newconn(admin_event_t *ep, admin_info_t *ai)
{
	admin_clr_event(ai, ep);
}

static void
event_handle_stopadmin(admin_event_t *ep, admin_info_t *ai)
{
	ai->ai_stop = true;
}

static void
event_cancel_stopadmin(admin_event_t *ep, admin_info_t *ai)
{
	admin_clr_event(ai, ep);
}

static void
event_handle_cmddone(admin_event_t *ep, admin_info_t *ai)
{
	int rv;
	struct cmdinfo *ci = (struct cmdinfo *)ep->e_data;

	close(ep->e_fd);
	admin_clr_event(ai, ep);

	rv = pthread_join(ci->ci_tid, NULL);
	PFS_VERIFY(rv == 0);
	pfs_mem_free(ci, M_CMDINFO);
}

static void
event_cancel_cmddone(admin_event_t *ep, admin_info_t *ai)
{
	struct cmdinfo *ci = (struct cmdinfo *)ep->e_data;

	/*
	 * Set the ci_stopcmd flag so that the command thread
	 * can stop its task and notify admin thread when it is
	 * done.
	 */
	__atomic_store_n(&ci->ci_stopcmd, 1, __ATOMIC_RELEASE);
}

static inline void
event_handle(admin_event_t *ep, admin_info_t *ai)
{
	(ep->e_ops->eop_handle)(ep, ai);
}

static inline void
event_cancel(admin_event_t *ep, admin_info_t *ai)
{
	(ep->e_ops->eop_cancel)(ep, ai);
}

static void
event_reset(admin_event_t *ep, struct pollfd *pfd)
{
	ep->e_fd = -1;
	ep->e_ops = NULL;
	ep->e_data = NULL;
	ep->e_pollfd = pfd;

	pfd->fd = -1;
	pfd->events = 0;
	pfd->revents = 0;
}

static void
admin_set_event(admin_info_t *ai, admin_event_t *ep, int fd, event_ops_t *ops,
    void *data)
{
	int indx = ep - &ai->ai_event[0];

	PFS_ASSERT(ep->e_ops == NULL);
	PFS_ASSERT(0 <= indx && indx < ADMIN_NEVENT);
	PFS_ASSERT(ep->e_pollfd == &ai->ai_pollfd[indx]);

	ep->e_fd = fd;
	ep->e_ops = ops;
	ep->e_data = data;
	ep->e_pollfd->fd = fd;
	ep->e_pollfd->events = POLLIN | POLLERR;
	ep->e_pollfd->revents = 0;

	ai->ai_nworkevt++;
}

static void
admin_clr_event(admin_info_t *ai, admin_event_t *ep)
{
	int indx = ep - &ai->ai_event[0];

	PFS_ASSERT(0 <= indx && indx < ADMIN_NEVENT);
	PFS_ASSERT(ep->e_pollfd == &ai->ai_pollfd[indx]);

	event_reset(ep, ep->e_pollfd);
	ai->ai_nworkevt--;
}

static admin_event_t *
admin_get_free_event(admin_info_t *ai)
{
	int i;
	admin_event_t *ep;

	for (i = 0; i < ADMIN_NEVENT; i++) {
		ep = &ai->ai_event[i];
		if (ep->e_ops == NULL)
			return ep;
	}
	return NULL;
}

/*
 * Main part of the debug thread. It inits the server socket
 * and in the loop waits for connecting
 */
static void *
pfs_admin_entry(void *arg)
{
	int i, ret;
	admin_info_t *ai = (admin_info_t *)arg;
	admin_event_t *ep;
	struct pollfd *pfd;

	pfs_itrace("admin thread enter\n");

	admin_set_event(ai, &ai->ai_event[0], ai->ai_exitfd,
	    &eventops_stopadmin, NULL);
	admin_set_event(ai, &ai->ai_event[1], ai->ai_sockfd,
	    &eventops_newconn, NULL);
	for (;;) {
		if (ai->ai_nworkevt == 0)
			break;

		ret = poll(ai->ai_pollfd, ADMIN_NEVENT, -1);
		if (ret < 0) {
			pfs_etrace("failed to poll: %s\n", strerror(errno));
			continue;
		}

		for (i = 0; i < ADMIN_NEVENT; i++) {
			ep = &ai->ai_event[i];
			if (ep->e_ops == NULL)
				continue;

			pfd = ep->e_pollfd;
			if (pfd->revents & (POLLIN|POLLERR)) {
				event_handle(ep, ai);
				pfd->revents = 0;
			} else if (pfd->revents != 0) {
				pfs_etrace("unkonw event mask %#x",
				    pfd->revents);
				pfd->revents = 0;
			}

			/*
			 * Must check the event is still valid, since
			 * event_handle may have cleared the event.
			 */
			if (ai->ai_stop && ep->e_ops)
				event_cancel(ep, ai);
		}
	}

	pfs_itrace("admin thread exit!\n");
	return NULL;
}

/*
 * the api for create monitor thread
 */
admin_info_t *
pfs_admin_init(const char *pbdname)
{
	int i;
	int err, nprint;
	struct sockaddr_un addr;
	admin_info_t *ai;
	mode_t omask;

	ai = (admin_info_t *)pfs_mem_malloc(sizeof(*ai), M_ADMINFO);
	if (ai == NULL)
		return NULL;
	memset(ai, 0, sizeof(*ai));
	ai->ai_sockfd = -1;
	ai->ai_exitfd = -1;
	ai->ai_stop = false;
	for (i = 0; i < ADMIN_NEVENT; i++)
		event_reset(&ai->ai_event[i], &ai->ai_pollfd[i]);
	ai->ai_nworkevt = 0;

	/*
	 * Prepare the unix domain socket address.
	 */
	nprint = snprintf(ai->ai_sockpath, sizeof(ai->ai_sockpath),
	   "/var/run/pfs/pfsadm-%s.sock", pbdname);
	if (nprint >= (int)sizeof(ai->ai_sockpath)) {
		pfs_etrace("pbdname %s too long\n", pbdname);
		ai->ai_sockpath[0] = '\0';
		goto out;
	}
	addr.sun_family = AF_UNIX;
	if (strncpy_safe(addr.sun_path, ai->ai_sockpath, sizeof(addr.sun_path)) < 0) {
		pfs_etrace("pbdname %s too long for uds socket\n", pbdname);
		ai->ai_sockpath[0] = '\0';
		goto out;
	}

	/*
	 * Setup the server socket.
	 */
	(void)unlink(ai->ai_sockpath);
	ai->ai_sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ai->ai_sockfd < 0) {
		pfs_etrace("creat socket failed: %s\n", strerror(errno));
		goto out;
	}
	omask = umask(0000);
	err = bind(ai->ai_sockfd, (struct sockaddr *)&addr, sizeof(addr));
	(void)umask(omask);
	if (err < 0) {
		pfs_etrace("bind socket %s failed: %s\n", addr.sun_path,
		    strerror(errno));
		goto out;
	}
	err = listen(ai->ai_sockfd, 5);
		if (err < 0) {
		pfs_etrace("listen on socket %d failed: %s\n", ai->ai_sockfd,
		    strerror(errno));
		goto out;
	}

	/*
	 * Create a event to communicate with the new trhead.
	 */
	ai->ai_exitfd = eventfd(0, 0);
	if (ai->ai_exitfd < 0) {
		pfs_etrace("eventfd failed: %s\n", strerror(errno));
		goto out;
	}

	err = pthread_create(&ai->ai_thrid, NULL, pfs_admin_entry, (void *)ai);
	if (err != 0) {
		pfs_etrace("create thread failed: %s\n", strerror(err));
		ai->ai_thrid = 0;
		goto out;
	}
	return ai;

out:
	pfs_admin_fini(ai, pbdname);
	ai = NULL;
	return ai;
}

/*
 * the api for destroy monitor thread
 */
int
pfs_admin_fini(admin_info_t *ai, const char *pbdname)
{
	int rv;

	if (ai == NULL)
		return 0;

	if (ai->ai_thrid) {
		uint64_t val = 1;
		write(ai->ai_exitfd, &val, sizeof(val));
		rv = pthread_join(ai->ai_thrid, NULL);
		PFS_VERIFY(rv == 0);
		ai->ai_thrid = 0;
	}
	if (ai->ai_exitfd >= 0) {
		close(ai->ai_exitfd);
		ai->ai_exitfd = -1;
	}
	if (ai->ai_sockfd >= 0) {
		close(ai->ai_sockfd);
		ai->ai_sockfd = -1;
	}
	if (strlen(ai->ai_sockpath) != 0) {
	    (void)unlink(ai->ai_sockpath);
	    ai->ai_sockpath[0] = '\0';
	}

	pfs_mem_free(ai, M_ADMINFO);
	return 0;
}

static int
pfs_adminbuf_flush(admin_buf_t *ab, int error)
{
	msg_header_t *mh;
	ssize_t n, sn;

	mh = ab->b_header;
	mh->mh_error = error;
	mh->mh_datalen = ab->b_datalen;
	sn = sizeof(*mh) + mh->mh_datalen;
	n = uds_send(ab->b_sock, mh, sn, MSG_NOSIGNAL);
	if (n != sn)
		return -EIO;
	n = ab->b_datalen;
	ab->b_datalen = 0;
	return n;
}

admin_buf_t *
pfs_adminbuf_create(int sock, int type, int op, int size)
{
	admin_buf_t *ab;
	msg_header_t *mh;

	ab = (admin_buf_t *)pfs_mem_malloc(sizeof(*ab) + sizeof(*mh) + size,
	    M_ADMBUF);
	if (ab == NULL)
		return ab;
	ab->b_sock = sock;
	ab->b_header = mh = (msg_header_t *)(ab + 1);
	mh->mh_type = type;
	mh->mh_op = op;
	mh->mh_error = 0;
	mh->mh_datalen = 0;
	ab->b_dataptr = (char *)(mh + 1);
	ab->b_datasiz = size;
	ab->b_datalen = 0;
	ab->b_printer.pr_dest = ab;
	ab->b_printer.pr_func = pfs_adminbuf_vprintf;
	return ab;
}

void
pfs_adminbuf_destroy(admin_buf_t *ab, int error)
{
	ssize_t n;

	n = pfs_adminbuf_flush(ab, error);
	if (error == 0 && n > 0) {
		/*
		 * Send the last msg for this successful
		 * session. The last successful msg has
		 * error == 0 and length == 0.
		 */
		(void)pfs_adminbuf_flush(ab, 0);
	}
	pfs_mem_free(ab, M_ADMBUF);
}

static int
pfs_adminbuf_vprintf(void *abbuf, const char *fmt, va_list ap)
{
	ssize_t n;
	va_list apcopy;
	int nflush = 0;
	admin_buf_t *ab = (admin_buf_t *)abbuf;

	do {
		va_copy(apcopy, ap);
		n = vsnprintf(ab->b_dataptr + ab->b_datalen,
		    ab->b_datasiz - ab->b_datalen, fmt, apcopy);
		va_end(apcopy);
		if (n < (ssize_t)(ab->b_datasiz - ab->b_datalen)) {
			ab->b_datalen += n;
			return (int)n;
		}
	} while (nflush++ == 0 && (n = pfs_adminbuf_flush(ab, 0)) >= 0);
	return -ENOBUFS;
}

int
pfs_adminbuf_printf(admin_buf_t *ab, const char *fmt, ...)
{
	va_list ap;
	ssize_t n;

	va_start(ap, fmt);
	n = pfs_adminbuf_vprintf(ab, fmt, ap);
	va_end(ap);
	return n;
}

pfs_printer_t *
pfs_adminbuf_printer(admin_buf_t *ab)
{
	return &ab->b_printer;
}

void *
pfs_adminbuf_reserve(admin_buf_t *ab, int size)
{
	int nflush = 0;

	do {
		if ((ssize_t)(ab->b_datasiz - ab->b_datalen) >= size)
			return ab->b_dataptr + ab->b_datalen;
	} while (nflush++ == 0 && pfs_adminbuf_flush(ab, 0) >= 0);
	return NULL;
}

void
pfs_adminbuf_consume(admin_buf_t *ab, int size)
{
	PFS_ASSERT(ab->b_datalen + size <= ab->b_datasiz);
	ab->b_datalen += size;
}
