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

#include "pfs_admin.h"
#include "pfs_api.h"
#include "pfs_command.h"
#include "pfs_devio.h"
#include "pfs_impl.h"
#include "pfs_file.h"
#include "pfs_mount.h"
#include "pfs_stat.h"
#include "pfs_namecache.h"

#define	IO_SIZE		(64 << 10)

static ssize_t
pfs_command_read(struct cmdinfo *ci, admin_buf_t *ab)
{
	struct cmd_read *rd = &ci->ci_msgcmd.mc_rd;
	int err;
	int srcfd = -1;
	off_t offset;
	ssize_t nr, sum, length;
	struct stat st;
	void *buf;

	srcfd = pfs_open(rd->rd_file, 0, 0);
	if (srcfd < 0) {
		pfs_etrace("admin cant open %s\n", rd->rd_file);
		ERR_GOTO(ENOENT, out);
	}

	err = pfs_fstat(srcfd, &st);
	if (err < 0) {
		pfs_etrace("admin cant stat file(%s), err:%d\n", rd->rd_file, err);
		ERR_GOTO(ENOENT, out);
	}

	if (!S_ISREG(st.st_mode)) {
		pfs_etrace("admin cannot read dir(%s)\n", rd->rd_file);
		ERR_GOTO(EISDIR, out);
	}

	offset = rd->rd_off;
	length = rd->rd_len;
	if (offset >= st.st_size) {
		pfs_etrace("admin read file (%s) invalid offset(%ld), size(%ld)\n",
		    rd->rd_file, offset, st.st_size);
		ERR_GOTO(EINVAL, out);
	}
	if (length == 0) {
		pfs_close(srcfd);
		return 0;
	}
	if (length < 0 || offset + length > st.st_size)
		length = st.st_size - offset;

	for (sum = 0, nr = 0; sum < length; offset += nr, sum += nr) {
		if (__atomic_load_n(&ci->ci_stopcmd, __ATOMIC_ACQUIRE))
			ERR_GOTO(EIO, out);

		if (length - sum >= IO_SIZE)
			nr = IO_SIZE;
		else
			nr = length - sum;
		buf = pfs_adminbuf_reserve(ab, nr);
		if (buf == NULL) {
			pfs_etrace("adminbuf reserve failed! file(%s) offset:%ld,"
			    " nr:%ld\n", rd->rd_file, offset, nr);
			ERR_GOTO(ENOBUFS, out);
		}
		nr = pfs_pread(srcfd, buf, nr, offset);
		if (nr < 0){
			pfs_etrace("admin read failed! file(%s) offset:%ld,"
			    " nr:%ld\n", rd->rd_file, offset, nr);
			ERR_GOTO(EIO, out);
		}

		if (nr == 0)
			break;
		pfs_adminbuf_consume(ab, nr);
	}
	pfs_close(srcfd);
	return 0;

out:
	if (srcfd >= 0) {
		pfs_close(srcfd);
		srcfd = -1;
	}
	return err;
}

static int
pfs_command_du(struct cmdinfo *ci, admin_buf_t *ab)
{
	int err;
	struct cmd_du *du = &ci->ci_msgcmd.mc_du;

	err = pfs_du(du->du_file, du->du_all, du->du_depth,
		pfs_adminbuf_printer(ab));
	if (err < 0)
		return -errno;
	return err;
}

static int
pfs_command_info(struct cmdinfo *ci, admin_buf_t *ab)
{
	int err;
	pfs_mount_t *mnt;
	struct cmd_info *info = &ci->ci_msgcmd.mc_info;

	if (info->info_depth < 1)
		return -EINVAL;

	mnt = pfs_get_mount(info->info_pbdname);
	if (mnt == NULL)
		return -EINVAL;

	err = pfs_meta_info(mnt, info->info_depth,
	    pfs_adminbuf_printer(ab));

	pfs_put_mount(mnt);
	return err;
}

static int
pfs_command_devstat(struct cmdinfo *ci, admin_buf_t *ab)
{
	int err;
	pfs_mount_t *mnt;
	struct cmd_devstat *cmdds = &ci->ci_msgcmd.mc_devstat;

	mnt = pfs_get_mount(cmdds->ds_pbdname);
	if (mnt == NULL)
		ERR_RETVAL(ENODEV);

	err = pfs_devstat_snap(mnt->mnt_ioch_desc, ab);

	pfs_put_mount(mnt);
	return err;
}

static int
pfs_command_mountstat(struct cmdinfo *ci, admin_buf_t *ab)
{
	int err = 0;
	pfs_mount_t *mnt;
	struct cmd_mountstat *cmdds = &ci->ci_msgcmd.mc_mountstat;

	mnt = pfs_get_mount(cmdds->ms_pbdname);
	if (mnt == NULL)
		ERR_RETVAL(ENODEV);

	if (strlen(cmdds->ms_sample_pattern) != 0)
		err = pfs_mntstat_sample(cmdds->ms_sample_pattern,
		    sizeof(cmdds->ms_sample_pattern));
	else
		err = pfs_mntstat_snap(ab, cmdds->ms_begin_time,
		    cmdds->ms_time_range, cmdds->ms_file_type_pattern,
		    sizeof(cmdds->ms_file_type_pattern));

	pfs_put_mount(mnt);
	return err;
}

void *
pfs_command_entry(void *arg)
{
	struct cmdinfo *ci = (struct cmdinfo *)arg;
	int64_t val = 1;
	admin_buf_t *ab;
	int err;

	ab = pfs_adminbuf_create(ci->ci_clisock, ADM_COMMAND, ci->ci_cmdop+1,
	    IO_SIZE);
	if (ab == NULL)
		ERR_GOTO(ENOMEM, out);

	switch (ci->ci_cmdop) {
	case CMD_READ_REQ:
		err = pfs_command_read(ci, ab);
		break;

	case CMD_DU_REQ:
		err = pfs_command_du(ci, ab);
		break;

	case CMD_LSOF_REQ:
		err = pfs_fdtbl_dump(ab);
		break;

	case CMD_MEMSTAT_REQ:
		err = pfs_mem_stat(ab);
		break;

	case CMD_INFO_REQ:
		err = pfs_command_info(ci, ab);
		break;

	case CMD_DEVSTAT_REQ:
		err = pfs_command_devstat(ci, ab);
		break;

	case CMD_MOUNTSTAT_REQ:
		err = pfs_command_mountstat(ci, ab);
		break;

	case CMD_NAMECACHE_STAT_REQ:
		err = pfs_namecache_dump(ci->ci_msgcmd.mc_namecachestat.type, ab);
		break;

	case CMD_NAMECACHE_BINSTAT_REQ:
		err = pfs_namecache_dumpbin(ci, ab);
		break;

	default:
		err = -EINVAL;
		break;
	}
	pfs_adminbuf_destroy(ab, err);

out:
	pfs_verbtrace("close cmd %d socket %d\n", ci->ci_cmdop, ci->ci_clisock);
	close(ci->ci_clisock);
	write(ci->ci_donefd, &val, sizeof(val));
	return NULL;
}
