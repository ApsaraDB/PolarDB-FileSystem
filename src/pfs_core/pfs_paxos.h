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

#ifndef	_PFS_PAXOS_H_
#define	_PFS_PAXOS_H_

typedef struct pfs_mount 		pfs_mount_t;

#define NAME_ID_SIZE 			48
#define	DEFAULT_MAX_HOSTS		254

#define PFS_LEADER_MAGIC 		0xbabababa
#define PFS_LEADER_CLEAR 		0x11282016
#define PFS_LEADER_VERSION_PRIMARY 	0x00010000
#define PFS_LEADER_VERSION_SECONDARY 	0x00000002
#define PFS_LEADER_UNUSED		0xb0

typedef struct pfs_leader_record {
        uint32_t magic;
        uint32_t version;
        uint32_t flags;
        uint32_t sector_size;
        uint64_t num_hosts;
        uint64_t max_hosts;

        uint8_t  unused[PFS_LEADER_UNUSED];

	/*
	 * Fields for log. The txid range on log is (tail, head].
	 * Tx upto tail have been committed to PBD.
	 */
	uint64_t tail_txid;		/* tx in range (tail, head] is */
	uint64_t head_txid;		/* in log; (-max, tail] is on pbd */
	uint64_t tail_offset;
	uint64_t head_offset;
	uint64_t log_size;
	uint64_t head_lsn;		/* sequence number; (0, head_lsn] */
	uint32_t checksum;
} pfs_leader_record_t;

/* LR size only relating to paxos */
#define	LR_PAXOS_SIZE		offsetof(pfs_leader_record, tail_txid)
#define	LEADER_CHECKSUM_LEN	offsetof(pfs_leader_record, checksum)

#define PFS_OK                   1
#define PFS_NONE                 0    /* unused */
#define PFS_ERROR             -201
#define PFS_AIO_TIMEOUT       -202
#define PFS_WD_ERROR          -203

#define PFS_LEADER_EMAGIC      -223
#define PFS_LEADER_EVERSION    -224
#define PFS_LEADER_ESECTORSIZE -225
#define PFS_LEADER_ENUMHOSTS   -228
#define PFS_LEADER_ECHECKSUM   -229

static inline uint32_t
leader_checksum(struct pfs_leader_record *lr)
{
	return crc32c((uint32_t)~1, (uint8_t *)lr, LEADER_CHECKSUM_LEN);
}

int 	pfs_leader_init(pfs_mount_t *mnt, int num_hosts, int max_hosts,
	    int write_clear, size_t logsize);
int 	pfs_leader_load(pfs_mount_t *mnt);
void 	pfs_leader_unload(pfs_mount_t *mnt);
int 	pfs_leader_write(pfs_mount_t *mnt, pfs_leader_record_t *nl);
int 	pfs_leader_read(pfs_mount_t *mnt, pfs_leader_record_t *leader_ret);

int	paxos_hostid_local_lock(const char *pbdname, int hostid, const char *caller);
void	paxos_hostid_local_unlock(int fd);

#endif
