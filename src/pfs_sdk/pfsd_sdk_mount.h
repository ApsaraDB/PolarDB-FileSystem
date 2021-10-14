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


#ifndef PFSD_MOUNT_SHARE_H_
#define PFSD_MOUNT_SHARE_H_

void 	*pfs_mount_prepare(const char *cluster, const char *pbdname,
    int host_id, int flags);
void 	pfs_mount_post(void *handle, int err);
void 	pfs_mount_atfork_child(void *handle);
void 	*pfs_remount_prepare(const char *cluster, const char *pbdname,
    int host_id, int flags);
void 	pfs_remount_post(void *handle, int err);

void	pfs_umount_prepare(const char *pbdname, void *handle);
void	pfs_umount_post(const char *pbdname, void *handle);

#endif //PFSD_MOUNT_SHARE_H_
