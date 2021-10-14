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

#ifndef	_PFS_COMMAND_H_
#define	_PFS_COMMAND_H_

#include <stdint.h>

#include "pfs_impl.h"


struct cmdinfo {
	int		ci_donefd;
	int		ci_clisock;
	int 		ci_cmdop;
	int		ci_stopcmd;
	pthread_t	ci_tid;
	msg_command_t 	ci_msgcmd;
};

void 	*pfs_command_entry(void *);

#endif	/* _PFS_COMMAND_H_ */
