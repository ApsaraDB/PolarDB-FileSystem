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

#ifndef	_PFS_DEF_H_
#define	_PFS_DEF_H_

#ifndef likely
	#define likely(c) __builtin_expect(!!(c), 1)
#endif
#ifndef unlikely
	#define unlikely(c)  __builtin_expect(!!(c), 0)
#endif

#define STATIC_ASSERT(sentence) \
	typedef __attribute__ ((unused)) char __sassert[(sentence)*2-1];

#define OUT

#endif // _PFS_DEF_H_
