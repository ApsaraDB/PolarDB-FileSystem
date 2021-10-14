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

#ifndef	_PFSD_MEMORY_H_
#define	_PFSD_MEMORY_H_

enum {
	MD_NONE = 0,
	MD_DIR,
	MD_FILE,
	MD_MOUNTARG,

	MD_NTYPE
};

void* pfsd_mem_malloc(size_t size, int type);
void* pfsd_mem_malloc_array(size_t nelem, size_t elemsize, int type);
void pfsd_mem_free(void *ptr, int type);
void* pfsd_mem_realloc(void *ptr, size_t newsize, int type);
int pfsd_mem_memalign(void **pp, size_t alignment, size_t size, int type);

#endif	/* _PFSD_MEMORY_H_ */

