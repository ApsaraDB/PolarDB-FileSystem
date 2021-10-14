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

#include <malloc.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "pfsd_memory.h"

typedef struct pfsd_memory {
	const char	*mt_name;
	pthread_mutex_t	mt_mtx;
	ssize_t		mt_bytes_alloc;
	ssize_t		mt_bytes_free;
	int64_t		mt_count_alloc;
	int64_t		mt_count_free;
} pfsd_memtype_t;

#define	MEMTYPE_ENTRY(tag)	[tag] = { #tag, PTHREAD_MUTEX_INITIALIZER, }
static pfsd_memtype_t pfsd_mem_type[MD_NTYPE] = {
	MEMTYPE_ENTRY(MD_NONE),
	MEMTYPE_ENTRY(MD_DIR),
	MEMTYPE_ENTRY(MD_FILE),
};

static inline const char *
memtype_name(int type)
{
	return pfsd_mem_type[type].mt_name;
}

static void
memtype_inc(int type, int count, size_t size)
{
	pfsd_memtype_t *mt;

	assert (0 < type && type < MD_NTYPE);

	mt = &pfsd_mem_type[type];
	pthread_mutex_lock(&mt->mt_mtx);
	mt->mt_bytes_alloc += (ssize_t)size;
	mt->mt_count_alloc += count;
	pthread_mutex_unlock(&mt->mt_mtx);
}

static void
memtype_dec(int type, size_t size)
{
	pfsd_memtype_t *mt;

	assert (0 < type && type < MD_NTYPE);

	mt = &pfsd_mem_type[type];
	pthread_mutex_lock(&mt->mt_mtx);
	mt->mt_bytes_free += (ssize_t)size;
	mt->mt_count_free += 1;
	pthread_mutex_unlock(&mt->mt_mtx);
}

void *
pfsd_mem_malloc(size_t size, int type)
{
	void* ptr = malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "malloc failed: type %s, size %zu\n",
		    memtype_name(type), size);
		return NULL;
	}
	memset(ptr, 0, size);
	memtype_inc(type, 1, malloc_usable_size(ptr));

	return ptr;
}

void *
pfsd_mem_malloc_array(size_t nelem, size_t elemsize, int type)
{
	return pfsd_mem_malloc(nelem * elemsize, type);
}

void
pfsd_mem_free(void *ptr, int type)
{
	if (ptr) {
		memtype_dec(type, malloc_usable_size(ptr));
		free(ptr);
	}
}

void *
pfsd_mem_realloc(void *ptr, size_t newsize, int type)
{
	void *newptr;
	int inc;
	size_t oldsize;

	if (ptr) {
		oldsize = malloc_usable_size(ptr);
		inc = 0;
	} else {
		oldsize = 0;
		inc = 1;
	}
	newptr = realloc(ptr, newsize);
	if (newptr) {
		memtype_inc(type, inc, malloc_usable_size(newptr) - oldsize);
	}
	return newptr;
}

int
pfsd_mem_memalign(void **pp, size_t alignment, size_t size, int type)
{
	int err;

	err = posix_memalign(pp, alignment, size);
	if (err == 0)
		memtype_inc(type, 1, malloc_usable_size(*pp));
	return err;
}

