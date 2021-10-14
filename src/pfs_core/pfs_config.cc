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

#include "pfs_config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pfs_impl.h"
#include "pfs_memory.h"
#include "pfs_trace.h"

#define COMMENT_CHARS		'#'    /* default comment chars */
#define KEYVAL_SEP		'='    /* default key-val separator character */
#define RESTART_SECTION_NAME	"restart"

static inline pfs_config_section_t*
get_section_by_name(const pfs_config_t *config, const char *sect_name)
{
	pfs_config_section_t *sect = NULL;

	if ((config == NULL) || (sect_name == NULL))
		return NULL;

	TAILQ_FOREACH(sect, &config->sect_list, next) {
		if (strcmp(sect->sect_name, sect_name) == 0)
			return sect;
	}

	return NULL;
}

static inline int
get_sect_name(char *p, char **section)
{
	/* q is temporary pointer */
	char *q = NULL;
	char *r = NULL;
	*section = NULL;

	if (!p || !*p || !section)
		return CONFIG_ERR_PARAMS;

	if (*p != '[')
		return CONFIG_ERR_PARSING;

	++p;
	while (*p && isspace(*p))
		++p;

	for (q = p; *q && (*q != ']') && (*q != '\r') && (*q != '\n'); ++q);

	if (*q != ']')
		return CONFIG_ERR_FILE;
	r = q+1;
	
	while (*q && (q > p) && isspace(*(q-1)))
		--q;

	if (q == p)
		return CONFIG_ERR_FILE;

	*q = '\0';
	*section = p;

	/* check the rest of section line */
	while (*r && isspace(*r))
		++r;

	/* must be comment or next line */
	if (*r && (*r != COMMENT_CHARS) && (*r != '\r') && (*r != '\n'))
		return CONFIG_ERR_FILE;

	return CONFIG_OK;
}

static inline pfs_config_section*
add_new_sect(pfs_config_t *config, const char *sect_name)
{
	int key_len = 0;
	if(!config || !sect_name)
		return NULL;

	pfs_config_section_t  *sect = NULL;

	if ((sect = get_section_by_name(config, sect_name)) != NULL)
		return sect;

	sect = (pfs_config_section_t*)pfs_mem_malloc(sizeof(pfs_config_section_t), M_CONFIG_SECT);
	if (sect == NULL)
		return NULL;   //return false

	key_len = strlen(sect_name);
	if (key_len < MAX_KEY_LEN) {
		strncpy(sect->sect_name, sect_name, key_len+1);
	} else {
		pfs_mem_free(sect, M_CONFIG_SECT);
		return NULL;
	}

	TAILQ_INIT(&sect->kv_list);
	TAILQ_INSERT_TAIL(&config->sect_list, sect, next);
	++config->num_of_sect;

	return sect;
}

static inline int
get_key_value(char *p, char **key, char **value)
{
	if (!p || !*p || !key || !value)
		return CONFIG_ERR_PARAMS;

	*key = *value = NULL;
	char *q = NULL;
	char *v = NULL;

	/* get key */
	while (*p && isspace(*p))
		++p;

	for (q = p; *q && (*q != KEYVAL_SEP); ++q);

	if (*q != KEYVAL_SEP)
		return CONFIG_ERR_FILE;

	v = q + 1;

	while (*q && (q > p) && isspace(*(q-1)))
		--q;

	if (q == p)
		return CONFIG_ERR_FILE;

	*q = '\0';
	*key = p;

	/* get value */
	while (*v && isspace(*v))
		++v;

	for (q = v; *q && (!isspace(*q)) && (*q != '\r') && (*q != '\n') && (*q != COMMENT_CHARS); ++q);

	while (*q && (q > v) && isspace(*(q-1)))
		--q;

	/* whether value is empty */
	if (q == v)
		return CONFIG_ERR_FILE;

	*q = '\0';
	*value = v;

	return CONFIG_OK;
}

static inline pfs_config_kv_t*
add_new_key_value(pfs_config_t *config, const char *sect_name, const char *key, const char *value)
{
	int key_len = 0;
	int value_len = 0;
	pfs_config_section_t *sect = NULL;
	pfs_config_kv_t *kv = NULL;

	/* param check */
	if (!config || !key || !value || !sect_name)
		return NULL;

	if ((sect = add_new_sect(config, sect_name)) == NULL) {
		/* something wrong */
		return NULL;
	}

	kv = (pfs_config_kv_t*)pfs_mem_malloc(sizeof(pfs_config_kv_t), M_CONFIG_KV);
	if (kv == NULL)
		return NULL;

	key_len = strlen(key);
	value_len = strlen(value);
	if ((key_len < MAX_KEY_LEN) && (value_len < MAX_VAL_LEN)) {
		strncpy(kv->kv_key, key, key_len+1);
		strncpy(kv->kv_value, value, value_len+1);
	} else {
		pfs_mem_free(kv, M_CONFIG_KV);
		return NULL;
	}

	TAILQ_INSERT_TAIL(&sect->kv_list, kv, next);
	++sect->num_of_kv;
	return kv;
}

static int
pfs_config_file_read(const char *config_path, pfs_config_t **config)
{
	int ret = 0;
	char *sect_name = NULL;
	char *key = NULL;
	char *value = NULL;
	//temp char pointer
	char *p = NULL;
	pfs_config_section_t *sect = NULL;

	FILE *fp = NULL;
	char buff[MAX_CONFIG_LINE_LEN];

	(*config) = (pfs_config_t*)pfs_mem_malloc(sizeof(pfs_config_t), M_CONFIG);
	if (*config == NULL)
		return CONFIG_ERR_MEM;

	TAILQ_INIT(&(*config)->sect_list);
	(*config)->num_of_sect = 0;

	if (config_path == NULL)
		config_path = DEFAULT_CONFIG_PATH;

	pfs_itrace("load config file from %s\n", config_path);

	fp = fopen(config_path, "r");
	if (fp == NULL) {
		if (errno == ENOENT) {
			pfs_itrace("pfs config file is not exist, path %s.\n", config_path);
			/* no config file regard as ok */
			return CONFIG_OK;
		} else {
			pfs_etrace("load config file from %s failed, errno %d\n", config_path, errno);
			return CONFIG_ERR_FILE;
		}
	}

	while (!feof(fp)) {
		//if empty line, forward
		if (fgets(buff, sizeof(buff), fp) == NULL)
			continue;

		//if space, forward
		for (p = buff; *p && isspace(*p); ++p);

		//comment line or empty line, continue next line
		if (!*p || (*p == '\r') || (*p == '\n') || (*p == COMMENT_CHARS))
			continue;

		//reach sector
		if (*p == '[') {
			if ((ret = get_sect_name(p, &sect_name)) != 0)
				goto exit;

			if ((sect = add_new_sect(*config, sect_name)) == NULL) {
				ret = CONFIG_ERR_MEM;
				goto exit;
			}
		} else {
			if (sect == NULL) {
				ret = CONFIG_ERR_FILE;
				goto exit;
			}
			//is key-value pair
			if ((ret = get_key_value(p, &key, &value)) != 0) {
				goto exit;
			}
			if (add_new_key_value(*config, sect->sect_name, key, value) == NULL) {
				ret = CONFIG_ERR_MEM;
				goto exit;
			}
		}
	}

exit:
	fclose(fp);

	return ret;
}

static inline void
remove_config_section(pfs_config_section_t *sect)
{
	pfs_config_kv_t *kv = NULL;

	if (sect == NULL)
		return;

	while ((kv = TAILQ_FIRST(&sect->kv_list)) != NULL) {
		TAILQ_REMOVE(&sect->kv_list, kv, next);
		pfs_mem_free(kv, M_CONFIG_KV);
		--(sect->num_of_kv);
	}

	pfs_mem_free(sect, M_CONFIG_SECT);
}


static void
pfs_config_free(pfs_config_t *config)
{
	pfs_config_section_t *sect = NULL;

	if (config == NULL)
		return;

	while ((sect = TAILQ_FIRST(&config->sect_list)) != NULL) {
		TAILQ_REMOVE(&config->sect_list, sect, next);
		remove_config_section(sect);
		--(config->num_of_sect);
	}

	pfs_mem_free(config, M_CONFIG);
}

int
pfs_config_load(const char *config_path, void (*func)(const char *, const char *, void*), void *ap)
{
	int ret = 0;

	pfs_config_t *config = NULL;
	pfs_config_section_t *section = NULL;
	pfs_config_kv_t *kv = NULL;

	if ((ret = pfs_config_file_read(config_path, &config)) != 0) {
		pfs_etrace("pfs load config file error, ret %d\n", ret);
		pfs_config_free(config);
		return ret;
	}

	TAILQ_FOREACH(section, &config->sect_list, next) {
		TAILQ_FOREACH(kv, &section->kv_list, next)
			(*func)(kv->kv_key, kv->kv_value, ap);
	}

	pfs_config_free(config);
	return ret;
}