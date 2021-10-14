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

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "pfs_admin.h"
#include "pfs_option.h"
#include "pfs_trace.h"
#include "pfs_config.h"

/*
 * define the config option which need restart to make effect
 */
#define LOAD_THREAD_COUNT "loadthread_count"
#define FILE_MAX_NFD "file_max_nfd"

bool
pfs_check_ival_normal(void *data)
{
	int64_t integer_val = *(int64_t*)data;
	if (integer_val <= 0)
		return false;
	return true;
}
/* 0 or 1 */
bool
pfs_check_ival_switch(void *data)
{
	int64_t integer_val = *(int64_t*)data;
	if (integer_val != PFS_OPT_ENABLE && integer_val != PFS_OPT_DISABLE)
		return false;
	return true;
}

/* convert to ensure value is a legal num */
static int
pfs_option_strtol(const char* sval, int64_t* ival)
{
	char *endptr;
	errno = 0;
	*ival = strtol(sval, &endptr, 10);
	if (endptr == sval || endptr != (sval + strlen(sval)))
		return CONFIG_ERR_VAL;

	if (errno)
		return CONFIG_ERR_VAL;

	return CONFIG_OK;
}

static int
pfs_option_list(admin_buf_t *ab)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;
	int n;

	n = pfs_adminbuf_printf(ab, "option\t\t\t\t\tcurrent\t\tdefault\n");
	if (n < 0)
		return n;

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;

		n = pfs_adminbuf_printf(ab,
					"%-36s\t%-10ld\t%-10ld\n",
					opt->o_name, *(opt->o_valuep), opt->o_valued);
		if (n < 0)
			return n;
	}
	return 0;
}

/*
 * add more protection when dukang working incorrect
 */
static bool
is_effect_after_restart_option(const char *option_name)
{
	if ((strcmp(option_name, LOAD_THREAD_COUNT) == 0) ||
	    (strcmp(option_name, FILE_MAX_NFD) == 0)) {
		return true;
	}
	return false;
}

static int
pfs_option_set(const char *name, int64_t val, admin_buf_t *ab)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;
	int n;
	bool flag = false;

	if (is_effect_after_restart_option(name)) {
		pfs_itrace("change %s should restart to take effect\n", name);
		n = pfs_adminbuf_printf(ab, "%s should restart to take effect!", name);
		return n < 0 ? n : 0;
	}

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;
		if (strcmp(name, opt->o_name) != 0)
			continue;

		if (!opt->check_func(&val)) {
			pfs_etrace("option %s new value %ld is invalid\n",
			    opt->o_name, val);
			ERR_RETVAL(EINVAL);
		}

		PFS_ASSERT(opt->o_valuep != NULL);
		pfs_itrace("option %s is changing from %ld to %ld\n",
		    opt->o_name, *(opt->o_valuep), val);
		*(opt->o_valuep) = val;
		flag = true;
		break;
	}

	if (!flag) {
		pfs_etrace("option %s is not found\n", name);
		ERR_RETVAL(EINVAL);
	}

	n = pfs_adminbuf_printf(ab, "succeeded\n");
	return n < 0 ? n : 0;
}

static void
pfs_option_update_value(const char *name, const char *value, void *data)
{
	int n = 0;
	int64_t ival = 0;

	admin_buf_t *ab = (admin_buf_t*)data;

	if (data && is_effect_after_restart_option(name)) {
		pfs_itrace("change %s should restart to take effect\n", name);
		pfs_adminbuf_printf(ab, "%s should restart to take effect!\n", name);
		return;
	}

	if (pfs_option_strtol(value, &ival) != CONFIG_OK) {
		pfs_etrace("pfs config value trans error, key %s value %s\n", name, value);
		if (ab) {
			pfs_adminbuf_printf(ab, "%-36s\t%-10ld\t%-10ld\tillegal\n",
			    name, ival, ival);
		}
		return;
	}

	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;
	bool flag = false;

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;
		if (strcmp(name, opt->o_name) != 0)
			continue;
		if (!opt->check_func(&ival)) {
			pfs_etrace("option %s new value %ld is invalid\n", opt->o_name, ival);
			if (ab)
				pfs_adminbuf_printf(ab,"%-36s\t%-10ld\t%-10ld\tillegal\n",
				    opt->o_name, ival, opt->o_valued);
			return;
		}

		PFS_ASSERT(opt->o_valuep != NULL);
		pfs_itrace("option %s is changing from %ld to %ld\n",
			    opt->o_name, *(opt->o_valuep), ival);

		*(opt->o_valuep) = ival;

		flag = true;
		if (ab) {
			n = pfs_adminbuf_printf(ab,"%-36s\t%-10ld\t%-10ld\tsuccess\n",
				    opt->o_name, ival, opt->o_valued);
			if (n < 0)
				return;
		}

		break;
	}
	if (!flag) {
		pfs_itrace("find unknown option name %s\n", name);
		if (ab)
			pfs_adminbuf_printf(ab, "%-36s\t%-10ld\t%-10ld\tn/a\n",
					    name, ival, 0);
	}
}

static int
pfs_option_reload(admin_buf_t *ab)
{
	int ret = 0;
	int n = 0;

	n = pfs_adminbuf_printf(ab, "loading config file from path %s\n"
		    "option\t\t\t\t\tnew\t\tdefault\t\tresult\n", DEFAULT_CONFIG_PATH);
	if (n < 0) {
		pfs_etrace("init return message fail\n");
		ERR_RETVAL(EINVAL);
	}

	ret = pfs_config_load(NULL, pfs_option_update_value, ab);
	if (ret != CONFIG_OK)
		pfs_etrace("pfs config load err, errno %d\n", ret);

	return ret;
}

/*
 *  update pfs option value
 *  1.after received config update command
 *  2.pfs was run at the first time
 */
int
pfs_option_init(const char *config_path)
{
	int ret = 0;

	ret = pfs_config_load(config_path, pfs_option_update_value, NULL);
	if (ret != CONFIG_OK)
		pfs_etrace("pfs config load err, errno %d\n", ret);

	return ret;
}

int
pfs_option_handle(int sock, msg_header_t *mh, msg_option_t *msgopt)
{
	int err;
	admin_buf_t *ab;

	ab = pfs_adminbuf_create(sock, mh->mh_type, mh->mh_op + 1, 32 << 10);
	if (ab == NULL) {
		ERR_RETVAL(ENOMEM);
	}
	pfs_itrace("pfs admin enter option handle, opid %d\n", mh->mh_op);

	switch (mh->mh_op) {
	case OPTION_LIST_REQ:
		err = pfs_option_list(ab);
		break;

	case OPTION_SET_REQ:
		err = pfs_option_set(msgopt->o_name, msgopt->o_value, ab);
		break;

	case OPTION_RELOAD_REQ:
		err = pfs_option_reload(ab);
		break;

	default:
		err = -1;
		break;
	}
	pfs_adminbuf_destroy(ab, err);

	return err;
}
