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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>

#include "pfsd_shm.h"
#include "pfsd_common.h"

/* Color output */
enum Color {
	Red = 1,
	Green,
	Yellow,
	Normal,
	Blue,
	Purple,
	White,
	Max,
};

inline
void SetColor(unsigned int color)
{
	const char* colorstrings[Max] = {
		"",
		"\033[1;31;40m",
		"\033[1;32;40m",
		"\033[1;33;40m",
		"\033[0m",

		"\033[1;34;40m",
		"\033[1;35;40m",
		"\033[1;37;40m",
	};

	fprintf(stdout, "%s", colorstrings[color]);
}

static void Usage(int ac, char* av[])
{
	SetColor(Green);
	printf("Usage: %s [options]\n"
	    " -s, --size: specify shm's request size, such as 1024, 1K, 2M, 0 means all.\n"
	    " -c, --channel: specify which channel to print, -1 means all.\n"
	    " -m, --mode: simple/detail mode, default 0 for detailed, will print channels, 1 for simple mode.\n"
	    " -a, --shmdir: shm directory like: /dev/shm/pfsd\n"
	    " -h, --help: print this message.\n"
	    " pbdname : specify pbdname like 1-1.\n",
	    av[0]);
	fflush(stdout);
	SetColor(Normal);
}

static struct option tool_options[] =
{
	{"size",	 optional_argument, NULL,  's' },
	{"channel",	 optional_argument, NULL,  'c' },
	{"mode",	 optional_argument, NULL,  'm' },
	{"shmdir",	 required_argument, NULL,  'a' },
	{"help",	 optional_argument, NULL,  'h' },
	{0,		  0,		 NULL,   0  }
};

struct config {
	/* Specify pbd name */
	char pbdname[PFS_MAX_NAMELEN];
	/* Shm path dir */
	char shm_dir[PFS_MAX_PATHLEN];
	/* Specify which shm to print, 0 means all, 1KB means the nearest to
	 * round up it, such as 1KB or 2KB */
	size_t shm_reqsize;
	/* Specify which channel to print, -1 means all */
	int ch_index;
	/* Whether print summary info without detail */
	int simple;
} g_config;

static
size_t parse_size(const char* str)
{
	char* endptr = NULL;
	size_t s = strtoul(optarg, &endptr, 10);

	size_t len = strlen(endptr);
	if (len == 0)
		return s;

	size_t scale = 1;
	if (strncasecmp(endptr, "KB", len) == 0 ||
	    strncasecmp(endptr, "K", len) == 0) {
		scale = 1024;
	} else if (strncasecmp(endptr, "MB", len) == 0 ||
	    strncasecmp(endptr, "M", len) == 0) {
		scale = 1024 * 1024;
	}

	return s * scale;
}

static
int parse_options(int ac, char* av[])
{
	/* Default: all shm and all channels, but in summary */
	g_config.shm_reqsize = 0;
	g_config.ch_index = -1;
	g_config.simple = 0;
	strncpy(g_config.shm_dir, "/dev/shm/pfsd/", sizeof g_config.shm_dir);

	bool help = false;
	int opt;
	optind = 1;

	while (!help && (opt = getopt_long(ac, av, "a:m:s:c:h", tool_options,
	    NULL)) != -1) {
		switch (opt) {
			case 's':
				if (!optarg) {
					printf("missing argument for --size\n");
					return -1;
				}
				g_config.shm_reqsize = parse_size(optarg);
				printf("reqsize %lu\n", g_config.shm_reqsize);
				break;

			case 'c':
				if (!optarg) {
					printf("missing argument for --channel\n");
					return -1;
				}
				g_config.ch_index = strtoul(optarg, NULL, 10);
				printf("ch index %d\n", g_config.ch_index);
				break;

			case 'm':
				if (!optarg) {
					printf("missing argument for --mode\n");
					return -1;
				}
				g_config.simple = (optarg[0] != '0');
				printf("mode simple %d\n", g_config.simple);
				break;

			case 'a':
				strncpy(g_config.shm_dir, optarg,
				    sizeof g_config.shm_dir);
				break;

			case 'h':
				help = true;
				break;

			default:
				return -1;
		}
	}

	if (help) {
		Usage(ac, av);
		exit(0);
	}

	if (optind < ac) {
		if (optind + 1 != ac)
			return -1;

		strncpy(g_config.pbdname, av[optind], PFS_MAX_NAMELEN);
	} else {
		printf("missing pbdname\n");
		return -1;
	}

	return optind;
}

static
void print_shm(size_t reqsize, int ch_index, bool simple)
{
	for (int i = 0; i < PFSD_SHM_MAX; ++i) {
		if (reqsize == 0 ||
			g_shm[i]->sh_unitsize >= reqsize) {

			SetColor(Yellow);
			printf("--------- shm %d -------------\n", i);
			pfsd_print_shm(g_shm[i]);

			if (!simple) {
				SetColor(Purple);
				if (ch_index == -1)
					pfsd_print_all_channels(g_shm[i]);
				else
					pfsd_print_channel(g_shm[i], ch_index);
			}

			if (reqsize != 0)
				break;
		}
	}

	SetColor(Normal);
}

int main(int ac, char* av[])
{
	if (parse_options(ac, av) < 0) {
		Usage(ac, av);
		return -1;
	}

	bool simple_mode = (g_config.simple != 0);
	int wr_attach = simple_mode ? 0 : 1;

	if (pfsd_shm_attach(g_config.shm_dir, g_config.pbdname, wr_attach) != 0)
		return -1;

	print_shm(g_config.shm_reqsize, g_config.ch_index, simple_mode);

	return 0;
}

