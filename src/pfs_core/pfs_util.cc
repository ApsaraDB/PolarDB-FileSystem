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

#include <string.h>
#undef	 NDEBUG
#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>

#include "pfs_impl.h"
#include "pfs_util.h"
#include "pfs_api.h"
#include "pfs_impl.h"
#include "pfs_inode.h"
#include "pfs_memory.h"
#include "pfs_trace.h"

/*-
 *  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 */

/* CRC32C routines, these use a different polynomial */
/*****************************************************************/
/*                                                               */
/* CRC LOOKUP TABLE                                              */
/* ================                                              */
/* The following CRC lookup table was generated automagically    */
/* by the Rocksoft^tm Model CRC Algorithm Table Generation       */
/* Program V1.0 using the following model parameters:            */
/*                                                               */
/*    Width   : 4 bytes.                                         */
/*    Poly    : 0x1EDC6F41L                                      */
/*    Reverse : TRUE.                                            */
/*                                                               */
/* For more information on the Rocksoft^tm Model CRC Algorithm,  */
/* see the document titled "A Painless Guide to CRC Error        */
/* Detection Algorithms" by Ross Williams                        */
/* (ross@guest.adelaide.edu.au.). This document is likely to be  */
/* in the FTP archive "ftp.adelaide.edu.au/pub/rocksoft".        */
/*                                                               */
/*****************************************************************/

static const uint32_t crc32Table[256] = {
	0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
	0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
	0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
	0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
	0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
	0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
	0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
	0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
	0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
	0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
	0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
	0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
	0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
	0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
	0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
	0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
	0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
	0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
	0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
	0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
	0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
	0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
	0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
	0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
	0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
	0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
	0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
	0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
	0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
	0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
	0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
	0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
	0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
	0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
	0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
	0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
	0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
	0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
	0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
	0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
	0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
	0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
	0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
	0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
	0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
	0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
	0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
	0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
	0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
	0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
	0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
	0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
	0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
	0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
	0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
	0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
	0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
	0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
	0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
	0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
	0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
	0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
	0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
	0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

uint32_t
crc32c(uint32_t crc, const void *buf, size_t size)
{
	const uint8_t *p = (const uint8_t *)buf;

	while (size--)
		crc = crc32Table[(crc ^ *p++) & 0xff] ^ (crc >> 8);

	return crc;
}

uint64_t
roundup_power2(uint64_t val)
{
	val--;
	val |= val >> 1;
	val |= val >> 2;
	val |= val >> 4;
	val |= val >> 8;
	val |= val >> 16;
	val |= val >> 32;
	val++;
	return val;
}

int
strncpy_safe(char *dst, const char *src, size_t n)
{
	size_t ncopy;

	assert(n > 0);
	(void)strncpy(dst, src, n);
	dst[n - 1] = '\0';
	if ((ncopy = strlen(dst)) != strlen(src))
		return -1;
	return (int)ncopy;
}

uint32_t
crc32c_compute(const void *buf, size_t size, size_t offset)
{
	char dup[size];
	uint32_t rv, *crcp;

	assert((offset + sizeof(uint32_t)) <= size);

	memcpy(dup, buf, size);
	crcp = (uint32_t *)(dup + offset);
	*crcp = 0;

	rv = crc32c((uint32_t)~1, (uint8_t *)(dup), size);
	return rv;
}

void
oidvect_init(oidvect_t *ov)
{
	ov->ov_buf = NULL;
	ov->ov_next = 0;
	ov->ov_size = 0;
	ov->ov_holeoff_buf = NULL;
}

int
oidvect_push(oidvect_t *ov, uint64_t val, int32_t holeoff)
{
#define	OIDV_INC	512
	if (ov->ov_next >= (int)ov->ov_size) {
		void *tmp;
		ov->ov_size += OIDV_INC;
		tmp = pfs_mem_realloc(ov->ov_buf,
		    ov->ov_size * sizeof(val), M_OIDV);
		if (tmp == NULL) {
			ov->ov_size -= OIDV_INC;
			return -ENOMEM;
		}
		ov->ov_buf = (uint64_t *)tmp;

		tmp = pfs_mem_realloc(ov->ov_holeoff_buf, 
		    ov->ov_size * sizeof(holeoff), M_OIDV_HOLEOFF);
		if (tmp == NULL) {
			ov->ov_size -= OIDV_INC;
			return -ENOMEM;
		}
		ov->ov_holeoff_buf = (int32_t *)tmp;
	}

	ov->ov_buf[ov->ov_next] = val;
	ov->ov_holeoff_buf[ov->ov_next] = holeoff;
	ov->ov_next++;
	return 0;
}

uint64_t
oidvect_pop(oidvect_t *ov)
{
	if (ov->ov_next > 0)
		return ov->ov_buf[--ov->ov_next];
	return (uint64_t)-1;
}

void
oidvect_fini(oidvect_t *ov)
{
	if (ov->ov_buf) {
		pfs_mem_free(ov->ov_buf, M_OIDV);
		ov->ov_buf = NULL;
	}

	if (ov->ov_holeoff_buf) {
		pfs_mem_free(ov->ov_holeoff_buf, M_OIDV_HOLEOFF);
		ov->ov_holeoff_buf = NULL;
	}
	ov->ov_next = 0;
	ov->ov_size = 0;
}

static const char letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
#define NLETTER		62

int
gen_tempname(char *tmpl, int suffixlen, int flags, int type)
{
	int save_errno = errno;
	int fd = -1;
	int len;
	char *XXXXXX;
	uint64_t random, retry, nretry;

	len = strlen(tmpl);
	if (len < 6 + suffixlen || memcmp(&tmpl[len - 6 - suffixlen], "XXXXXX", 6))
		ERR_RETVAL(EINVAL);
	XXXXXX = &tmpl[len - 6 - suffixlen];

	random = (uint64_t)time(NULL) ^ (uint64_t)pthread_self();
	nretry = TMP_MAX;
	for (retry = 0; retry < nretry; random += 7777, ++retry) {

		for (int i = 0; i < 6; i++) {
			XXXXXX[i] = letters[random % NLETTER];
			random /= NLETTER;
		}

		switch (type) {
		case PFS_INODET_FILE:
			fd = pfs_open(tmpl,
				 (flags & ~O_ACCMODE) | O_RDWR | O_CREAT | O_EXCL,
				 S_IRUSR|S_IWUSR);
			break;

		case PFS_INODET_DIR:
			ERR_RETVAL(ENOTSUP);

		default:
			pfs_etrace("invalid type %d to generate temp file\n", type);
			PFS_ASSERT("invalid argument" == NULL);
		}

		if (fd < 0 && errno != EEXIST)
			ERR_RETVAL(errno);

		if (fd >= 0)
			break;

		/* file exist, retry */
	}

	PFS_ASSERT(fd >= 0 || retry >= nretry);
	if (retry >= nretry)
		ERR_RETVAL(EEXIST);

	errno = save_errno;
	return fd;
}

int
pfs_printf(pfs_printer_t *pr, const char *fmt, ...)
{
	int rv;
	va_list ap;

	va_start(ap, fmt);
	if (pr == NULL) {
		rv = vprintf(fmt, ap);
	} else {
		rv = (*pr->pr_func)(pr->pr_dest, fmt, ap);
	}
	va_end(ap);

	return rv;
}

void
pfs_abort(const char *action, const char *cond, const char *func, int line)
{
#define	SYM_SIZE	128
	void *buf[SYM_SIZE];
	int nsym;
	char **syms;

	pfs_etrace("failed to %s %s at %s: %d\n", action, cond, func, line);
	nsym = backtrace(buf, SYM_SIZE);
	syms = backtrace_symbols(buf, nsym);
	for (int i = 0; i < nsym; i++)
		pfs_etrace("%s\n", syms[i]);
	free(syms);

	abort();
}

uint64_t
gettimeofday_us()
{
	struct timeval now;
	int err = gettimeofday(&now, NULL);
	PFS_VERIFY(err == 0);
	(void)err;
	return now.tv_sec * 1000000 + now.tv_usec;
}
