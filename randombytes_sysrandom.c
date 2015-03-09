/*
 * Copyright (c) 2013-2015
 * Frank Denis <j at pureftpd dot org>
 * Copyright (c) 2015
 * Vsevolod Stakhov <vsevolod@highsecure.ru>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stddef.h>
#include <sys/types.h>
#include <sys/param.h>
#ifndef _WIN32
# include <sys/stat.h>
# include <sys/time.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
# include <unistd.h>
#endif

#ifdef _WIN32
# include <windows.h>
# define RtlGenRandom SystemFunction036
# if defined(__cplusplus)
extern "C"
# endif
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
# pragma comment(lib, "advapi32.lib")
#endif

#ifdef __OpenBSD__

uint32_t
randombytes_sysrandom(void)
{
	return arc4random();
}

void
randombytes_sysrandom_stir(void)
{
}

void
randombytes_sysrandom_buf(void * const buf, const size_t size)
{
	return arc4random_buf(buf, size);
}

int
randombytes_sysrandom_close(void)
{
	return 0;
}

#else /* __OpenBSD__ */

typedef struct SysRandom_ {
	int random_data_source_fd;
	int initialized;
} SysRandom;

static SysRandom stream = {
	.random_data_source_fd = -1,
	.initialized = 0
};

void randombytes_sysrandom_buf (void * const buf, const size_t size);

#ifndef _WIN32
static ssize_t
safe_read (const int fd, void * const buf_, size_t count)
{
	unsigned char *buf = (unsigned char *) buf_;
	ssize_t readnb;

	assert(count > (size_t) 0U);
	do {
		while ((readnb = read (fd, buf, count)) < (ssize_t) 0
				&& (errno == EINTR || errno == EAGAIN))
			; /* LCOV_EXCL_LINE */
		if (readnb < (ssize_t) 0) {
			return readnb; /* LCOV_EXCL_LINE */
		}
		if (readnb == (ssize_t) 0) {
			break; /* LCOV_EXCL_LINE */
		}
		count -= (size_t) readnb;
		buf += readnb;
	} while (count > (ssize_t) 0);

	return (ssize_t) (buf - (unsigned char *) buf_);
}
#endif

#ifndef _WIN32
static int
randombytes_sysrandom_random_dev_open (void)
{
	/* LCOV_EXCL_START */
	struct stat st;
	static const char *devices[] = {
# ifndef USE_BLOCKING_RANDOM
			"/dev/urandom",
# endif
			"/dev/random", NULL };
	const char ** device = devices;
	int fd;

	do {
		fd = open (*device, O_RDONLY);
		if (fd != -1) {
			if (fstat (fd, &st) == 0 && S_ISCHR(st.st_mode)) {
# if defined(F_SETFD) && defined(FD_CLOEXEC)
				(void) fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC);
# endif
				return fd;
			}
			(void) close (fd);
		}
		else if (errno == EINTR) {
			continue;
		}
		device++;
	} while (*device != NULL );

	errno = EIO;
	return -1;
	/* LCOV_EXCL_STOP */
}

void
randombytes_sysrandom_init (void)
{
	const int errno_save = errno;

	if ((stream.random_data_source_fd = randombytes_sysrandom_random_dev_open ())
			== -1) {
		abort (); /* LCOV_EXCL_LINE */
	}
	errno = errno_save;
}

#else /* _WIN32 */

static void
randombytes_sysrandom_init(void)
{
}
#endif

void
randombytes_sysrandom_stir (void)
{
	if (stream.initialized == 0) {
		randombytes_sysrandom_init ();
		stream.initialized = 1;
	}
}

static void
randombytes_sysrandom_stir_if_needed (void)
{
	if (stream.initialized == 0) {
		randombytes_sysrandom_stir ();
	}
}

int
randombytes_sysrandom_close (void)
{
	int ret = -1;

#ifndef _WIN32
	if (stream.random_data_source_fd != -1
			&& close (stream.random_data_source_fd) == 0) {
		stream.random_data_source_fd = -1;
		stream.initialized = 0;
		ret = 0;
	}
#else /* _WIN32 */
	if (stream.initialized != 0) {
		stream.initialized = 0;
		ret = 0;
	}
#endif
	return ret;
}

uint32_t
randombytes_sysrandom (void)
{
	uint32_t r;

	randombytes_sysrandom_buf (&r, sizeof r);

	return r;
}

void
randombytes_sysrandom_buf (void * const buf, const size_t size)
{
	randombytes_sysrandom_stir_if_needed ();
#ifdef ULONG_LONG_MAX
	/* coverity[result_independent_of_operands] */
	assert(size <= ULONG_LONG_MAX);
#endif
#ifndef _WIN32
	if (safe_read (stream.random_data_source_fd, buf, size) != (ssize_t) size) {
		abort (); /* LCOV_EXCL_LINE */
	}
#else
	if (size > (size_t) 0xffffffff) {
		abort(); /* LCOV_EXCL_LINE */
	}
	if (! RtlGenRandom((PVOID) buf, (ULONG) size)) {
		abort(); /* LCOV_EXCL_LINE */
	}
#endif
}

#endif /* __OpenBSD__ */

const char *
randombytes_sysrandom_implementation_name (void)
{
	return "sysrandom";
}
