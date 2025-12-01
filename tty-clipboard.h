/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#ifndef TTY_CLIPBOARD_H_
#define TTY_CLIPBOARD_H_

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define READ_PORT 5457
#define WRITE_PORT 5458
#define BUFFER_SIZE 4096
#define READ_BLOCKED_PORT 5459

char *create_xdg_config_path(const char *app_name);

#define __cleanup__(fn) __attribute__((cleanup(fn)))

#define DECLARE_CLEANUP_FUNC(name, type) void name(type *__p)

#define DEFINE_CLEANUP_FUNC(name, type, free_fn) \
	DECLARE_CLEANUP_FUNC(name, type)         \
	{                                        \
		if (*__p)                        \
			free_fn(*__p);           \
	}

static inline void freep(void *p)
{
	free(*(void **)p);
}
#define _cleanup_free_ __cleanup__(freep)

static inline DEFINE_CLEANUP_FUNC(cleanup_file, FILE *, fclose)
#define _cleanup_file_ __cleanup__(cleanup_file)

	static inline DEFINE_CLEANUP_FUNC(cleanup_dir, DIR *, closedir)
#define _cleanup_dir_ __cleanup__(cleanup_dir)

		static inline void cleanup_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}
#define _cleanup_fd_ __cleanup__(cleanup_fd)

#endif // TTY_CLIPBOARD_H_
