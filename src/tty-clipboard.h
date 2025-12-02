/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#ifndef TTY_CLIPBOARD_H_
#define TTY_CLIPBOARD_H_

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define SERVER_PORT 5457
#define BUFFER_SIZE 4096

// Logging framework
typedef enum {
	LOG_LEVEL_ERROR = 0,
	LOG_LEVEL_WARN = 1,
	LOG_LEVEL_INFO = 2,
	LOG_LEVEL_DEBUG = 3
} log_level_t;

extern log_level_t current_log_level;

#define LOG_ERROR(...) do { \
	if (current_log_level >= LOG_LEVEL_ERROR) { \
		fprintf(stderr, "[ERROR] " __VA_ARGS__); \
		fprintf(stderr, "\n"); \
	} \
} while(0)

#define LOG_WARN(...) do { \
	if (current_log_level >= LOG_LEVEL_WARN) { \
		fprintf(stderr, "[WARN] " __VA_ARGS__); \
		fprintf(stderr, "\n"); \
	} \
} while(0)

#define LOG_INFO(...) do { \
	if (current_log_level >= LOG_LEVEL_INFO) { \
		fprintf(stdout, "[INFO] " __VA_ARGS__); \
		fprintf(stdout, "\n"); \
	} \
} while(0)

#define LOG_DEBUG(...) do { \
	if (current_log_level >= LOG_LEVEL_DEBUG) { \
		fprintf(stdout, "[DEBUG] " __VA_ARGS__); \
		fprintf(stdout, "\n"); \
	} \
} while(0)

// Protocol commands
#define CMD_READ "read"
#define CMD_WRITE "write"
#define CMD_READ_BLOCKED "read_blocked"
#define CMD_MAX_LEN 32

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
