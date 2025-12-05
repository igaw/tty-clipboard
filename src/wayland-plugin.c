/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#include "plugin.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>

typedef struct {
	/* No state needed for Wayland - we call external commands */
	int dummy;
} wayland_plugin_ctx_t;

/**
 * Execute wl-paste/wl-copy and return output/handle errors
 */
static int execute_command(const char *cmd, unsigned char **output, size_t *output_size)
{
	FILE *fp = popen(cmd, "r");
	if (!fp)
		return -1;

	size_t capacity = 4096;
	size_t size = 0;
	unsigned char *buf = malloc(capacity);
	if (!buf) {
		pclose(fp);
		return -1;
	}

	int c;
	while ((c = fgetc(fp)) != EOF) {
		if (size >= capacity) {
			capacity *= 2;
			unsigned char *tmp = realloc(buf, capacity);
			if (!tmp) {
				free(buf);
				pclose(fp);
				return -1;
			}
			buf = tmp;
		}
		buf[size++] = c;
	}

	int ret = pclose(fp);
	if (ret != 0) {
		free(buf);
		return -1;
	}

	*output = buf;
	*output_size = size;
	return 0;
}

static plugin_handle_t wayland_init(void)
{
	/* Check if wl-paste/wl-copy are available */
	if (system("which wl-paste > /dev/null 2>&1") != 0) {
		fprintf(stderr, "[ERROR] wl-paste not found, Wayland clipboard unavailable\n");
		return NULL;
	}

	wayland_plugin_ctx_t *ctx = malloc(sizeof(wayland_plugin_ctx_t));
	if (!ctx)
		return NULL;

	ctx->dummy = 0;
	return ctx;
}

static clipboard_data_t* wayland_read(plugin_handle_t handle)
{
	(void)handle;  /* unused */

	unsigned char *data;
	size_t size;

	if (execute_command("wl-paste 2>/dev/null", &data, &size) != 0)
		return NULL;

	if (size == 0) {
		free(data);
		return NULL;
	}

	clipboard_data_t *cdata = malloc(sizeof(clipboard_data_t));
	if (!cdata) {
		free(data);
		return NULL;
	}

	cdata->data = data;
	cdata->size = size;
	memset(&cdata->metadata, 0, sizeof(cdata->metadata));

	return cdata;
}

static int wayland_write(plugin_handle_t handle, const clipboard_data_t *data)
{
	(void)handle;  /* unused */

	if (!data || !data->data || data->size == 0)
		return -1;

	/* Write to wl-copy via pipe */
	FILE *fp = popen("wl-copy 2>/dev/null", "w");
	if (!fp)
		return -1;

	size_t written = fwrite(data->data, 1, data->size, fp);
	int ret = pclose(fp);

	if (written != data->size || ret != 0)
		return -1;

	return 0;
}

static void wayland_free_clipboard_data(clipboard_data_t *data)
{
	if (data) {
		free(data->data);
		free(data);
	}
}

static void wayland_cleanup(plugin_handle_t handle)
{
	free(handle);
}

/* Export plugin interface */
const plugin_interface_t wayland_plugin = {
	.name = "wayland",
	.version = "1.0",
	.init = wayland_init,
	.read = wayland_read,
	.write = wayland_write,
	.free_clipboard_data = wayland_free_clipboard_data,
	.cleanup = wayland_cleanup,
};

