/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#include "plugin.h"
#include "tty-clipboard.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>

/**
 * Mock plugin for testing bridge without depending on Wayland/Klipper
 * 
 * This plugin stores clipboard data in memory and can be used to test
 * the bridge functionality without requiring a real clipboard manager.
 * 
 * Supports SIGUSR1 signal to inject local clipboard changes for testing
 * scenarios where the buffer originates from the local system.
 */

typedef struct {
	unsigned char *data;
	size_t size;
	clipboard_metadata_t metadata;
	volatile int local_change_pending;
	int local_change_count;
} mock_plugin_ctx_t;

static mock_plugin_ctx_t *mock_data = NULL;

/* Generate new clipboard data simulating a local system change */
static void generate_local_clipboard_data(mock_plugin_ctx_t *ctx)
{
	if (!ctx)
		return;

	/* Free previous data */
	if (ctx->data) {
		free(ctx->data);
		ctx->data = NULL;
		ctx->size = 0;
	}

	/* Increment change counter and generate new data */
	ctx->local_change_count++;

	/* Generate data: "local_clipboard_change_<timestamp>_#<count>" */
	char buffer[256];
	time_t now = time(NULL);
	int written = snprintf(buffer, sizeof(buffer),
			       "local_clipboard_change_%ld_#%d", now,
			       ctx->local_change_count);

	if (written > 0 && written < (int)sizeof(buffer)) {
		ctx->size = (size_t)written;
		ctx->data = malloc(ctx->size);
		if (ctx->data) {
			memcpy(ctx->data, buffer, ctx->size);
			/* Update metadata to indicate local origin */
			memset(&ctx->metadata, 0, sizeof(ctx->metadata));
			/* Mark as local change by setting metadata fields */
		}
	}
}

/* Signal handler for local clipboard changes */
static void signal_local_change(int signum)
{
	(void)signum;
	if (mock_data) {
		mock_data->local_change_pending = 1;
		/* Generate new clipboard data immediately */
		generate_local_clipboard_data(mock_data);
	}
}

static plugin_handle_t mock_init(void)
{
	mock_plugin_ctx_t *ctx = malloc(sizeof(mock_plugin_ctx_t));
	if (!ctx)
		return NULL;

	ctx->data = NULL;
	ctx->size = 0;
	ctx->local_change_pending = 0;
	ctx->local_change_count = 0;
	memset(&ctx->metadata, 0, sizeof(ctx->metadata));

	mock_data = ctx;

	/* Setup signal handler for local clipboard changes */
	signal(SIGUSR1, signal_local_change);

	return ctx;
}

static clipboard_data_t *mock_read(plugin_handle_t handle)
{
	mock_plugin_ctx_t *ctx = (mock_plugin_ctx_t *)handle;
	if (!ctx || !ctx->data || ctx->size == 0)
		return NULL;

	clipboard_data_t *cdata = allocate_clipboard_data(ctx->size);
	if (!cdata)
		return NULL;

	memcpy(cdata->data, ctx->data, ctx->size);
	memcpy(&cdata->metadata, &ctx->metadata, sizeof(clipboard_metadata_t));

	// Logging: trace read operation
	char uuid_buf[33];
	for (int i = 0; i < 16; ++i) sprintf(&uuid_buf[i*2], "%02x", ctx->metadata.write_uuid[i]);
	uuid_buf[32] = '\0';
	LOG_DEBUG("[MOCK] Read %zu bytes, hostname: %s, ts: %ld, uuid: %s",
		ctx->size,
		ctx->metadata.hostname[0] ? ctx->metadata.hostname : "unknown",
		(long)ctx->metadata.timestamp,
		uuid_buf);

	return cdata;
}

static int mock_write(plugin_handle_t handle, const clipboard_data_t *data)
{
	mock_plugin_ctx_t *ctx = (mock_plugin_ctx_t *)handle;
	if (!ctx || !data)
		return -1;

	/* Free previous data */
	if (ctx->data) {
		free(ctx->data);
		ctx->data = NULL;
		ctx->size = 0;
	}

	/* Store new data */
	if (data->size > 0) {
		ctx->data = malloc(data->size);
		if (!ctx->data)
			return -1;

		memcpy(ctx->data, data->data, data->size);
		ctx->size = data->size;
		memcpy(&ctx->metadata, &data->metadata,
			   sizeof(clipboard_metadata_t));
	}

	// Logging: trace write operation
	char uuid_buf[33];
	for (int i = 0; i < 16; ++i) sprintf(&uuid_buf[i*2], "%02x", data->metadata.write_uuid[i]);
	uuid_buf[32] = '\0';
	LOG_DEBUG("[MOCK] Write %zu bytes, hostname: %s, ts: %ld, uuid: %s",
		data->size,
		data->metadata.hostname[0] ? data->metadata.hostname : "unknown",
		(long)data->metadata.timestamp,
		uuid_buf);

	/* Clear pending change flag when bridge writes to local clipboard */
	ctx->local_change_pending = 0;

	return 0;
}

static void mock_free_clipboard_data(clipboard_data_t *data)
{
	if (data) {
		free(data->data);
		free(data);
	}
}

static void mock_cleanup(plugin_handle_t handle)
{
	mock_plugin_ctx_t *ctx = (mock_plugin_ctx_t *)handle;
	if (ctx) {
		if (ctx->data)
			free(ctx->data);
		free(ctx);
		mock_data = NULL;
	}
}

/* Export plugin interface */
const plugin_interface_t mock_plugin = {
	.name = "mock",
	.version = "1.0",
	.init = mock_init,
	.read = mock_read,
	.write = mock_write,
	.free_clipboard_data = mock_free_clipboard_data,
	.cleanup = mock_cleanup,
};
