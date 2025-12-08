/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#ifndef PLUGIN_H_
#define PLUGIN_H_

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/**
 * Plugin interface for clipboard bridges
 *
 * A plugin provides access to a local clipboard (Wayland, Klipper, etc.)
 * and forwards metadata (hostname, timestamp, UUID) through the bridge
 */

/* Forward declaration */
typedef struct clipboard_metadata {
	char hostname[256];
	int64_t timestamp;
	unsigned char write_uuid[16];  /* UUID_SIZE */
} clipboard_metadata_t;

/* Clipboard content with metadata */
typedef struct clipboard_data {
	unsigned char *data;
	size_t size;
	clipboard_metadata_t metadata;
} clipboard_data_t;

/* Plugin context - opaque pointer managed by plugin */
typedef void* plugin_handle_t;

/* Plugin interface - all plugins must implement this */
typedef struct {
	const char *name;
	const char *version;

	/**
	 * Initialize plugin
	 * Returns: plugin handle or NULL on error
	 */
	plugin_handle_t (*init)(void);


	/**
	 * Read from local clipboard (non-blocking)
	 * Returns: pointer to clipboard_data (allocated by plugin) or NULL if empty
	 * Caller must call free_clipboard_data() to free the result
	 */
	clipboard_data_t* (*read)(plugin_handle_t handle);

	/**
	 * Read from local clipboard (blocking until new data is available)
	 * Returns: pointer to clipboard_data (allocated by plugin) or NULL if interrupted
	 * Caller must call free_clipboard_data() to free the result
	 */
	clipboard_data_t* (*read_blocked)(plugin_handle_t handle);

	/**
	 * Write to local clipboard with metadata
	 * Returns: 0 on success, -1 on error
	 */
	int (*write)(plugin_handle_t handle, const clipboard_data_t *data);

	/**
	 * Free clipboard_data allocated by read()
	 */
	void (*free_clipboard_data)(clipboard_data_t *data);

	/**
	 * Cleanup plugin
	 */
	void (*cleanup)(plugin_handle_t handle);

} plugin_interface_t;

/* Helper to allocate clipboard_data */
static inline clipboard_data_t* allocate_clipboard_data(size_t size)
{
	clipboard_data_t *data = malloc(sizeof(clipboard_data_t));
	if (!data)
		return NULL;
	data->data = malloc(size);
	if (!data->data) {
		free(data);
		return NULL;
	}
	data->size = size;
	memset(&data->metadata, 0, sizeof(data->metadata));
	return data;
}

/* Helper to free clipboard_data */
static inline void free_clipboard_data_internal(clipboard_data_t *data)
{
	if (data) {
		free(data->data);
		free(data);
	}
}

#endif /* PLUGIN_H_ */
