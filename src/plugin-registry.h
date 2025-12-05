/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#ifndef PLUGIN_REGISTRY_H_
#define PLUGIN_REGISTRY_H_

#include "plugin.h"

/**
 * Plugin registry - allows selecting plugins by name
 * All available plugins are compiled into a single bridge binary
 */

/* Forward declarations - each plugin implements these */
extern const plugin_interface_t wayland_plugin;
extern const plugin_interface_t klipper_plugin;
extern const plugin_interface_t mock_plugin;

/**
 * Get plugin by name
 * @param name: plugin name (e.g., "wayland", "klipper", "mock")
 * @return: pointer to plugin interface or NULL if not found
 */
static inline const plugin_interface_t *get_plugin_by_name(const char *name)
{
	if (!name)
		return NULL;

	if (strcmp(name, "wayland") == 0)
		return &wayland_plugin;
	
	if (strcmp(name, "klipper") == 0)
		return &klipper_plugin;
	
	if (strcmp(name, "mock") == 0)
		return &mock_plugin;

	return NULL;
}

#endif /* PLUGIN_REGISTRY_H_ */
