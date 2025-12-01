#include "tty-clipboard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEFAULT_XDG_CONFIG_HOME ".config"
#define DEFAULT_XDG_CONFIG_DIRS "/etc/xdg"

// Function to ensure a directory exists
void ensure_directory_exists(const char *path)
{
	struct stat st;
	if (stat(path, &st) == -1) {
		if (mkdir(path, 0755) == -1) {
			perror("Failed to create directory");
			exit(EXIT_FAILURE);
		}
	} else if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "Path exists but is not a directory: %s\n",
			path);
		exit(EXIT_FAILURE);
	}
}

// Function to construct and ensure the XDG config path
char *create_xdg_config_path(const char *app_name)
{
	const char *xdg_config_home = getenv("XDG_CONFIG_HOME");
	char *config_path = NULL;

	config_path = malloc(BUFFER_SIZE);
	if (!config_path) {
		perror("could not allocated config_path buffer\n");
		exit(EXIT_FAILURE);
	}

	// Use the default if XDG_CONFIG_HOME is not set
	if (!xdg_config_home) {
		const char *home = getenv("HOME");
		if (!home) {
			fprintf(stderr,
				"HOME environment variable is not set.\n");
			exit(EXIT_FAILURE);
		}
		snprintf(config_path, BUFFER_SIZE - 1, "%s/%s", home,
			 DEFAULT_XDG_CONFIG_HOME);
	} else {
		strncpy(config_path, xdg_config_home, BUFFER_SIZE - 1);
	}
	config_path[BUFFER_SIZE - 1] = '\0';

	// Append the app-specific directory
	strncat(config_path, "/", BUFFER_SIZE - strlen(config_path) - 1);
	strncat(config_path, app_name, BUFFER_SIZE - strlen(config_path) - 1);

	// Ensure the directory exists
	ensure_directory_exists(config_path);

	return config_path;
}
