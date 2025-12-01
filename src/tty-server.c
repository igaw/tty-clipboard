/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#include "tty-clipboard.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>  
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/select.h>
#include <stdint.h>
#include <endian.h>

// Shared buffer and mutex
char shared_buffer[BUFFER_SIZE];
size_t shared_length = 0; // current length of data stored in shared_buffer
unsigned int gen = 0;
pthread_mutex_t buffer_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t buffer_cond = PTHREAD_COND_INITIALIZER;
volatile sig_atomic_t terminate = 0;

// Signal handler
void handle_sigint(int sig __attribute__((unused)))
{
	printf("%s:%d signal caught\n", __func__, __LINE__);
	pthread_mutex_lock(&buffer_mutex);
	terminate = 1; // Set the termination flag
	pthread_cond_broadcast(
		&buffer_cond); // Wake up threads waiting on the condition variable
	pthread_mutex_unlock(&buffer_mutex);
}

SSL_CTX *init_ssl_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	_cleanup_free_ char *path = create_xdg_config_path("tty-clipboard");
	_cleanup_free_ char *crt = NULL;
	_cleanup_free_ char *key = NULL;
	_cleanup_free_ char *ca = NULL;

	if (asprintf(&crt, "%s/certs/server.crt", path) < 0) {
		perror("Unable to create path for server certificate\n");
		exit(EXIT_FAILURE);
	}

	if (asprintf(&key, "%s/keys/server.key", path) < 0) {
		perror("Unable to create path for server key\n");
		exit(EXIT_FAILURE);
	}

	if (asprintf(&ca, "%s/certs/ca.crt", path) < 0) {
		perror("Unable to create path for ca\n");
		exit(EXIT_FAILURE);
	}

	// Initialize OpenSSL library
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// Choose the method for SSL/TLS
	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Load the server's certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM) <= 0) {
		perror("Unable to load certificate");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		perror("Unable to load private key");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Load the CA certificate for client verification
	if (SSL_CTX_load_verify_locations(ctx, ca, NULL) <= 0) {
		perror("Unable to load CA certificate");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Set the server to verify the client's certificate
	SSL_CTX_set_verify(
		ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	return ctx;
}

static int ssl_read_all(SSL *ssl, void *buf, size_t len)
{
	unsigned char *p = buf;
	size_t total = 0;
	while (total < len) {
		int r = SSL_read(ssl, p + total, (int)(len - total));
		if (r <= 0) {
			int err = SSL_get_error(ssl, r);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
				continue;
			return -1;
		}
		total += (size_t)r;
	}
	return 0;
}

static int ssl_write_all(SSL *ssl, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	size_t total = 0;
	while (total < len) {
		int w = SSL_write(ssl, p + total, (int)(len - total));
		if (w <= 0) {
			int err = SSL_get_error(ssl, w);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
				continue;
			return -1;
		}
		total += (size_t)w;
	}
	return 0;
}

static void handle_write(SSL *ssl)
{
	uint64_t be_len = 0;
	if (ssl_read_all(ssl, &be_len, sizeof(be_len)) < 0) {
		printf("Failed to read length prefix\n");
		return;
	}
	size_t len = (size_t)be64toh(be_len);
	if (len == 0) {
		printf("Empty write received\n");
		return;
	}
	if (len > BUFFER_SIZE) {
		printf("Incoming payload %zu exceeds buffer size %u, truncating\n", len, (unsigned)BUFFER_SIZE);
	}
	size_t to_copy = len > BUFFER_SIZE ? BUFFER_SIZE : len;
	unsigned char *tmp = malloc(len);
	if (!tmp) {
		perror("malloc");
		return;
	}
	if (ssl_read_all(ssl, tmp, len) < 0) {
		printf("Failed to read payload bytes\n");
		free(tmp);
		return;
	}
	pthread_mutex_lock(&buffer_mutex);
	memcpy(shared_buffer, tmp, to_copy);
	shared_length = to_copy;
	gen++;
	pthread_cond_signal(&buffer_cond);
	pthread_mutex_unlock(&buffer_mutex);
	printf("Stored %zu bytes (original %zu)\n", to_copy, len);
	free(tmp);
}

static void handle_read(SSL *ssl)
{
    pthread_mutex_lock(&buffer_mutex);
    size_t len = shared_length;
    uint64_t be_len = htobe64((uint64_t)len);
    int rc = ssl_write_all(ssl, &be_len, sizeof(be_len));
    if (rc == 0 && len > 0)
        rc = ssl_write_all(ssl, shared_buffer, len);
    pthread_mutex_unlock(&buffer_mutex);
    if (rc < 0)
        printf("Failed to send read response\n");
    else
        printf("Sent %zu bytes to reader\n", len);
}

static void handle_read_blocked(SSL *ssl)
{
    unsigned int seen = 0;
    while (!terminate) {
        pthread_mutex_lock(&buffer_mutex);
        while (seen == gen && !terminate) {
            pthread_cond_wait(&buffer_cond, &buffer_mutex);
        }
        if (terminate) {
            pthread_mutex_unlock(&buffer_mutex);
            break;
        }
        seen = gen;
        size_t len = shared_length;
        uint64_t be_len = htobe64((uint64_t)len);
        int rc = ssl_write_all(ssl, &be_len, sizeof(be_len));
        if (rc == 0 && len > 0)
            rc = ssl_write_all(ssl, shared_buffer, len);
        pthread_mutex_unlock(&buffer_mutex);
        if (rc < 0) {
            printf("Failed to send blocked update\n");
            break;
        }
        printf("Blocked reader sent %zu bytes\n", len);
    }
}

// Unified client handler that reads command and dispatches
void *client_handler(void *arg)
{
	SSL *ssl = (SSL *)arg;
	char command[CMD_MAX_LEN];

	// Read the command from client
	memset(command, 0, CMD_MAX_LEN);
	int bytes_read = SSL_read(ssl, command, CMD_MAX_LEN - 1);
	if (bytes_read <= 0) {
		printf("Failed to read command from client\n");
		goto cleanup;
	}

	// Remove trailing newline if present
	size_t len = strlen(command);
	if (len > 0 && command[len - 1] == '\n') {
		command[len - 1] = '\0';
	}

	printf("Client requested operation: '%s'\n", command);

	// Dispatch to appropriate handler
	if (strcmp(command, CMD_WRITE) == 0) {
		handle_write(ssl);
	} else if (strcmp(command, CMD_READ) == 0) {
		handle_read(ssl);
	} else if (strcmp(command, CMD_READ_BLOCKED) == 0) {
		handle_read_blocked(ssl);
	} else {
		printf("Unknown command: '%s'\n", command);
	}

cleanup:
	// After finishing, initiate a graceful shutdown
	if (SSL_shutdown(ssl) == 0) {
		// The first call to SSL_shutdown() sends a close_notify alert to the client
		SSL_shutdown(ssl);
	}

	SSL_free(ssl);
	pthread_exit(NULL);
}

struct server_args {
	int port;
	SSL_CTX *ctx;
};

static void *start_server(void *data)
{
	struct server_args *args = data;
	int server_fd, client_fd;
	struct sockaddr_in address;
	int addrlen = sizeof(address);

	// Create server socket
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	int opt = 1;
	// Set socket options to reuse address
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt failed");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(args->port);

	// Bind the socket
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

	// Listen for client connections
	if (listen(server_fd, 3) < 0) {
		perror("Listen failed");
		exit(EXIT_FAILURE);
	}

	printf("Server listening on port %d...\n", args->port);

	// Accept client connections
	while (!terminate) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(server_fd, &readfds);

		struct timeval timeout = {1, 0};  // Check periodically

		int ready = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
		if (ready < 0) {
			if (errno == EINTR) {
				// Interrupted by a signal
				break;
			}
			perror("select");
			continue;
		} else if (ready == 0) {
			// Timeout occurred, check termination flag
			continue;
		}

		if (FD_ISSET(server_fd, &readfds)) {
			printf("%s:%d fd %d\n", __func__, __LINE__, server_fd);
			if ((client_fd = accept(server_fd, (struct sockaddr *)&address,
						(socklen_t *)&addrlen)) < 0) {
				if (errno == EINTR) {
					// Interrupted by a signal
					break;
				}
				perror("accept");
				continue;
			}
			printf("Client connected\n");
		} else
			continue;

		// Create SSL structure for the accepted connection
		SSL *ssl = SSL_new(args->ctx);
		SSL_set_fd(ssl, client_fd);

		// Perform SSL/TLS handshake
		if (SSL_accept(ssl) <= 0) {
			printf("SSL handshake failed\n");
			ERR_print_errors_fp(stderr);
			SSL_free(ssl);
			close(client_fd);
			continue;
		}

		// Verify client certificate
		X509 *cert = SSL_get_peer_certificate(ssl);
		if (cert == NULL) {
			printf("Client certificate not provided\n");
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(client_fd);
			continue;
		}
		X509_free(cert);

		long verify_result = SSL_get_verify_result(ssl);
		if (verify_result != X509_V_OK) {
			printf("Certificate verification failed: %ld\n",
			       verify_result);
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(client_fd);
			continue;
		}

		// Allocate client handler thread
		pthread_t client_thread;
		if (pthread_create(&client_thread, NULL, client_handler,
				   (void *)ssl) != 0) {
			perror("Failed to create client thread");
			SSL_free(ssl);
			close(client_fd);
			continue;
		}

		pthread_detach(client_thread);
	}

	close(server_fd);

	return NULL;
}

static void print_usage(const char *prog_name)
{
	printf("Usage: %s [OPTIONS]\n", prog_name);
	printf("\nA secure clipboard server for TTY environments.\n");
	printf("\nOptions:\n");
	printf("  -h, --help       Display this help message\n");
	printf("  -v, --version    Display version information\n");
	printf("  -d, --daemon     Run in daemon mode (background)\n");
	printf("\nPort:\n");
	printf("  %d              Server port (all operations)\n", SERVER_PORT);
	printf("\nProtocol:\n");
	printf("  Client connects and sends command: %s, %s, or %s\n",
	       CMD_READ, CMD_WRITE, CMD_READ_BLOCKED);
	printf("\nThe server listens on all interfaces (0.0.0.0) by default.\n");
	printf("Client authentication is required via mutual TLS.\n");
	printf("\n");
}

static void print_version(void)
{
	printf("tty-cb-server version %s\n", VERSION);
	printf("License: %s\n", LICENSE);
}

int main(int argc, char *argv[])
{
	int opt;
	int daemon_mode = 0;

	static struct option long_options[] = {
		{"help",    no_argument, 0, 'h'},
		{"version", no_argument, 0, 'v'},
		{"daemon",  no_argument, 0, 'd'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "hvd", long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'v':
			print_version();
			exit(EXIT_SUCCESS);
		case 'd':
			daemon_mode = 1;
			break;
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (daemon_mode) {
		// Simple daemonization
		pid_t pid = fork();
		if (pid < 0) {
			perror("Failed to fork");
			exit(EXIT_FAILURE);
		}
		if (pid > 0) {
			// Parent process exits
			printf("Server started in background with PID: %d\n", pid);
			exit(EXIT_SUCCESS);
		}
		// Child continues
		setsid();
		if (chdir("/") < 0) {
			perror("Failed to change directory");
			exit(EXIT_FAILURE);
		}
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	// Set up signal handling
	struct sigaction sa;
	sa.sa_handler = handle_sigint;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

	SSL_CTX *ctx = init_ssl_context();
	struct server_args args = { .port = SERVER_PORT, .ctx = ctx };

	// Start server
	pthread_t server_thread;
	if (pthread_create(&server_thread, NULL, start_server, &args) != 0) {
		perror("Failed to create server thread");
		exit(EXIT_FAILURE);
	}

	pthread_join(server_thread, NULL);

	SSL_CTX_free(ctx);
	return 0;
}
