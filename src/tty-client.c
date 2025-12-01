/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#include "tty-clipboard.h"
#include "config.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

volatile sig_atomic_t terminate = 0;

// Signal handler
void handle_sigint(int sig __attribute__((unused)))
{
	terminate = 1; // Set the termination flag
}


SSL_CTX *init_ssl_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	_cleanup_free_ char *path = create_xdg_config_path("tty-clipboard");
	_cleanup_free_ char *crt = NULL;
	_cleanup_free_ char *key = NULL;
	_cleanup_free_ char *ca = NULL;

	if (asprintf(&crt, "%s/certs/client.crt", path) < 0) {
		perror("Unable to create path for client certificate\n");
		exit(EXIT_FAILURE);
	}

	if (asprintf(&key, "%s/keys/client.key", path) < 0) {
		perror("Unable to create path for client key\n");
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
	method = TLS_client_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Load the client's certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM) <= 0) {
		perror("Unable to load client certificate");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		perror("Unable to load client private key");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Load the CA certificate to verify the server's certificate
	if (SSL_CTX_load_verify_locations(ctx, ca, NULL) <= 0) {
		perror("Unable to load CA certificate");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Enable server certificate verification
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	return ctx;
}

void handle_error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

void read_from_server(SSL *ssl)
{
	char buffer[BUFFER_SIZE];
	ssize_t bytes_read;

	while ((bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1)) > 0) {
		buffer[bytes_read] = 0;
		fprintf(stdout, "%s\n", buffer);
		fflush(stdout);
	}
	if (bytes_read < 0)
		handle_error("SSL_read");
}

void write_to_server(SSL *ssl)
{
	char buffer[BUFFER_SIZE];
	ssize_t bytes_read, bytes_written;

	while ((bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE - 1)) > 0) {
		buffer[bytes_read] = 0;
		size_t len = strlen(buffer);
		if (len > 0 && buffer[len - 1] == '\n') {
			buffer[len - 1] = '\0';
			len--;
		}
		bytes_written = SSL_write(ssl, buffer, len);
		if (bytes_written <= 0)
			handle_error("error writing to server");
	}
	if (bytes_read < 0)
		handle_error("read from stdin");
}

static void print_usage(const char *prog_name)
{
	printf("Usage: %s [OPTIONS] <read|write> <server_ip>\n", prog_name);
	printf("\nA secure clipboard client for TTY environments.\n");
	printf("\nCommands:\n");
	printf("  read             Read clipboard content from server\n");
	printf("  write            Write stdin content to server clipboard\n");
	printf("\nOptions:\n");
	printf("  -s, --sync       Use synchronous/blocking read mode\n");
	printf("  -h, --help       Display this help message\n");
	printf("  -v, --version    Display version information\n");
	printf("\nExamples:\n");
	printf("  %s write 192.168.1.100          # Write stdin to clipboard\n", prog_name);
	printf("  %s read 192.168.1.100           # Read clipboard to stdout\n", prog_name);
	printf("  %s read 192.168.1.100 --sync    # Read with sync mode\n", prog_name);
	printf("\n");
}

static void print_version(void)
{
	printf("tty-cb-client version %s\n", VERSION);
	printf("License: GPL-2.0-only\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int sync = 0;
	const char *role = NULL;
	const char *server_ip = NULL;

	static struct option long_options[] = {
		{"sync",    no_argument, 0, 's'},
		{"help",    no_argument, 0, 'h'},
		{"version", no_argument, 0, 'v'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "shv", long_options, NULL)) != -1) {
		switch (opt) {
		case 's':
			sync = 1;
			break;
		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'v':
			print_version();
			exit(EXIT_SUCCESS);
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	// Parse positional arguments
	if (optind + 2 > argc) {
		fprintf(stderr, "Error: Missing required arguments\n\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	role = argv[optind];
	server_ip = argv[optind + 1];

	// Validate role
	if (strcmp(role, "read") != 0 && strcmp(role, "write") != 0) {
		fprintf(stderr, "Error: Command must be 'read' or 'write'\n\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	// Set up signal handling
	struct sigaction sa;
	sa.sa_handler = handle_sigint;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

	int server_port;

	if (!strcmp(role, "read")) {
		if (sync)
			server_port = READ_BLOCKED_PORT;
		else
			server_port = READ_PORT;
	} else
		server_port = WRITE_PORT;

	SSL_CTX *ctx = init_ssl_context();

	// Create socket and connect to server
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(server_port);
	inet_pton(AF_INET, server_ip, &server_address.sin_addr);

	// Create SSL object and establish SSL connection
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);
	if (connect(sock, (struct sockaddr *)&server_address,
		    sizeof(server_address)) < 0) {
		perror("Connection failed");
		exit(EXIT_FAILURE);
	}

	// Perform SSL handshake
	if (SSL_connect(ssl) <= 0) {
		perror("SSL connection failed");
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		close(sock);
		exit(EXIT_FAILURE);
	}

	// Verify the server's certificate
	long verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		fprintf(stderr, "Server certificate verification failed: %ld\n",
			verify_result);
		SSL_free(ssl);
		close(sock);
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}

	// Send or receive data based on the role
	if (!strcmp(role, "read")) {
		read_from_server(ssl);
	} else if (!strcmp(role, "write")) {
		write_to_server(ssl);
	}

	// Initiate graceful shutdown after all data is sent
	if (SSL_shutdown(ssl) == 0) {
		// The first call to SSL_shutdown() sends a close_notify alert to the server
		if (SSL_shutdown(ssl) == 1) {
			// printf("Connection shutdown successfully.\n");
		}
	}

	// Clean up
	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	return 0;
}
