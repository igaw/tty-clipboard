/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#include "config.h"
#include "tty-clipboard.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <endian.h>

// Forward declaration to avoid implicit declaration warnings
void handle_error(const char *msg);

volatile sig_atomic_t terminate = 0;

// Signal handler
void handle_sigint(int sig __attribute__((unused)))
{
	terminate = 1; // Set the termination flag
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <protobuf-c/protobuf-c.h>
#include "clipboard.pb-c.h"
#pragma GCC diagnostic pop

static void pb_send_envelope(SSL *ssl, Ttycb__Envelope *env)
{
	uint8_t *buf = NULL;
	size_t sz = ttycb__envelope__get_packed_size(env);
	buf = malloc(sz);
	if (!buf)
		handle_error("malloc");
	ttycb__envelope__pack(env, buf);
	uint64_t pfx = htobe64((uint64_t)sz);
	if (SSL_write(ssl, &pfx, sizeof(pfx)) <= 0)
		handle_error("SSL_write prefix");
	size_t total = 0;
	while (total < sz) {
		int w = SSL_write(ssl, buf + total, (int)(sz - total));
		if (w <= 0)
			handle_error("SSL_write msg");
		total += (size_t)w;
	}
	free(buf);
}

static Ttycb__Envelope *pb_recv_envelope(SSL *ssl)
{
	uint64_t be = 0;
	int r = SSL_read(ssl, &be, sizeof(be));
	if (r <= 0) {
		// Check if this is a clean shutdown or actual error
		if (terminate ||
		    SSL_get_error(ssl, r) == SSL_ERROR_ZERO_RETURN) {
			return NULL; // Clean connection close or termination signal
		}
		handle_error("SSL_read prefix");
	}
	size_t sz = (size_t)be64toh(be);
	if (sz == 0)
		return NULL;
	uint8_t *buf = malloc(sz);
	if (!buf)
		handle_error("malloc");
	size_t tot = 0;
	while (tot < sz) {
		int rr = SSL_read(ssl, buf + tot, (int)(sz - tot));
		if (rr <= 0)
			handle_error("SSL_read msg");
		tot += (size_t)rr;
	}
	Ttycb__Envelope *e = ttycb__envelope__unpack(NULL, sz, buf);
	free(buf);
	if (!e)
		handle_error("unpack");
	return e;
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

static void print_usage(const char *prog_name)
{
	printf("Usage: %s [OPTIONS] <read|write> <server_ip>\n", prog_name);
	printf("\nA secure clipboard client for TTY environments.\n");
	printf("\nCommands:\n");
	printf("  read             Read clipboard content from server\n");
	printf("  write            Write stdin content to server clipboard\n");
	printf("  read_blocked     Subscribe to clipboard updates (blocking)\n");
	printf("\nOptions:\n");
	printf("  -h, --help       Display this help message\n");
	printf("  -v, --version    Display version information\n");
	printf("\nExamples:\n");
	printf("  %s write 192.168.1.100          # Write stdin to clipboard\n",
	       prog_name);
	printf("  %s read 192.168.1.100           # Read clipboard to stdout\n",
	       prog_name);
	printf("  %s read_blocked 192.168.1.100   # Subscribe to updates\n",
	       prog_name);
	printf("\n");
}

static void print_version(void)
{
	printf("tty-cb-client version %s\n", VERSION);
	printf("License: %s\n", LICENSE);
}

static void setup_signal_handler(void)
{
	struct sigaction sa;
	sa.sa_handler = handle_sigint;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
}

static uint64_t generate_client_id(void)
{
	uint64_t client_id;
	if (RAND_bytes((unsigned char *)&client_id, sizeof(client_id)) != 1) {
		fprintf(stderr, "Failed to generate client_id\n");
		exit(EXIT_FAILURE);
	}
	if (client_id == 0)
		client_id = 1; // ensure non-zero
	return client_id;
}

static SSL *connect_to_server(const char *server_ip, int port, SSL_CTX *ctx,
			       int *sock_fd)
{
	// Create socket and connect to server
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port);
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
		exit(EXIT_FAILURE);
	}

	*sock_fd = sock;
	return ssl;
}

static uint8_t *read_stdin_to_buffer(size_t *out_size)
{
	size_t cap = 4096, used = 0;
	uint8_t *buf = malloc(cap);
	if (!buf)
		handle_error("malloc");
	while (1) {
		if (used == cap) {
			cap *= 2;
			uint8_t *t = realloc(buf, cap);
			if (!t)
				handle_error("realloc");
			buf = t;
		}
		ssize_t r = read(STDIN_FILENO, buf + used, cap - used);
		if (r < 0)
			handle_error("read");
		if (r == 0)
			break;
		used += (size_t)r;
	}
	*out_size = used;
	return buf;
}

static void do_write(SSL *ssl, uint64_t client_id, SSL_CTX *ctx, int sock)
{
	size_t used;
	uint8_t *buf = read_stdin_to_buffer(&used);

	Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
	Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT;
	wr.data.data = buf;
	wr.data.len = used;
	wr.client_id = client_id;
	env.write = &wr;
	env.body_case = TTYCB__ENVELOPE__BODY_WRITE;
	pb_send_envelope(ssl, &env);
	free(buf);

	Ttycb__Envelope *resp = pb_recv_envelope(ssl);
	if (!resp || resp->body_case != TTYCB__ENVELOPE__BODY_WRITE_RESP ||
	    !resp->write_resp || !resp->write_resp->ok) {
		ttycb__envelope__free_unpacked(resp, NULL);
		fprintf(stderr, "Write failed\n");
		SSL_free(ssl);
		close(sock);
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}
	ttycb__envelope__free_unpacked(resp, NULL);
}

static void do_read(SSL *ssl, SSL_CTX *ctx, int sock)
{
	Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
	Ttycb__ReadRequest rd = TTYCB__READ_REQUEST__INIT;
	env.read = &rd;
	env.body_case = TTYCB__ENVELOPE__BODY_READ;
	pb_send_envelope(ssl, &env);

	Ttycb__Envelope *resp = pb_recv_envelope(ssl);
	if (!resp || resp->body_case != TTYCB__ENVELOPE__BODY_DATA ||
	    !resp->data) {
		ttycb__envelope__free_unpacked(resp, NULL);
		fprintf(stderr, "Read failed\n");
		SSL_free(ssl);
		close(sock);
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}
	fwrite(resp->data->data.data, 1, resp->data->data.len, stdout);
	fflush(stdout);
	ttycb__envelope__free_unpacked(resp, NULL);
}

static void do_write_read(SSL *ssl, uint64_t client_id, SSL_CTX *ctx, int sock)
{
	size_t used;
	uint8_t *buf = read_stdin_to_buffer(&used);

	Ttycb__Envelope envw = TTYCB__ENVELOPE__INIT;
	Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT;
	wr.data.data = buf;
	wr.data.len = used;
	wr.client_id = client_id;
	envw.write = &wr;
	envw.body_case = TTYCB__ENVELOPE__BODY_WRITE;
	pb_send_envelope(ssl, &envw);

	Ttycb__Envelope *wresp = pb_recv_envelope(ssl);
	if (!wresp || wresp->body_case != TTYCB__ENVELOPE__BODY_WRITE_RESP ||
	    !wresp->write_resp || !wresp->write_resp->ok) {
		ttycb__envelope__free_unpacked(wresp, NULL);
		fprintf(stderr, "Write failed\n");
		SSL_free(ssl);
		close(sock);
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}
	ttycb__envelope__free_unpacked(wresp, NULL);
	free(buf);

	Ttycb__Envelope envr = TTYCB__ENVELOPE__INIT;
	Ttycb__ReadRequest rd = TTYCB__READ_REQUEST__INIT;
	envr.read = &rd;
	envr.body_case = TTYCB__ENVELOPE__BODY_READ;
	pb_send_envelope(ssl, &envr);

	Ttycb__Envelope *rresp = pb_recv_envelope(ssl);
	if (!rresp || rresp->body_case != TTYCB__ENVELOPE__BODY_DATA ||
	    !rresp->data) {
		ttycb__envelope__free_unpacked(rresp, NULL);
		fprintf(stderr, "Read failed\n");
		SSL_free(ssl);
		close(sock);
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}
	fwrite(rresp->data->data.data, 1, rresp->data->data.len, stdout);
	fflush(stdout);
	ttycb__envelope__free_unpacked(rresp, NULL);
}

static void do_subscribe(SSL *ssl, uint64_t client_id)
{
	Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
	Ttycb__SubscribeRequest sub = TTYCB__SUBSCRIBE_REQUEST__INIT;
	sub.client_id = client_id;
	env.subscribe = &sub;
	env.body_case = TTYCB__ENVELOPE__BODY_SUBSCRIBE;
	pb_send_envelope(ssl, &env);

	// Loop receiving data frames until connection closes or terminate signal
	while (!terminate) {
		Ttycb__Envelope *resp = pb_recv_envelope(ssl);
		if (!resp)
			break; // connection closed
		if (resp->body_case == TTYCB__ENVELOPE__BODY_DATA &&
		    resp->data) {
			fwrite(resp->data->data.data, 1,
			       resp->data->data.len, stdout);
			fflush(stdout);
		}
		ttycb__envelope__free_unpacked(resp, NULL);
	}
}

static void do_write_subscribe(SSL *ssl, uint64_t client_id, SSL_CTX *ctx,
				int sock)
{
	size_t used;
	uint8_t *buf = read_stdin_to_buffer(&used);

	Ttycb__Envelope envw = TTYCB__ENVELOPE__INIT;
	Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT;
	wr.data.data = buf;
	wr.data.len = used;
	wr.client_id = client_id;
	envw.write = &wr;
	envw.body_case = TTYCB__ENVELOPE__BODY_WRITE;
	pb_send_envelope(ssl, &envw);

	Ttycb__Envelope *wresp = pb_recv_envelope(ssl);
	if (!wresp || wresp->body_case != TTYCB__ENVELOPE__BODY_WRITE_RESP ||
	    !wresp->write_resp || !wresp->write_resp->ok) {
		ttycb__envelope__free_unpacked(wresp, NULL);
		fprintf(stderr, "Write failed\n");
		SSL_free(ssl);
		close(sock);
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}
	ttycb__envelope__free_unpacked(wresp, NULL);
	free(buf);

	// Now subscribe
	do_subscribe(ssl, client_id);
}

int main(int argc, char *argv[])
{
	const char *role = NULL;
	const char *server_ip = NULL;
	int opt;

	static struct option long_options[] = { { "help", no_argument, 0, 'h' },
						{ "version", no_argument, 0,
						  'v' },
						{ 0, 0, 0, 0 } };

	while ((opt = getopt_long(argc, argv, "hv", long_options, NULL)) !=
	       -1) {
		switch (opt) {
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
	if (strcmp(role, "read") != 0 && strcmp(role, "write") != 0 &&
	    strcmp(role, "write_read") != 0 &&
	    strcmp(role, "read_blocked") != 0 &&
	    strcmp(role, "write_subscribe") != 0) {
		fprintf(stderr,
			"Error: Command must be 'read', 'write', 'write_read', 'read_blocked', or 'write_subscribe'\n\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	// Set up signal handling
	setup_signal_handler();

	// Generate a random non-zero client_id
	uint64_t client_id = generate_client_id();

	// Initialize SSL context
	SSL_CTX *ctx = init_ssl_context();

	// Connect to server
	int sock;
	SSL *ssl = connect_to_server(server_ip, SERVER_PORT, ctx, &sock);

	// Execute the requested role
	if (strcmp(role, "write") == 0) {
		do_write(ssl, client_id, ctx, sock);
	} else if (strcmp(role, "read") == 0) {
		do_read(ssl, ctx, sock);
	} else if (strcmp(role, "write_read") == 0) {
		do_write_read(ssl, client_id, ctx, sock);
	} else if (strcmp(role, "read_blocked") == 0) {
		do_subscribe(ssl, client_id);
	} else if (strcmp(role, "write_subscribe") == 0) {
		do_write_subscribe(ssl, client_id, ctx, sock);
	}

	// Initiate graceful shutdown after all data is sent
	if (SSL_shutdown(ssl) == 0) {
		// The first call to SSL_shutdown() sends a close_notify alert to the server
		SSL_shutdown(ssl);
	}

	// Clean up
	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	return 0;
}
