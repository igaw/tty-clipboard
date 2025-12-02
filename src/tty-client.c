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
#include <stdint.h>
#include <endian.h>

// Forward declaration to avoid implicit declaration warnings
void handle_error(const char *msg);

#if HAVE_PROTOBUF
#include <protobuf-c/protobuf-c.h>
#include "clipboard.pb-c.h"

static void pb_send_envelope(SSL *ssl, Ttycb__Envelope *env)
{
	uint8_t *buf = NULL; size_t sz = ttycb__envelope__get_packed_size(env);
	buf = malloc(sz); if (!buf) handle_error("malloc");
	ttycb__envelope__pack(env, buf);
	uint64_t pfx = htobe64((uint64_t)sz);
	if (SSL_write(ssl, &pfx, sizeof(pfx)) <= 0) handle_error("SSL_write prefix");
	size_t total = 0; while (total < sz) { int w = SSL_write(ssl, buf+total, (int)(sz-total)); if (w<=0) handle_error("SSL_write msg"); total += (size_t)w; }
	free(buf);
}

static Ttycb__Envelope *pb_recv_envelope(SSL *ssl)
{
	uint64_t be=0; if (SSL_read(ssl, &be, sizeof(be)) <= 0) handle_error("SSL_read prefix");
	size_t sz=(size_t)be64toh(be); if (sz==0) return NULL;
	uint8_t *buf = malloc(sz); if (!buf) handle_error("malloc"); size_t tot=0; while (tot<sz){int r=SSL_read(ssl, buf+tot, (int)(sz-tot)); if (r<=0) handle_error("SSL_read msg"); tot+=(size_t)r;}
	Ttycb__Envelope *e = ttycb__envelope__unpack(NULL, sz, buf); free(buf); if (!e) handle_error("unpack"); return e;
}
#endif

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
	uint64_t be_len = 0;
	if (SSL_read(ssl, &be_len, sizeof(be_len)) <= 0) {
		handle_error("SSL_read length");
	}
	size_t len = (size_t)be64toh(be_len);
	if (len == 0) return; // empty clipboard
	unsigned char *buf = malloc(len);
	if (!buf) handle_error("malloc");
	size_t total = 0;
	while (total < len) {
		int r = SSL_read(ssl, buf + total, (int)(len - total));
		if (r <= 0) handle_error("SSL_read payload");
		total += (size_t)r;
	}
	fwrite(buf, 1, len, stdout);
	if (buf[len-1] != '\n')
		fflush(stdout);
	free(buf);
}

void write_to_server(SSL *ssl)
{
	// Read all stdin into a dynamic buffer
	size_t cap = 4096, used = 0;
	unsigned char *buf = malloc(cap);
	if (!buf) handle_error("malloc");
	while (1) {
		if (used == cap) {
			cap *= 2;
			unsigned char *tmp = realloc(buf, cap);
			if (!tmp) handle_error("realloc");
			buf = tmp;
		}
		ssize_t r = read(STDIN_FILENO, buf + used, cap - used);
		if (r < 0) handle_error("read stdin");
		if (r == 0) break; // EOF
		used += (size_t)r;
	}
	uint64_t be_len = htobe64((uint64_t)used);
	if (SSL_write(ssl, &be_len, sizeof(be_len)) <= 0) handle_error("SSL_write length");
	size_t total = 0;
	while (total < used) {
		int w = SSL_write(ssl, buf + total, (int)(used - total));
		if (w <= 0) handle_error("SSL_write payload");
		total += (size_t)w;
	}
	// Read status byte from server (0=success, 1=reject)
	unsigned char status = 0;
	int r = SSL_read(ssl, &status, 1);
	if (r <= 0) handle_error("SSL_read write-status");
	if (status != 0) {
		fprintf(stderr, "Write rejected by server (oversize or error)\n");
		free(buf);
		exit(EXIT_FAILURE);
	}
	free(buf);
}

void read_from_server_blocked(SSL *ssl)
{
	while (!terminate) {
		uint64_t be_len = 0;
		int r = SSL_read(ssl, &be_len, sizeof(be_len));
		if (r <= 0) break; // connection closed
		size_t len = (size_t)be64toh(be_len);
		if (len == 0) continue; // skip empty
		unsigned char *buf = malloc(len);
		if (!buf) handle_error("malloc");
		size_t total = 0;
		while (total < len) {
			int rr = SSL_read(ssl, buf + total, (int)(len - total));
			if (rr <= 0) { free(buf); handle_error("SSL_read blocked payload"); }
			total += (size_t)rr;
		}
		fwrite(buf, 1, len, stdout);
		fflush(stdout);
		free(buf);
	}
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
	printf("License: %s\n", LICENSE);
}

int main(int argc, char *argv[])
{
	int opt;
	int sync = 0;
	const char *role = NULL;
	const char *server_ip = NULL;
    int use_protobuf = 0;

	static struct option long_options[] = {
		{"sync",    no_argument, 0, 's'},
		{"help",    no_argument, 0, 'h'},
		{"version", no_argument, 0, 'v'},
		{"protobuf", no_argument, 0, 1000},
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
		case 1000:
			use_protobuf = 1;
			break;
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
	if (strcmp(role, "read") != 0 && strcmp(role, "write") != 0
#if HAVE_PROTOBUF
    && !(use_protobuf && strcmp(role, "write_read") == 0)
#endif
	    ) {
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

	// Determine command to send (classic mode)
	const char *command = NULL;
	if (!use_protobuf) {
		if (strcmp(role, "read") == 0) {
			if (sync)
				command = CMD_READ_BLOCKED;
			else
				command = CMD_READ;
		} else {
			command = CMD_WRITE;
		}
	}

	int server_port = SERVER_PORT;

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

	// Classic vs protobuf
	if (!use_protobuf) {
		// Send command to server (classic)
		char cmd_buffer[CMD_MAX_LEN];
		snprintf(cmd_buffer, CMD_MAX_LEN, "%s\n", command);
		if (SSL_write(ssl, cmd_buffer, strlen(cmd_buffer)) <= 0) {
			perror("Failed to send command to server");
			SSL_free(ssl);
			close(sock);
			SSL_CTX_free(ctx);
			exit(EXIT_FAILURE);
		}

		if (!strcmp(role, "read")) {
			if (sync)
				read_from_server_blocked(ssl);
			else
				read_from_server(ssl);
		} else if (!strcmp(role, "write")) {
			write_to_server(ssl);
		}
	} else {
#if HAVE_PROTOBUF
		if (strcmp(role, "write") == 0) {
			// Read stdin
			size_t cap=4096, used=0; uint8_t *buf = malloc(cap); if (!buf) handle_error("malloc");
			while (1){ if (used==cap){cap*=2; uint8_t *t=realloc(buf,cap); if(!t) handle_error("realloc"); buf=t;} ssize_t r=read(STDIN_FILENO, buf+used, cap-used); if (r<0) handle_error("read"); if (r==0) break; used+=(size_t)r; }
			Ttycb__Envelope env = TTYCB__ENVELOPE__INIT; Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT; wr.data.data = buf; wr.data.len = used; env.write = &wr; env.body_case = TTYCB__ENVELOPE__BODY_WRITE; pb_send_envelope(ssl, &env); free(buf);
			Ttycb__Envelope *resp = pb_recv_envelope(ssl); if (!resp || resp->body_case != TTYCB__ENVELOPE__BODY_WRITE_RESP || !resp->write_resp || !resp->write_resp->ok){ ttycb__envelope__free_unpacked(resp,NULL); fprintf(stderr, "Write failed\n"); SSL_free(ssl); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);} ttycb__envelope__free_unpacked(resp,NULL);
		} else if (strcmp(role, "read") == 0) {
			Ttycb__Envelope env = TTYCB__ENVELOPE__INIT; Ttycb__ReadRequest rd = TTYCB__READ_REQUEST__INIT; env.read = &rd; env.body_case = TTYCB__ENVELOPE__BODY_READ; pb_send_envelope(ssl, &env);
			Ttycb__Envelope *resp = pb_recv_envelope(ssl); if (!resp || resp->body_case != TTYCB__ENVELOPE__BODY_DATA || !resp->data){ ttycb__envelope__free_unpacked(resp,NULL); fprintf(stderr, "Read failed\n"); SSL_free(ssl); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);} fwrite(resp->data->data.data,1,resp->data->data.len,stdout); fflush(stdout); ttycb__envelope__free_unpacked(resp,NULL);
		} else if (strcmp(role, "write_read") == 0) {
			// Write stdin then read back
			size_t cap=4096, used=0; uint8_t *buf = malloc(cap); if (!buf) handle_error("malloc"); while (1){ if (used==cap){cap*=2; uint8_t *t=realloc(buf,cap); if(!t) handle_error("realloc"); buf=t;} ssize_t r=read(STDIN_FILENO, buf+used, cap-used); if (r<0) handle_error("read"); if (r==0) break; used+=(size_t)r; }
			Ttycb__Envelope envw = TTYCB__ENVELOPE__INIT; Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT; wr.data.data=buf; wr.data.len=used; envw.write=&wr; envw.body_case=TTYCB__ENVELOPE__BODY_WRITE; pb_send_envelope(ssl, &envw); Ttycb__Envelope *wresp=pb_recv_envelope(ssl); if (!wresp || wresp->body_case!=TTYCB__ENVELOPE__BODY_WRITE_RESP || !wresp->write_resp || !wresp->write_resp->ok){ ttycb__envelope__free_unpacked(wresp,NULL); fprintf(stderr, "Write failed\n"); SSL_free(ssl); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);} ttycb__envelope__free_unpacked(wresp,NULL); free(buf);
			Ttycb__Envelope envr = TTYCB__ENVELOPE__INIT; Ttycb__ReadRequest rd = TTYCB__READ_REQUEST__INIT; envr.read=&rd; envr.body_case=TTYCB__ENVELOPE__BODY_READ; pb_send_envelope(ssl, &envr); Ttycb__Envelope *rresp=pb_recv_envelope(ssl); if (!rresp || rresp->body_case!=TTYCB__ENVELOPE__BODY_DATA || !rresp->data){ ttycb__envelope__free_unpacked(rresp,NULL); fprintf(stderr, "Read failed\n"); SSL_free(ssl); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);} fwrite(rresp->data->data.data,1,rresp->data->data.len,stdout); fflush(stdout); ttycb__envelope__free_unpacked(rresp,NULL);
		}
#endif
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
