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
#include <errno.h>
#include <sys/socket.h>
#include <mbedtls/version.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <endian.h>

// Forward declaration to avoid implicit declaration warnings
void handle_error(const char *msg);

// Helper to print mbedTLS errors
static void print_mbedtls_error(const char *context, int errcode)
{
	char error_buf[100];
	mbedtls_strerror(errcode, error_buf, sizeof(error_buf));
	LOG_ERROR("%s: -0x%04x (%s)", context, -errcode, error_buf);
	fprintf(stderr, "%s: -0x%04x (%s)\n", context, -errcode, error_buf);
}

// Custom send/recv callbacks for mbedTLS that work with raw socket fds
static int ssl_send_callback(void *ctx, const unsigned char *buf, size_t len)
{
	int fd = (int)(intptr_t)ctx;
	ssize_t ret = send(fd, buf, len, 0);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	return (int)ret;
}

static int ssl_recv_callback(void *ctx, unsigned char *buf, size_t len)
{
	int fd = (int)(intptr_t)ctx;
	ssize_t ret = recv(fd, buf, len, 0);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_READ;
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	if (ret == 0)
		return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
	return (int)ret;
}

// mbedTLS context structures
typedef struct {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt clicert;
	mbedtls_pk_context pkey;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} ssl_context_t;

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

static void pb_send_envelope(ssl_context_t *ssl_ctx, Ttycb__Envelope *env)
{
	uint8_t *buf = NULL;
	size_t sz = ttycb__envelope__get_packed_size(env);
	buf = malloc(sz);
	if (!buf)
		handle_error("malloc");
	ttycb__envelope__pack(env, buf);
	uint64_t pfx = htobe64((uint64_t)sz);
	if (mbedtls_ssl_write(&ssl_ctx->ssl, (unsigned char *)&pfx, sizeof(pfx)) <= 0)
		handle_error("mbedtls_ssl_write prefix");
	size_t total = 0;
	while (total < sz) {
		int w = mbedtls_ssl_write(&ssl_ctx->ssl, buf + total, sz - total);
		if (w <= 0)
			handle_error("mbedtls_ssl_write msg");
		total += (size_t)w;
	}
	free(buf);
}

static Ttycb__Envelope *pb_recv_envelope(ssl_context_t *ssl_ctx)
{
	uint64_t be = 0;
	int r = mbedtls_ssl_read(&ssl_ctx->ssl, (unsigned char *)&be, sizeof(be));
	if (r <= 0) {
		// Check if this is a clean shutdown or actual error
		if (terminate || r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			return NULL; // Clean connection close or termination signal
		}
		handle_error("mbedtls_ssl_read prefix");
	}
	size_t sz = (size_t)be64toh(be);
	if (sz == 0)
		return NULL;
	uint8_t *buf = malloc(sz);
	if (!buf)
		handle_error("malloc");
	size_t tot = 0;
	while (tot < sz) {
		int rr = mbedtls_ssl_read(&ssl_ctx->ssl, buf + tot, sz - tot);
		if (rr <= 0)
			handle_error("mbedtls_ssl_read msg");
		tot += (size_t)rr;
	}
	Ttycb__Envelope *e = ttycb__envelope__unpack(NULL, sz, buf);
	free(buf);
	if (!e)
		handle_error("unpack");
	return e;
}

ssl_context_t *init_ssl_context()
{
	int ret;
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

	ssl_context_t *ssl_ctx = calloc(1, sizeof(ssl_context_t));
	if (!ssl_ctx) {
		perror("Unable to allocate SSL context");
		exit(EXIT_FAILURE);
	}

	// Initialize mbedTLS structures
	mbedtls_ssl_init(&ssl_ctx->ssl);
	mbedtls_ssl_config_init(&ssl_ctx->conf);
	mbedtls_x509_crt_init(&ssl_ctx->cacert);
	mbedtls_x509_crt_init(&ssl_ctx->clicert);
	mbedtls_pk_init(&ssl_ctx->pkey);
	mbedtls_entropy_init(&ssl_ctx->entropy);
	mbedtls_ctr_drbg_init(&ssl_ctx->ctr_drbg);

	LOG_DEBUG("mbedTLS structures initialized");

	// Seed the RNG
	const char *pers = "tty_clipboard_client";
	ret = mbedtls_ctr_drbg_seed(&ssl_ctx->ctr_drbg, mbedtls_entropy_func,
				    &ssl_ctx->entropy,
				    (const unsigned char *)pers, strlen(pers));
	if (ret != 0) {
		LOG_ERROR("mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}
	LOG_DEBUG("RNG initialized");

	// Load the CA certificate
	LOG_DEBUG("Loading CA certificate from %s", ca);
	ret = mbedtls_x509_crt_parse_file(&ssl_ctx->cacert, ca);
	if (ret != 0) {
		LOG_ERROR("Unable to load CA certificate from %s: -0x%04x", ca, -ret);
		fprintf(stderr, "Unable to load CA certificate: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

	// Load the client certificate
	LOG_DEBUG("Loading client certificate from %s", crt);
	ret = mbedtls_x509_crt_parse_file(&ssl_ctx->clicert, crt);
	if (ret != 0) {
		LOG_ERROR("Unable to load client certificate from %s: -0x%04x", crt, -ret);
		fprintf(stderr, "Unable to load client certificate: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

	// Load the client private key
	LOG_DEBUG("Loading client private key from %s", key);
#ifdef MBEDTLS_3X
	// mbedTLS 3.x requires RNG parameters
	ret = mbedtls_pk_parse_keyfile(&ssl_ctx->pkey, key, NULL,
				      mbedtls_ctr_drbg_random, &ssl_ctx->ctr_drbg);
#else
	// mbedTLS 2.x uses simpler API
	ret = mbedtls_pk_parse_keyfile(&ssl_ctx->pkey, key, NULL);
#endif
	if (ret != 0) {
		LOG_ERROR("Unable to load client private key from %s: -0x%04x", key, -ret);
		fprintf(stderr, "Unable to load client private key: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

	// Configure SSL/TLS defaults for client
	ret = mbedtls_ssl_config_defaults(&ssl_ctx->conf,
					  MBEDTLS_SSL_IS_CLIENT,
					  MBEDTLS_SSL_TRANSPORT_STREAM,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		LOG_ERROR("mbedtls_ssl_config_defaults failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ssl_config_defaults failed: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}
	LOG_DEBUG("SSL config initialized with defaults");

	// Set RNG and I/O callbacks
	mbedtls_ssl_conf_rng(&ssl_ctx->conf, mbedtls_ctr_drbg_random, &ssl_ctx->ctr_drbg);

	// Optional debug: enable detailed mbedTLS logging when MBEDTLS_DEBUG env var is set
	const char *dbg = getenv("MBEDTLS_DEBUG");
	if (dbg && *dbg) {
		mbedtls_debug_set_threshold(4);
		mbedtls_ssl_conf_dbg(&ssl_ctx->conf, mbedtls_debug_print_msg, NULL);
	}

	// Set CA certificate for verification
	mbedtls_ssl_conf_ca_chain(&ssl_ctx->conf, &ssl_ctx->cacert, NULL);

	// Set client certificate and private key
	ret = mbedtls_ssl_conf_own_cert(&ssl_ctx->conf, &ssl_ctx->clicert, &ssl_ctx->pkey);
	if (ret != 0) {
		LOG_ERROR("mbedtls_ssl_conf_own_cert failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ssl_conf_own_cert failed: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

	// Require server certificate verification
	mbedtls_ssl_conf_authmode(&ssl_ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	LOG_DEBUG("SSL context configured with certificates");

	// Setup the SSL context
	ret = mbedtls_ssl_setup(&ssl_ctx->ssl, &ssl_ctx->conf);
	if (ret != 0) {
		LOG_ERROR("mbedtls_ssl_setup failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ssl_setup failed: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

#ifdef MBEDTLS_3X
	// mbedTLS 3.x requires setting hostname, matching the CN in our certificates
	ret = mbedtls_ssl_set_hostname(&ssl_ctx->ssl, "tty-clipboard-server");
	if (ret != 0) {
		LOG_ERROR("mbedtls_ssl_set_hostname failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ssl_set_hostname failed: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}
	LOG_DEBUG("Hostname set to 'tty-clipboard-server' for certificate verification");
#endif

	return ssl_ctx;
}

void handle_error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static void print_usage(const char *prog_name)
{
	printf("Usage: %s [OPTIONS] <command>\n", prog_name);
	printf("\nA secure clipboard client for TTY environments.\n");
	printf("\nCommands:\n");
	printf("  read             Read clipboard content from server\n");
	printf("  write            Write stdin content to server clipboard\n");
	printf("  write_read       Write then read from clipboard\n");
	printf("  read_blocked     Subscribe to clipboard updates (blocking)\n");
	printf("  write_subscribe  Write then subscribe to updates\n");
	printf("\nOptions:\n");
	printf("  -h, --help       Display this help message\n");
	printf("  -V, --version    Display version information\n");
	printf("  -v, --verbose    Enable verbose logging (repeat for more detail)\n");
	printf("  -s, --server IP  Server IP address (default: 127.0.0.1)\n");
	printf("  -p, --port PORT  Server port (default: %d)\n", SERVER_PORT);
	printf("\nExamples:\n");
	printf("  %s write                          # Write to localhost:5457\n",
	       prog_name);
	printf("  %s read                           # Read from localhost:5457\n",
	       prog_name);
	printf("  %s -s 192.168.1.100 write         # Write to remote server\n",
	       prog_name);
	printf("  %s -s 10.0.0.1 -p 9999 read       # Custom server and port\n",
	       prog_name);
	printf("  %s -v read                        # Read with INFO logging\n",
	       prog_name);
	printf("  %s -v -v write                    # Write with DEBUG logging\n",
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

static uint64_t generate_client_id(ssl_context_t *ssl_ctx)
{
	uint64_t client_id;
	if (mbedtls_ctr_drbg_random(&ssl_ctx->ctr_drbg, (unsigned char *)&client_id, sizeof(client_id)) != 0) {
		fprintf(stderr, "Failed to generate client_id\n");
		exit(EXIT_FAILURE);
	}
	if (client_id == 0)
		client_id = 1; // ensure non-zero
	return client_id;
}

static int connect_to_server(const char *server_ip, int port, ssl_context_t *ssl_ctx,
			       int *sock_fd)
{
	int ret;
	LOG_DEBUG("Creating socket for connection to %s:%d", server_ip, port);
	// Create socket and connect to server
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		LOG_ERROR("Socket creation failed");
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port);
	inet_pton(AF_INET, server_ip, &server_address.sin_addr);

	// Connect to server
	LOG_DEBUG("Initiating TCP connection");
	if (connect(sock, (struct sockaddr *)&server_address,
		    sizeof(server_address)) < 0) {
		LOG_ERROR("Connection to server failed");
		perror("Connection failed");
		exit(EXIT_FAILURE);
	}
	LOG_DEBUG("TCP connection established");

	// Set the socket for the SSL session
	// Use custom callbacks that work with raw socket fds
	mbedtls_ssl_set_bio(&ssl_ctx->ssl, (void *)(intptr_t)sock, 
			    ssl_send_callback, ssl_recv_callback, NULL);

	// Perform SSL handshake
	LOG_DEBUG("Performing SSL handshake");
	while ((ret = mbedtls_ssl_handshake(&ssl_ctx->ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			print_mbedtls_error("SSL handshake failed", ret);
			close(sock);
			exit(EXIT_FAILURE);
		}
	}

	// Verify the server's certificate
	LOG_DEBUG("Verifying server certificate");
	uint32_t flags = mbedtls_ssl_get_verify_result(&ssl_ctx->ssl);
	if (flags != 0) {
		char vrfy_buf[512];
		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
		LOG_ERROR("Server certificate verification failed:\n%s", vrfy_buf);
		fprintf(stderr, "Server certificate verification failed:\n%s\n", vrfy_buf);
		close(sock);
		exit(EXIT_FAILURE);
	}
	LOG_INFO("SSL connection established successfully");

	*sock_fd = sock;
	return 0;
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

static void cleanup_and_exit(ssl_context_t *ssl_ctx, int sock, const char *error_msg)
{
	fprintf(stderr, "%s\n", error_msg);
	mbedtls_ssl_close_notify(&ssl_ctx->ssl);
	close(sock);
	mbedtls_ssl_free(&ssl_ctx->ssl);
	mbedtls_ssl_config_free(&ssl_ctx->conf);
	mbedtls_x509_crt_free(&ssl_ctx->cacert);
	mbedtls_x509_crt_free(&ssl_ctx->clicert);
	mbedtls_pk_free(&ssl_ctx->pkey);
	mbedtls_entropy_free(&ssl_ctx->entropy);
	mbedtls_ctr_drbg_free(&ssl_ctx->ctr_drbg);
	free(ssl_ctx);
	exit(EXIT_FAILURE);
}

static void do_write(ssl_context_t *ssl_ctx, uint64_t client_id, int sock)
{
	size_t used;
	LOG_DEBUG("Reading data from stdin for write operation");
	uint8_t *buf = read_stdin_to_buffer(&used);
	LOG_DEBUG("Read %zu bytes from stdin", used);

	Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
	Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT;
	wr.data.data = buf;
	wr.data.len = used;
	wr.client_id = client_id;
	env.write = &wr;
	env.body_case = TTYCB__ENVELOPE__BODY_WRITE;
	LOG_DEBUG("Sending write request to server");
	pb_send_envelope(ssl_ctx, &env);
	free(buf);

	LOG_DEBUG("Waiting for write response");
	Ttycb__Envelope *resp = pb_recv_envelope(ssl_ctx);
	if (!resp || resp->body_case != TTYCB__ENVELOPE__BODY_WRITE_RESP ||
	    !resp->write_resp || !resp->write_resp->ok) {
		ttycb__envelope__free_unpacked(resp, NULL);
		cleanup_and_exit(ssl_ctx, sock, "Write failed");
	}
	LOG_INFO("Write operation completed, message_id: %lu", resp->write_resp->message_id);
	ttycb__envelope__free_unpacked(resp, NULL);
}

static void do_read(ssl_context_t *ssl_ctx, int sock)
{
	LOG_DEBUG("Sending read request to server");
	Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
	Ttycb__ReadRequest rd = TTYCB__READ_REQUEST__INIT;
	env.read = &rd;
	env.body_case = TTYCB__ENVELOPE__BODY_READ;
	pb_send_envelope(ssl_ctx, &env);

	LOG_DEBUG("Waiting for data frame response");
	Ttycb__Envelope *resp = pb_recv_envelope(ssl_ctx);
	if (!resp || resp->body_case != TTYCB__ENVELOPE__BODY_DATA ||
	    !resp->data) {
		ttycb__envelope__free_unpacked(resp, NULL);
		cleanup_and_exit(ssl_ctx, sock, "Read failed");
	}
	LOG_INFO("Received data frame, size: %zu bytes, message_id: %lu",
		 resp->data->data.len, resp->data->message_id);
	fwrite(resp->data->data.data, 1, resp->data->data.len, stdout);
	fflush(stdout);
	ttycb__envelope__free_unpacked(resp, NULL);
}

static void do_write_read(ssl_context_t *ssl_ctx, uint64_t client_id, int sock)
{
	LOG_DEBUG("Starting write_read operation");
	size_t used;
	uint8_t *buf = read_stdin_to_buffer(&used);
	LOG_DEBUG("Read %zu bytes from stdin for write_read", used);

	Ttycb__Envelope envw = TTYCB__ENVELOPE__INIT;
	Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT;
	wr.data.data = buf;
	wr.data.len = used;
	wr.client_id = client_id;
	envw.write = &wr;
	envw.body_case = TTYCB__ENVELOPE__BODY_WRITE;
	LOG_DEBUG("Sending write request");
	pb_send_envelope(ssl_ctx, &envw);

	LOG_DEBUG("Waiting for write response");
	Ttycb__Envelope *wresp = pb_recv_envelope(ssl_ctx);
	if (!wresp || wresp->body_case != TTYCB__ENVELOPE__BODY_WRITE_RESP ||
	    !wresp->write_resp || !wresp->write_resp->ok) {
		ttycb__envelope__free_unpacked(wresp, NULL);
		cleanup_and_exit(ssl_ctx, sock, "Write failed");
	}
	LOG_INFO("Write completed, message_id: %lu", wresp->write_resp->message_id);
	ttycb__envelope__free_unpacked(wresp, NULL);
	free(buf);

	LOG_DEBUG("Sending read request");
	Ttycb__Envelope envr = TTYCB__ENVELOPE__INIT;
	Ttycb__ReadRequest rd = TTYCB__READ_REQUEST__INIT;
	envr.read = &rd;
	envr.body_case = TTYCB__ENVELOPE__BODY_READ;
	pb_send_envelope(ssl_ctx, &envr);

	LOG_DEBUG("Waiting for data frame");
	Ttycb__Envelope *rresp = pb_recv_envelope(ssl_ctx);
	if (!rresp || rresp->body_case != TTYCB__ENVELOPE__BODY_DATA ||
	    !rresp->data) {
		ttycb__envelope__free_unpacked(rresp, NULL);
		cleanup_and_exit(ssl_ctx, sock, "Read failed");
	}
	fwrite(rresp->data->data.data, 1, rresp->data->data.len, stdout);
	fflush(stdout);
	ttycb__envelope__free_unpacked(rresp, NULL);
}

static void do_subscribe(ssl_context_t *ssl_ctx, uint64_t client_id)
{
	LOG_INFO("Starting subscription to clipboard updates");
	Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
	Ttycb__SubscribeRequest sub = TTYCB__SUBSCRIBE_REQUEST__INIT;
	sub.client_id = client_id;
	env.subscribe = &sub;
	env.body_case = TTYCB__ENVELOPE__BODY_SUBSCRIBE;
	LOG_DEBUG("Sending subscribe request");
	pb_send_envelope(ssl_ctx, &env);

	LOG_DEBUG("Entering subscription loop");
	// Loop receiving data frames until connection closes or terminate signal
	while (!terminate) {
		Ttycb__Envelope *resp = pb_recv_envelope(ssl_ctx);
		if (!resp) {
			LOG_DEBUG("Connection closed by server");
			break; // connection closed
		}
		if (resp->body_case == TTYCB__ENVELOPE__BODY_DATA &&
		    resp->data) {
			LOG_DEBUG("Received clipboard update, size: %zu bytes, message_id: %lu",
				  resp->data->data.len, resp->data->message_id);
			fwrite(resp->data->data.data, 1,
			       resp->data->data.len, stdout);
			fflush(stdout);
		}
		ttycb__envelope__free_unpacked(resp, NULL);
	}
	LOG_INFO("Subscription ended");
}

static void do_write_subscribe(ssl_context_t *ssl_ctx, uint64_t client_id,
				int sock)
{
	LOG_DEBUG("Starting write_subscribe operation");
	size_t used;
	uint8_t *buf = read_stdin_to_buffer(&used);
	LOG_DEBUG("Read %zu bytes from stdin for write_subscribe", used);

	Ttycb__Envelope envw = TTYCB__ENVELOPE__INIT;
	Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT;
	wr.data.data = buf;
	wr.data.len = used;
	wr.client_id = client_id;
	envw.write = &wr;
	envw.body_case = TTYCB__ENVELOPE__BODY_WRITE;
	pb_send_envelope(ssl_ctx, &envw);

	Ttycb__Envelope *wresp = pb_recv_envelope(ssl_ctx);
	if (!wresp || wresp->body_case != TTYCB__ENVELOPE__BODY_WRITE_RESP ||
	    !wresp->write_resp || !wresp->write_resp->ok) {
		ttycb__envelope__free_unpacked(wresp, NULL);
		cleanup_and_exit(ssl_ctx, sock, "Write failed");
	}
	ttycb__envelope__free_unpacked(wresp, NULL);
	free(buf);

	// Now subscribe
	do_subscribe(ssl_ctx, client_id);
}

int main(int argc, char *argv[])
{
	const char *role = NULL;
	const char *server_ip = "127.0.0.1";
	int server_port = SERVER_PORT;
	int opt;
	int verbose_count = 0;

	static struct option long_options[] = { { "help", no_argument, 0, 'h' },
						{ "version", no_argument, 0,
						  'V' },
						{ "verbose", no_argument, 0,
						  'v' },
						{ "server", required_argument, 0,
						  's' },
						{ "port", required_argument, 0,
						  'p' },
						{ 0, 0, 0, 0 } };

	while ((opt = getopt_long(argc, argv, "hvVs:p:", long_options, NULL)) !=
	       -1) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'V':
			print_version();
			exit(EXIT_SUCCESS);
		case 'v':
			verbose_count++;
			break;
		case 's':
			server_ip = optarg;
			break;
		case 'p':
			server_port = atoi(optarg);
			if (server_port <= 0 || server_port > 65535) {
				fprintf(stderr, "Error: Invalid port number: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	// Set log level based on verbose count
	if (verbose_count == 1) {
		current_log_level = LOG_LEVEL_INFO;
	} else if (verbose_count == 2) {
		current_log_level = LOG_LEVEL_DEBUG;
	} else if (verbose_count >= 3) {
		current_log_level = LOG_LEVEL_DEBUG;
	}

	// Parse positional arguments
	if (optind >= argc) {
		fprintf(stderr, "Error: Missing command argument\n\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	role = argv[optind];

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

	// Initialize SSL context
	LOG_INFO("Initializing SSL context");
	ssl_context_t *ssl_ctx = init_ssl_context();

	// Generate a random non-zero client_id
	uint64_t client_id = generate_client_id(ssl_ctx);
	LOG_DEBUG("Generated client_id: %lu", client_id);

	// Connect to server
	LOG_INFO("Connecting to server %s:%d", server_ip, server_port);
	int sock;
	connect_to_server(server_ip, server_port, ssl_ctx, &sock);

	// Execute the requested role
	LOG_INFO("Executing command: %s", role);
	if (strcmp(role, "write") == 0) {
		do_write(ssl_ctx, client_id, sock);
	} else if (strcmp(role, "read") == 0) {
		do_read(ssl_ctx, sock);
	} else if (strcmp(role, "write_read") == 0) {
		do_write_read(ssl_ctx, client_id, sock);
	} else if (strcmp(role, "read_blocked") == 0) {
		do_subscribe(ssl_ctx, client_id);
	} else if (strcmp(role, "write_subscribe") == 0) {
		do_write_subscribe(ssl_ctx, client_id, sock);
	}
	LOG_INFO("Command completed successfully");

	// Initiate graceful shutdown
	mbedtls_ssl_close_notify(&ssl_ctx->ssl);

	// Clean up
	close(sock);
	mbedtls_ssl_free(&ssl_ctx->ssl);
	mbedtls_ssl_config_free(&ssl_ctx->conf);
	mbedtls_x509_crt_free(&ssl_ctx->cacert);
	mbedtls_x509_crt_free(&ssl_ctx->clicert);
	mbedtls_pk_free(&ssl_ctx->pkey);
	mbedtls_entropy_free(&ssl_ctx->entropy);
	mbedtls_ctr_drbg_free(&ssl_ctx->ctr_drbg);
	free(ssl_ctx);
	return 0;
}
