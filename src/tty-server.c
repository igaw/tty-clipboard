/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#include "config.h"
#include "tty-clipboard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <mbedtls/version.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <sys/select.h>
#include <stdint.h>
#include <endian.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <protobuf-c/protobuf-c.h>
#include "clipboard.pb-c.h"
#pragma GCC diagnostic pop

static void tls_debug(void *ctx, int level, const char *file, int line, const char *msg)
{
	(void)ctx;
	fprintf(stderr, "mbedtls[%d] %s:%d: %s\n", level, file, line, msg);
}

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

// mbedTLS context structures for server
typedef struct {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt srvcert;
	mbedtls_x509_crt cacert;
	mbedtls_pk_context pkey;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} ssl_context_t;

// Shared buffer and mutex (dynamic)
char *shared_buffer = NULL;
size_t shared_capacity = 0; // allocated size
size_t shared_length = 0; // used length
uint64_t shared_message_id = 0; // message_id of current buffer
unsigned int gen = 0;
pthread_mutex_t buffer_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t buffer_cond = PTHREAD_COND_INITIALIZER;
volatile sig_atomic_t terminate = 0;
// Message ID counter for tracking clipboard updates (protobuf mode)
static uint64_t next_message_id = 1;
// Maximum allowed clipboard size (0 means unlimited)
static size_t max_buffer_size = 0;
// Oversize policy: reject (close connection) or drop (discard payload)
typedef enum { OVERSIZE_REJECT = 0, OVERSIZE_DROP = 1 } oversize_policy_t;
static oversize_policy_t oversize_policy = OVERSIZE_REJECT;

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

ssl_context_t *init_ssl_context()
{
	int ret;
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

	ssl_context_t *ssl_ctx = calloc(1, sizeof(ssl_context_t));
	if (!ssl_ctx) {
		perror("Unable to allocate SSL context");
		exit(EXIT_FAILURE);
	}

	// Initialize mbedTLS structures
	mbedtls_ssl_init(&ssl_ctx->ssl);
	mbedtls_ssl_config_init(&ssl_ctx->conf);
	mbedtls_x509_crt_init(&ssl_ctx->srvcert);
	mbedtls_x509_crt_init(&ssl_ctx->cacert);
	mbedtls_pk_init(&ssl_ctx->pkey);
	mbedtls_entropy_init(&ssl_ctx->entropy);
	mbedtls_ctr_drbg_init(&ssl_ctx->ctr_drbg);

	LOG_DEBUG("mbedTLS structures initialized");

	// Seed the RNG
	const char *pers = "tty_clipboard_server";
	ret = mbedtls_ctr_drbg_seed(&ssl_ctx->ctr_drbg, mbedtls_entropy_func,
				    &ssl_ctx->entropy,
				    (const unsigned char *)pers, strlen(pers));
	if (ret != 0) {
		LOG_ERROR("mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}
	LOG_DEBUG("RNG initialized");

	// Load the CA certificate for client verification
	LOG_DEBUG("Loading CA certificate from %s", ca);
	ret = mbedtls_x509_crt_parse_file(&ssl_ctx->cacert, ca);
	if (ret != 0) {
		LOG_ERROR("Unable to load CA certificate from %s: -0x%04x", ca, -ret);
		fprintf(stderr, "Unable to load CA certificate: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

	// Load the server certificate
	LOG_DEBUG("Loading server certificate from %s", crt);
	ret = mbedtls_x509_crt_parse_file(&ssl_ctx->srvcert, crt);
	if (ret != 0) {
		LOG_ERROR("Unable to load server certificate from %s: -0x%04x", crt, -ret);
		fprintf(stderr, "Unable to load server certificate: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

	// Load the server private key
	LOG_DEBUG("Loading server private key from %s", key);
#ifdef MBEDTLS_3X
	// mbedTLS 3.x requires RNG parameters
	ret = mbedtls_pk_parse_keyfile(&ssl_ctx->pkey, key, NULL,
				      mbedtls_ctr_drbg_random, &ssl_ctx->ctr_drbg);
#else
	// mbedTLS 2.x uses simpler API
	ret = mbedtls_pk_parse_keyfile(&ssl_ctx->pkey, key, NULL);
#endif
	if (ret != 0) {
		LOG_ERROR("Unable to load server private key from %s: -0x%04x", key, -ret);
		fprintf(stderr, "Unable to load server private key: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

	// Configure SSL/TLS defaults for server
	ret = mbedtls_ssl_config_defaults(&ssl_ctx->conf,
					  MBEDTLS_SSL_IS_SERVER,
					  MBEDTLS_SSL_TRANSPORT_STREAM,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		LOG_ERROR("mbedtls_ssl_config_defaults failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ssl_config_defaults failed: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}
	LOG_DEBUG("SSL config initialized with defaults");

	// Set RNG callback
	mbedtls_ssl_conf_rng(&ssl_ctx->conf, mbedtls_ctr_drbg_random, &ssl_ctx->ctr_drbg);

	// Optional debug: enable detailed mbedTLS logging when MBEDTLS_DEBUG env var is set
	const char *dbg = getenv("MBEDTLS_DEBUG");
	if (dbg && *dbg) {
		mbedtls_debug_set_threshold(4);
		mbedtls_ssl_conf_dbg(&ssl_ctx->conf, tls_debug, NULL);
	}

	// Set CA certificate for client verification
	mbedtls_ssl_conf_ca_chain(&ssl_ctx->conf, &ssl_ctx->cacert, NULL);

	// Set server certificate and private key
	ret = mbedtls_ssl_conf_own_cert(&ssl_ctx->conf, &ssl_ctx->srvcert, &ssl_ctx->pkey);
	if (ret != 0) {
		LOG_ERROR("mbedtls_ssl_conf_own_cert failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ssl_conf_own_cert failed: -0x%04x\n", -ret);
		exit(EXIT_FAILURE);
	}

	// Require and verify client certificates
	mbedtls_ssl_conf_authmode(&ssl_ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	LOG_DEBUG("SSL context configured with certificates");

	return ssl_ctx;
}

static int ssl_read_all(mbedtls_ssl_context *ssl, void *buf, size_t len)
{
	unsigned char *p = buf;
	size_t total = 0;
	while (total < len) {
		int r = mbedtls_ssl_read(ssl, p + total, len - total);
		if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		if (r <= 0)
			return -1;
		total += (size_t)r;
	}
	return 0;
}

static int ssl_write_all(mbedtls_ssl_context *ssl, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	size_t total = 0;
	while (total < len) {
		int w = mbedtls_ssl_write(ssl, p + total, len - total);
		if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		if (w <= 0)
			return -1;
		total += (size_t)w;
	}
	return 0;
}

static int send_protobuf_response(mbedtls_ssl_context *ssl, Ttycb__Envelope *resp)
{
	size_t outsz = ttycb__envelope__get_packed_size(resp);
	unsigned char *outbuf = malloc(outsz);
	if (!outbuf)
		return -1;

	ttycb__envelope__pack(resp, outbuf);
	uint64_t pfx = htobe64((uint64_t)outsz);

	int result = 0;
	if (ssl_write_all(ssl, &pfx, sizeof(pfx)) < 0 ||
	    ssl_write_all(ssl, outbuf, outsz) < 0)
		result = -1;

	free(outbuf);
	return result;
}

static int handle_write_request(mbedtls_ssl_context *ssl, Ttycb__WriteRequest *write_req)
{
	size_t len = write_req->data.len;
	const unsigned char *data = write_req->data.data;
	int oversize = (max_buffer_size && len > max_buffer_size);

	LOG_DEBUG("Write request: %zu bytes from client_id %lu", len, write_req->client_id);

	if (oversize) {
		LOG_WARN("Write request rejected: size %zu exceeds max %zu (policy: %s)",
			 len, max_buffer_size,
			 oversize_policy == OVERSIZE_DROP ? "drop" : "reject");
		int ok = (oversize_policy == OVERSIZE_DROP);
		Ttycb__Envelope resp = TTYCB__ENVELOPE__INIT;
		Ttycb__WriteResponse wr = TTYCB__WRITE_RESPONSE__INIT;
		wr.ok = ok;
		if (!ok)
			wr.message = (char *)"oversize";
		wr.message_id = 0; // No message_id for rejected writes
		resp.write_resp = &wr;
		resp.body_case = TTYCB__ENVELOPE__BODY_WRITE_RESP;
		return send_protobuf_response(ssl, &resp);
	}

	// Store the data
	pthread_mutex_lock(&buffer_mutex);
	if (len > shared_capacity) {
		char *nbuf = realloc(shared_buffer, len);
		if (!nbuf) {
			pthread_mutex_unlock(&buffer_mutex);
			return -1;
		}
		shared_buffer = nbuf;
		shared_capacity = len;
	}
	memcpy(shared_buffer, data, len);
	shared_length = len;
	uint64_t msg_id = next_message_id++;
	shared_message_id = msg_id;
	gen++;
	pthread_cond_broadcast(&buffer_cond);
	pthread_mutex_unlock(&buffer_mutex);

	LOG_INFO("Write completed: %zu bytes, message_id: %lu", len, msg_id);

	// Send success response
	Ttycb__Envelope resp = TTYCB__ENVELOPE__INIT;
	Ttycb__WriteResponse wr = TTYCB__WRITE_RESPONSE__INIT;
	wr.ok = 1;
	wr.message_id = msg_id;
	resp.write_resp = &wr;
	resp.body_case = TTYCB__ENVELOPE__BODY_WRITE_RESP;
	return send_protobuf_response(ssl, &resp);
}

static int handle_read_request(mbedtls_ssl_context *ssl)
{
	LOG_DEBUG("Read request received");
	pthread_mutex_lock(&buffer_mutex);
	size_t len = shared_length;
	LOG_INFO("Read completed: %zu bytes, message_id: %lu", len, shared_message_id);
	Ttycb__Envelope resp = TTYCB__ENVELOPE__INIT;
	Ttycb__DataFrame df = TTYCB__DATA_FRAME__INIT;
	df.data.len = len;
	df.data.data = (uint8_t *)shared_buffer;
	resp.data = &df;
	resp.body_case = TTYCB__ENVELOPE__BODY_DATA;

	size_t outsz = ttycb__envelope__get_packed_size(&resp);
	unsigned char *outbuf = malloc(outsz);
	if (!outbuf) {
		pthread_mutex_unlock(&buffer_mutex);
		return -1;
	}
	ttycb__envelope__pack(&resp, outbuf);
	pthread_mutex_unlock(&buffer_mutex);

	uint64_t pfx = htobe64((uint64_t)outsz);
	int result = 0;
	if (ssl_write_all(ssl, &pfx, sizeof(pfx)) < 0 ||
	    ssl_write_all(ssl, outbuf, outsz) < 0)
		result = -1;

	free(outbuf);
	return result;
}

static int handle_subscribe_request(mbedtls_ssl_context *ssl, Ttycb__SubscribeRequest *sub_req)
{
	(void)sub_req; // Unused for now, but client_id could be used for filtering

	pthread_mutex_lock(&buffer_mutex);
	unsigned int seen = gen; // Start from current generation
	uint64_t last_sent_message_id = shared_message_id;
	pthread_mutex_unlock(&buffer_mutex);

	while (!terminate) {
		pthread_mutex_lock(&buffer_mutex);
		while (seen == gen && !terminate)
			pthread_cond_wait(&buffer_cond, &buffer_mutex);
		if (terminate) {
			pthread_mutex_unlock(&buffer_mutex);
			break;
		}
		seen = gen;

		// Skip if we've already sent this message to this subscriber
		if (shared_message_id == last_sent_message_id) {
			pthread_mutex_unlock(&buffer_mutex);
			continue;
		}

		size_t len = shared_length;
		uint64_t msg_id = shared_message_id;
		last_sent_message_id = msg_id;

		Ttycb__Envelope resp = TTYCB__ENVELOPE__INIT;
		Ttycb__DataFrame df = TTYCB__DATA_FRAME__INIT;
		df.data.len = len;
		df.data.data = (uint8_t *)shared_buffer;
		df.message_id = msg_id;
		resp.data = &df;
		resp.body_case = TTYCB__ENVELOPE__BODY_DATA;

		size_t outsz = ttycb__envelope__get_packed_size(&resp);
		unsigned char *outbuf = malloc(outsz);
		if (!outbuf) {
			pthread_mutex_unlock(&buffer_mutex);
			return -1;
		}
		ttycb__envelope__pack(&resp, outbuf);
		pthread_mutex_unlock(&buffer_mutex);

		uint64_t pfx = htobe64((uint64_t)outsz);
		if (ssl_write_all(ssl, &pfx, sizeof(pfx)) < 0 ||
		    ssl_write_all(ssl, outbuf, outsz) < 0) {
			free(outbuf);
			return -1;
		}
		free(outbuf);
	}
	return 0;
}

static Ttycb__Envelope *receive_envelope(mbedtls_ssl_context *ssl, int *error)
{
	*error = 0;

	uint64_t be_len = 0;
	int rr = mbedtls_ssl_read(ssl, (unsigned char *)&be_len, sizeof(be_len));
	if (rr <= 0) {
		*error = 1;
		return NULL;
	}

	size_t mlen = (size_t)be64toh(be_len);
	if (mlen == 0)
		return NULL; // Skip empty message, not an error

	unsigned char *mbuf = malloc(mlen);
	if (!mbuf) {
		*error = 1;
		return NULL;
	}

	if (ssl_read_all(ssl, mbuf, mlen) < 0) {
		free(mbuf);
		*error = 1;
		return NULL;
	}

	Ttycb__Envelope *env = ttycb__envelope__unpack(NULL, mlen, mbuf);
	free(mbuf);

	if (!env) {
		printf("Failed to unpack envelope\n");
		*error = 1;
	}

	return env;
}

// Protobuf client handler
void *client_handler(void *arg)
{
	mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)arg;

	while (!terminate) {
		int error = 0;
		Ttycb__Envelope *env = receive_envelope(ssl, &error);
		if (!env) {
			if (error || terminate)
				break;
			continue; // Empty message, continue loop
		}

		int result = 0;
		if (env->body_case == TTYCB__ENVELOPE__BODY_WRITE &&
		    env->write) {
			LOG_DEBUG("Handling write request from client");
			result = handle_write_request(ssl, env->write);
		} else if (env->body_case == TTYCB__ENVELOPE__BODY_READ &&
			   env->read) {
			LOG_DEBUG("Handling read request from client");
			result = handle_read_request(ssl);
		} else if (env->body_case == TTYCB__ENVELOPE__BODY_SUBSCRIBE &&
			   env->subscribe) {
			LOG_DEBUG("Handling subscribe request from client_id: %lu", env->subscribe->client_id);
			result = handle_subscribe_request(ssl, env->subscribe);
		}

		ttycb__envelope__free_unpacked(env, NULL);

		if (result < 0)
			break;
	}

	mbedtls_ssl_close_notify(ssl);
	mbedtls_ssl_free(ssl);
	free(ssl);
	pthread_exit(NULL);
}

struct server_args {
	int port;
	const char *bind_addr;
	ssl_context_t *ctx;
};

static int create_server_socket(int port, const char *bind_addr)
{
	int server_fd;
	struct sockaddr_in address;

	LOG_DEBUG("Creating server socket on port %d", port);
	// Create server socket
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		LOG_ERROR("Socket creation failed");
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	int opt = 1;
	// Set socket options to reuse address
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt,
		       sizeof(opt)) == -1) {
		perror("setsockopt failed");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	if (bind_addr && strcmp(bind_addr, "0.0.0.0") != 0) {
		if (inet_pton(AF_INET, bind_addr, &address.sin_addr) <= 0) {
			fprintf(stderr, "Invalid bind address: %s\n", bind_addr);
			close(server_fd);
			exit(EXIT_FAILURE);
		}
		LOG_INFO("Binding to address %s", bind_addr);
	} else {
		address.sin_addr.s_addr = INADDR_ANY;
		LOG_DEBUG("Binding to all interfaces (0.0.0.0)");
	}
	address.sin_port = htons(port);

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

	printf("Server listening on port %d...\n", port);
	return server_fd;
}

static int accept_client_connection(int server_fd)
{
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int client_fd;

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(server_fd, &readfds);

	struct timeval timeout = { 1, 0 }; // Check periodically

	int ready = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
	if (ready < 0) {
		if (errno == EINTR)
			return -1; // Signal interrupted
		perror("select");
		return -2; // Error, continue
	}
	if (ready == 0)
		return -2; // Timeout, continue

	if (!FD_ISSET(server_fd, &readfds))
		return -2; // No connection ready

	LOG_DEBUG("Connection pending on server socket");
	if ((client_fd = accept(server_fd, (struct sockaddr *)&address,
				(socklen_t *)&addrlen)) < 0) {
		if (errno == EINTR)
			return -1; // Signal interrupted
		LOG_ERROR("Accept failed: %s", strerror(errno));
		perror("accept");
		return -2; // Error, continue
	}
	LOG_INFO("Client connected from %s:%d", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
	printf("Client connected\n");
	return client_fd;
}

static mbedtls_ssl_context *setup_client_ssl(ssl_context_t *ctx, int client_fd)
{
	int ret;
	// Allocate a new SSL context for this client
	mbedtls_ssl_context *ssl = calloc(1, sizeof(mbedtls_ssl_context));
	if (!ssl) {
		perror("Unable to allocate SSL context for client");
		close(client_fd);
		return NULL;
	}

	mbedtls_ssl_init(ssl);

	// Setup the SSL context with the server's configuration
	ret = mbedtls_ssl_setup(ssl, &ctx->conf);
	if (ret != 0) {
		LOG_ERROR("mbedtls_ssl_setup failed: -0x%04x", -ret);
		fprintf(stderr, "mbedtls_ssl_setup failed: -0x%04x\n", -ret);
		mbedtls_ssl_free(ssl);
		free(ssl);
		close(client_fd);
		return NULL;
	}

	// Set the socket for the SSL session
	// Use custom callbacks that work with raw socket fds
	mbedtls_ssl_set_bio(ssl, (void *)(intptr_t)client_fd,
			    ssl_send_callback, ssl_recv_callback, NULL);

	// Perform SSL/TLS handshake
	while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			print_mbedtls_error("SSL handshake failed", ret);
			mbedtls_ssl_free(ssl);
			free(ssl);
			close(client_fd);
			return NULL;
		}
	}

	return ssl;
}

static int verify_client_certificate(mbedtls_ssl_context *ssl)
{
	// Verify client certificate
	const mbedtls_x509_crt *cert = mbedtls_ssl_get_peer_cert(ssl);
	if (cert == NULL) {
		printf("Client certificate not provided\n");
		return -1;
	}

	uint32_t flags = mbedtls_ssl_get_verify_result(ssl);
	if (flags != 0) {
		char vrfy_buf[512];
		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
		printf("Certificate verification failed:\n%s\n", vrfy_buf);
		return -1;
	}

	return 0;
}

static void spawn_client_handler(mbedtls_ssl_context *ssl, int client_fd)
{
	pthread_t client_thread;
	if (pthread_create(&client_thread, NULL, client_handler, (void *)ssl) !=
	    0) {
		perror("Failed to create client thread");
		mbedtls_ssl_free(ssl);
		free(ssl);
		close(client_fd);
		return;
	}
	pthread_detach(client_thread);
}

static void *start_server(void *data)
{
	struct server_args *args = data;

	// Create and configure server socket
	int server_fd = create_server_socket(args->port, args->bind_addr);

	// Accept client connections
	while (!terminate) {
		int client_fd = accept_client_connection(server_fd);
		if (client_fd == -1)
			break; // Signal interrupted
		if (client_fd == -2)
			continue; // Timeout or error, try again

		// Setup SSL for client
		mbedtls_ssl_context *ssl = setup_client_ssl(args->ctx, client_fd);
		if (!ssl)
			continue;

		// Verify client certificate
		if (verify_client_certificate(ssl) < 0) {
			mbedtls_ssl_close_notify(ssl);
			mbedtls_ssl_free(ssl);
			free(ssl);
			close(client_fd);
			continue;
		}

		// Spawn client handler thread
		spawn_client_handler(ssl, client_fd);
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
	printf("  -V, --version    Display version information\n");
	printf("  -v, --verbose    Enable verbose logging (can be repeated for more detail)\n");
	printf("  -d, --daemon     Run in daemon mode (background)\n");
	printf("  -b, --bind IP    Bind to specific IP address (default: 0.0.0.0)\n");
	printf("  -p, --port PORT  Server port (default: %d)\n", SERVER_PORT);
	printf("  -m, --max-size N[K|M|G]  Set maximum clipboard size (0=unlimited)\n");
	printf("  --oversize-policy reject|drop  Action on oversize write (default: reject)\n");
	printf("\nProtocol:\n");
	printf("  Client connects and sends command: %s, %s, or %s\n", CMD_READ,
	       CMD_WRITE, CMD_READ_BLOCKED);
	printf("\nThe server listens on all interfaces (0.0.0.0) by default.\n");
	printf("Client authentication is required via mutual TLS.\n");
	printf("\n");
}

static void print_version(void)
{
	printf("tty-cb-server version %s\n", VERSION);
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

static void parse_max_size(const char *max_size_arg)
{
	char *end = NULL;
	unsigned long long v = strtoull(max_size_arg, &end, 10);
	if (end == max_size_arg) {
		fprintf(stderr, "Invalid --max-size value: %s\n", max_size_arg);
		exit(EXIT_FAILURE);
	}
	unsigned long long mult = 1ULL;
	if (*end) {
		if (end[1] != '\0') {
			fprintf(stderr, "Invalid --max-size suffix: %s\n", end);
			exit(EXIT_FAILURE);
		}
		switch (*end) {
		case 'k':
		case 'K':
			mult = 1024ULL;
			break;
		case 'm':
		case 'M':
			mult = 1024ULL * 1024ULL;
			break;
		case 'g':
		case 'G':
			mult = 1024ULL * 1024ULL * 1024ULL;
			break;
		default:
			fprintf(stderr,
				"Unknown size suffix '%c' in --max-size\n",
				*end);
			exit(EXIT_FAILURE);
		}
	}
	unsigned long long result = v * mult;
	if (result > SIZE_MAX) {
		LOG_ERROR("--max-size value too large: %s", max_size_arg);
		fprintf(stderr, "--max-size value too large: %s\n",
			max_size_arg);
		exit(EXIT_FAILURE);
	}
	max_buffer_size = (size_t)result;
	LOG_INFO("Configured max clipboard size: %zu bytes", max_buffer_size);
	printf("Configured max clipboard size: %zu bytes\n", max_buffer_size);
}

static void daemonize(void)
{
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

static void init_shared_buffer(void)
{
	shared_capacity = BUFFER_SIZE;
	shared_buffer = malloc(shared_capacity);
	if (!shared_buffer) {
		perror("malloc shared buffer");
		exit(EXIT_FAILURE);
	}
	shared_length = 0;
}

int main(int argc, char *argv[])
{
	int opt;
	int daemon_mode = 0;
	int verbose_count = 0;
	int server_port = SERVER_PORT;
	const char *bind_addr = NULL;
	char *max_size_arg = NULL;

	static struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
		{ "verbose", no_argument, 0, 'v' },
		{ "daemon", no_argument, 0, 'd' },
		{ "bind", required_argument, 0, 'b' },
		{ "port", required_argument, 0, 'p' },
		{ "max-size", required_argument, 0, 'm' },
		{ "oversize-policy", required_argument, 0, 1 },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hvVdb:p:m:", long_options, NULL)) !=
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
		case 'd':
			daemon_mode = 1;
			break;
		case 'b':
			bind_addr = optarg;
			break;
		case 'p':
			server_port = atoi(optarg);
			if (server_port <= 0 || server_port > 65535) {
				fprintf(stderr, "Error: Invalid port number: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'm':
			max_size_arg = optarg;
			break;
		case 1:
			if (strcmp(optarg, "reject") == 0)
				oversize_policy = OVERSIZE_REJECT;
			else if (strcmp(optarg, "drop") == 0)
				oversize_policy = OVERSIZE_DROP;
			else {
				fprintf(stderr,
					"Invalid oversize policy: %s (use reject|drop)\n",
					optarg);
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

	LOG_INFO("Starting tty-clipboard server version %s", VERSION);

	// Parse max size argument if provided
	if (max_size_arg) {
		LOG_DEBUG("Parsing max-size argument: %s", max_size_arg);
		parse_max_size(max_size_arg);
	}

	// Daemonize if requested
	if (daemon_mode) {
		LOG_INFO("Daemonizing server");
		daemonize();
	}

	// Set up signal handling
	LOG_DEBUG("Setting up signal handlers");
	setup_signal_handler();

	// Allocate initial shared buffer
	LOG_DEBUG("Initializing shared buffer");
	init_shared_buffer();

	// Initialize SSL context
	LOG_INFO("Initializing SSL context");
	ssl_context_t *ctx = init_ssl_context();
	struct server_args args = { .port = server_port, .bind_addr = bind_addr, .ctx = ctx };

	// Start server thread
	LOG_INFO("Starting server on port %d", server_port);
	pthread_t server_thread;
	if (pthread_create(&server_thread, NULL, start_server, &args) != 0) {
		LOG_ERROR("Failed to create server thread");
		perror("Failed to create server thread");
		exit(EXIT_FAILURE);
	}

	pthread_join(server_thread, NULL);

	// Clean up SSL context
	mbedtls_ssl_config_free(&ctx->conf);
	mbedtls_x509_crt_free(&ctx->srvcert);
	mbedtls_x509_crt_free(&ctx->cacert);
	mbedtls_pk_free(&ctx->pkey);
	mbedtls_entropy_free(&ctx->entropy);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	free(ctx);
	free(shared_buffer);
	return 0;
}
