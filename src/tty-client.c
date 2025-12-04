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
#include <sys/select.h>
#include <poll.h>
#include <time.h>

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

// Connection info for multiple servers
typedef struct {
	int sock_fd;
	int port;
	ssl_context_t *ssl_ctx;
} connection_t;

static void tls_debug(void *ctx, int level, const char *file, int line, const char *msg)
{
	(void)ctx;
	fprintf(stderr, "mbedtls[%d] %24s:%5d: %s",
		level, basename(file), line, msg);
}


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

// Forward declarations
static ssl_context_t *init_ssl_context(void);
static int connect_to_server(const char *server_ip, int port, ssl_context_t *ssl_ctx,
			       int *sock_fd);

static int parse_ports(const char *port_str, int **ports_out, int *count_out)
{
	// Count commas to determine number of ports
	int count = 1;
	for (const char *p = port_str; *p; p++) {
		if (*p == ',')
			count++;
	}
	
	int *ports = malloc(sizeof(int) * count);
	if (!ports)
		return -1;
	
	char *str_copy = strdup(port_str);
	if (!str_copy) {
		free(ports);
		return -1;
	}
	
	int idx = 0;
	char *token = strtok(str_copy, ",");
	while (token && idx < count) {
		int port = atoi(token);
		if (port <= 0 || port > 65535) {
			fprintf(stderr, "Error: Invalid port number: %s\n", token);
			free(str_copy);
			free(ports);
			return -1;
		}
		ports[idx++] = port;
		token = strtok(NULL, ",");
	}
	
	free(str_copy);
	*ports_out = ports;
	*count_out = idx;
	return 0;
}

static connection_t *create_connections(const char *server_ip, int *ports,
					 int port_count)
{
	connection_t *conns = calloc(port_count, sizeof(connection_t));
	if (!conns)
		return NULL;
	
	for (int i = 0; i < port_count; i++) {
		conns[i].port = ports[i];
		conns[i].ssl_ctx = init_ssl_context();
		if (!conns[i].ssl_ctx) {
			// Cleanup previous connections
			for (int j = 0; j < i; j++) {
				close(conns[j].sock_fd);
				mbedtls_ssl_free(&conns[j].ssl_ctx->ssl);
				mbedtls_ssl_config_free(&conns[j].ssl_ctx->conf);
				mbedtls_x509_crt_free(&conns[j].ssl_ctx->cacert);
				mbedtls_x509_crt_free(&conns[j].ssl_ctx->clicert);
				mbedtls_pk_free(&conns[j].ssl_ctx->pkey);
				mbedtls_entropy_free(&conns[j].ssl_ctx->entropy);
				mbedtls_ctr_drbg_free(&conns[j].ssl_ctx->ctr_drbg);
				free(conns[j].ssl_ctx);
			}
			free(conns);
			return NULL;
		}
		
		if (connect_to_server(server_ip, ports[i], conns[i].ssl_ctx,
				      &conns[i].sock_fd) != 0) {
			LOG_ERROR("Failed to connect to port %d", ports[i]);
			// Cleanup
			for (int j = 0; j <= i; j++) {
				if (j < i)
					close(conns[j].sock_fd);
				mbedtls_ssl_free(&conns[j].ssl_ctx->ssl);
				mbedtls_ssl_config_free(&conns[j].ssl_ctx->conf);
				mbedtls_x509_crt_free(&conns[j].ssl_ctx->cacert);
				mbedtls_x509_crt_free(&conns[j].ssl_ctx->clicert);
				mbedtls_pk_free(&conns[j].ssl_ctx->pkey);
				mbedtls_entropy_free(&conns[j].ssl_ctx->entropy);
				mbedtls_ctr_drbg_free(&conns[j].ssl_ctx->ctr_drbg);
				free(conns[j].ssl_ctx);
			}
			free(conns);
			return NULL;
		}
		LOG_INFO("Connected to %s:%d", server_ip, ports[i]);
	}
	
	return conns;
}

static void cleanup_connections(connection_t *conns, int count)
{
	for (int i = 0; i < count; i++) {
		mbedtls_ssl_close_notify(&conns[i].ssl_ctx->ssl);
		close(conns[i].sock_fd);
		mbedtls_ssl_free(&conns[i].ssl_ctx->ssl);
		mbedtls_ssl_config_free(&conns[i].ssl_ctx->conf);
		mbedtls_x509_crt_free(&conns[i].ssl_ctx->cacert);
		mbedtls_x509_crt_free(&conns[i].ssl_ctx->clicert);
		mbedtls_pk_free(&conns[i].ssl_ctx->pkey);
		mbedtls_entropy_free(&conns[i].ssl_ctx->entropy);
		mbedtls_ctr_drbg_free(&conns[i].ssl_ctx->ctr_drbg);
		free(conns[i].ssl_ctx);
	}
	free(conns);
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

	// Prefer TLS 1.3 when available; keep TLS 1.2 as minimum for compatibility
#ifdef MBEDTLS_3X
	mbedtls_ssl_conf_min_tls_version(&ssl_ctx->conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(&ssl_ctx->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#else
	// mbedTLS 2.x supports up to TLS 1.2 only
	mbedtls_ssl_conf_min_version(&ssl_ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // TLS 1.2
	mbedtls_ssl_conf_max_version(&ssl_ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
#endif

	// Optional debug: enable detailed mbedTLS logging when MBEDTLS_DEBUG env var is set
	const char *dbg = getenv("MBEDTLS_DEBUG");
	if (dbg && *dbg) {
		mbedtls_debug_set_threshold(4);
		mbedtls_ssl_conf_dbg(&ssl_ctx->conf, tls_debug, NULL);
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
	printf("  read_blocked     Subscribe to clipboard updates (blocking)\n");
	printf("\nOptions:\n");
	printf("  -h, --help       Display this help message\n");
	printf("  -V, --version    Display version information\n");
	printf("  -v, --verbose    Enable verbose logging (repeat for more detail)\n");
	printf("  -s, --server IP  Server IP address (default: 127.0.0.1)\n");
	printf("  -p, --port PORTS Server port(s), comma-separated (default: %d)\n", SERVER_PORT);
	printf("\nExamples:\n");
	printf("  %s write                          # Write to localhost:5457\n",
	       prog_name);
	printf("  %s read                           # Read from localhost:5457\n",
	       prog_name);
	printf("  %s -p 5457,5458 write             # Write to multiple ports\n",
	       prog_name);
	printf("  %s -p 5457,5458,5459 read_blocked # Monitor multiple servers\n",
	       prog_name);
	printf("  %s -s 192.168.1.100 write         # Write to remote server\n",
	       prog_name);
	printf("  %s -s 10.0.0.1 -p 9999 read       # Custom server and port\n",
	       prog_name);
	printf("  %s -v read                        # Read with INFO logging\n",
	       prog_name);
	printf("  %s -v -v write                    # Write with DEBUG logging\n",
	       prog_name);
	printf("\nMulti-port usage:\n");
	printf("  When multiple ports are specified, write operations send to all ports,\n");
	printf("  and read operations return the first available update from any port.\n");
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
	sigaction(SIGTERM, &sa, NULL);  // Also handle SIGTERM for graceful shutdown
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


// Multi-port operations (work for both single and multi-port cases)
static void do_write_multi(connection_t *conns, int count, uint64_t client_id, unsigned char *out_uuid)
{
	size_t used;
	LOG_DEBUG("Reading data from stdin for multi-port write operation");
	uint8_t *buf = read_stdin_to_buffer(&used);
	LOG_DEBUG("Read %zu bytes from stdin, writing to %d port(s)", used, count);

	// Generate UUID once for all ports (same write operation)
	unsigned char write_uuid[UUID_SIZE];
	generate_uuid(write_uuid);
	if (out_uuid) {
		memcpy(out_uuid, write_uuid, UUID_SIZE);
	}

	// Get hostname and timestamp for debugging
	char hostname[256];
	if (gethostname(hostname, sizeof(hostname)) != 0) {
		strncpy(hostname, "unknown", sizeof(hostname));
	}
	hostname[sizeof(hostname) - 1] = '\0';
	int64_t timestamp = (int64_t)time(NULL);

	int success_count = 0;
	for (int i = 0; i < count; i++) {
		Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
		Ttycb__WriteRequest wr = TTYCB__WRITE_REQUEST__INIT;
		wr.data.data = buf;
		wr.data.len = used;
		wr.client_id = client_id;
		wr.write_uuid.data = write_uuid;
		wr.write_uuid.len = UUID_SIZE;
		wr.hostname = hostname;
		wr.timestamp = timestamp;
		env.write = &wr;
		env.body_case = TTYCB__ENVELOPE__BODY_WRITE;
		
		LOG_DEBUG("Sending write request to port %d", conns[i].port);
		pb_send_envelope(conns[i].ssl_ctx, &env);
		
		LOG_DEBUG("Waiting for write response from port %d", conns[i].port);
		Ttycb__Envelope *resp = pb_recv_envelope(conns[i].ssl_ctx);
		if (resp && resp->body_case == TTYCB__ENVELOPE__BODY_WRITE_RESP &&
		    resp->write_resp && resp->write_resp->ok) {
			LOG_INFO("Write to port %d completed, message_id: %lu",
				 conns[i].port, resp->write_resp->message_id);
			success_count++;
		} else {
			LOG_ERROR("Write to port %d failed", conns[i].port);
		}
		ttycb__envelope__free_unpacked(resp, NULL);
	}
	
	free(buf);
	LOG_INFO("Write operation completed for %d/%d port(s)", success_count, count);
	
	// If any writes failed, exit with error
	if (success_count != count) {
		exit(EXIT_FAILURE);
	}
}

static void do_read_multi(connection_t *conns, int count)
{
	LOG_DEBUG("Sending read requests to %d port(s)", count);
	
	// Send read request to all ports
	for (int i = 0; i < count; i++) {
		Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
		Ttycb__ReadRequest rd = TTYCB__READ_REQUEST__INIT;
		env.read = &rd;
		env.body_case = TTYCB__ENVELOPE__BODY_READ;
		pb_send_envelope(conns[i].ssl_ctx, &env);
		LOG_DEBUG("Read request sent to port %d", conns[i].port);
	}
	
	// Wait for first response using poll
	struct pollfd *fds = malloc(sizeof(struct pollfd) * count);
	if (!fds)
		handle_error("malloc pollfd");
	
	for (int i = 0; i < count; i++) {
		fds[i].fd = conns[i].sock_fd;
		fds[i].events = POLLIN;
	}
	
	LOG_DEBUG("Waiting for data from any port");
	int ret = poll(fds, count, -1);
	if (ret < 0) {
		free(fds);
		handle_error("poll");
	}
	
	// Read from first available port
	for (int i = 0; i < count; i++) {
		if (fds[i].revents & POLLIN) {
			LOG_DEBUG("Data available from port %d", conns[i].port);
			Ttycb__Envelope *resp = pb_recv_envelope(conns[i].ssl_ctx);
			if (resp && resp->body_case == TTYCB__ENVELOPE__BODY_DATA &&
			    resp->data) {
				LOG_INFO("Received data from port %d, size: %zu bytes, message_id: %lu",
					 conns[i].port, resp->data->data.len,
					 resp->data->message_id);
				if (resp->data->hostname && resp->data->hostname[0] != '\0') {
					LOG_DEBUG("Data from host: %s, timestamp: %ld",
						  resp->data->hostname,
						  (long)resp->data->timestamp);
				}
				fwrite(resp->data->data.data, 1,
				       resp->data->data.len, stdout);
				fflush(stdout);
				ttycb__envelope__free_unpacked(resp, NULL);
				free(fds);
				return;
			}
			ttycb__envelope__free_unpacked(resp, NULL);
		}
	}
	
	free(fds);
	LOG_ERROR("No valid data received from any port");
	exit(EXIT_FAILURE);
}

static void do_subscribe_multi(connection_t *conns, int count, uint64_t client_id, const unsigned char *init_uuid)
{
	LOG_INFO("Starting subscription to %d port(s)", count);
	
	// Send subscribe request to all ports
	for (int i = 0; i < count; i++) {
		Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
		Ttycb__SubscribeRequest sub = TTYCB__SUBSCRIBE_REQUEST__INIT;
		sub.client_id = client_id;
		env.subscribe = &sub;
		env.body_case = TTYCB__ENVELOPE__BODY_SUBSCRIBE;
		pb_send_envelope(conns[i].ssl_ctx, &env);
		LOG_DEBUG("Subscribe request sent to port %d", conns[i].port);
	}
	
	// Setup poll fds
	struct pollfd *fds = malloc(sizeof(struct pollfd) * count);
	if (!fds)
		handle_error("malloc pollfd");
	
	for (int i = 0; i < count; i++) {
		fds[i].fd = conns[i].sock_fd;
		fds[i].events = POLLIN;
	}
	
	LOG_DEBUG("Entering multi-port subscription loop");
	// Loop receiving updates from any port
	while (!terminate) {
		int ret = poll(fds, count, 1000); // 1 second timeout
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			free(fds);
			handle_error("poll");
		}
		
		if (ret == 0)
			continue; // timeout, check terminate flag
		
		// Check all ports for data
		for (int i = 0; i < count; i++) {
			if (fds[i].revents & POLLIN) {
				Ttycb__Envelope *resp =
					pb_recv_envelope(conns[i].ssl_ctx);
				if (!resp) {
					LOG_DEBUG("Connection closed on port %d",
						  conns[i].port);
					fds[i].fd = -1; // Mark as closed
					continue;
				}
				
				if (resp->body_case == TTYCB__ENVELOPE__BODY_DATA &&
				    resp->data) {
					LOG_DEBUG("Received update from port %d, size: %zu bytes, message_id: %lu",
						  conns[i].port,
						  resp->data->data.len,
						  resp->data->message_id);
					if (resp->data->hostname && resp->data->hostname[0] != '\0') {
						LOG_DEBUG("Data from host: %s, timestamp: %ld",
							  resp->data->hostname,
							  (long)resp->data->timestamp);
					}
					fwrite(resp->data->data.data, 1,
					       resp->data->data.len, stdout);
					fflush(stdout);
				}
				ttycb__envelope__free_unpacked(resp, NULL);
			}
		}
	}
	
	free(fds);
	LOG_INFO("Multi-port subscription ended");
	(void)init_uuid; // Unused parameter
}

int main(int argc, char *argv[])
{
	const char *role = NULL;
	const char *server_ip = "127.0.0.1";
	const char *port_str = NULL;
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
			port_str = optarg;
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
	    strcmp(role, "read_blocked") != 0) {
		fprintf(stderr,
			"Error: Command must be 'read', 'write', or 'read_blocked'\n\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	// Parse ports
	int *ports = NULL;
	int port_count = 0;
	
	if (!port_str) {
		// Default to single port
		ports = malloc(sizeof(int));
		if (!ports)
			handle_error("malloc");
		ports[0] = SERVER_PORT;
		port_count = 1;
	} else {
		if (parse_ports(port_str, &ports, &port_count) != 0) {
			exit(EXIT_FAILURE);
		}
	}
	
	LOG_INFO("Configured %d port(s)", port_count);

	// Set up signal handling
	setup_signal_handler();

	// Create connections to all ports
	LOG_INFO("Creating connections to %s", server_ip);
	connection_t *conns = create_connections(server_ip, ports, port_count);
	if (!conns) {
		fprintf(stderr, "Failed to establish connections\n");
		free(ports);
		exit(EXIT_FAILURE);
	}

	// Generate a random non-zero client_id
	uint64_t client_id = generate_client_id(conns[0].ssl_ctx);
	LOG_DEBUG("Generated client_id: %lu", client_id);

	// Execute the requested role using multi-port functions
	// (they handle both single and multiple ports efficiently)
	LOG_INFO("Executing command: %s", role);
	
	if (strcmp(role, "write") == 0) {
		do_write_multi(conns, port_count, client_id, NULL);
	} else if (strcmp(role, "read") == 0) {
		do_read_multi(conns, port_count);
	} else if (strcmp(role, "read_blocked") == 0) {
		do_subscribe_multi(conns, port_count, client_id, NULL);
	}
	
	LOG_INFO("Command completed successfully");

	// Clean up
	cleanup_connections(conns, port_count);
	free(ports);
	return 0;
}
