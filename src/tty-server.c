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
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/select.h>
#include <stdint.h>
#include <endian.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <protobuf-c/protobuf-c.h>
#include "clipboard.pb-c.h"
#pragma GCC diagnostic pop

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
	LOG_DEBUG("OpenSSL library initialized");

	// Choose the method for SSL/TLS
	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		LOG_ERROR("Unable to create SSL context");
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	LOG_DEBUG("SSL context created");

	// Load the server's certificate and private key
	LOG_DEBUG("Loading server certificate from %s", crt);
	if (SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM) <= 0) {
		LOG_ERROR("Unable to load server certificate from %s", crt);
		perror("Unable to load certificate");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	LOG_DEBUG("Loading server private key from %s", key);
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		LOG_ERROR("Unable to load server private key from %s", key);
		perror("Unable to load private key");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Load the CA certificate for client verification
	LOG_DEBUG("Loading CA certificate from %s", ca);
	if (SSL_CTX_load_verify_locations(ctx, ca, NULL) <= 0) {
		LOG_ERROR("Unable to load CA certificate from %s", ca);
		perror("Unable to load CA certificate");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Set the server to verify the client's certificate
	SSL_CTX_set_verify(
		ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	LOG_DEBUG("SSL context configured with certificates");

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
			if (err == SSL_ERROR_WANT_READ ||
			    err == SSL_ERROR_WANT_WRITE)
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
			if (err == SSL_ERROR_WANT_READ ||
			    err == SSL_ERROR_WANT_WRITE)
				continue;
			return -1;
		}
		total += (size_t)w;
	}
	return 0;
}

static int send_protobuf_response(SSL *ssl, Ttycb__Envelope *resp)
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

static int handle_write_request(SSL *ssl, Ttycb__WriteRequest *write_req)
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

static int handle_read_request(SSL *ssl)
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

static int handle_subscribe_request(SSL *ssl, Ttycb__SubscribeRequest *sub_req)
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

static Ttycb__Envelope *receive_envelope(SSL *ssl, int *error)
{
	*error = 0;

	uint64_t be_len = 0;
	int rr = SSL_read(ssl, &be_len, sizeof(be_len));
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
	SSL *ssl = (SSL *)arg;

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

	if (SSL_shutdown(ssl) == 0)
		SSL_shutdown(ssl);
	SSL_free(ssl);
	pthread_exit(NULL);
}

struct server_args {
	int port;
	SSL_CTX *ctx;
};

static int create_server_socket(int port)
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
	address.sin_addr.s_addr = INADDR_ANY;
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

static SSL *setup_client_ssl(SSL_CTX *ctx, int client_fd)
{
	// Create SSL structure for the accepted connection
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client_fd);

	// Perform SSL/TLS handshake
	if (SSL_accept(ssl) <= 0) {
		printf("SSL handshake failed\n");
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		close(client_fd);
		return NULL;
	}

	return ssl;
}

static int verify_client_certificate(SSL *ssl)
{
	// Verify client certificate
	X509 *cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		printf("Client certificate not provided\n");
		return -1;
	}
	X509_free(cert);

	long verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		printf("Certificate verification failed: %ld\n", verify_result);
		return -1;
	}

	return 0;
}

static void spawn_client_handler(SSL *ssl, int client_fd)
{
	pthread_t client_thread;
	if (pthread_create(&client_thread, NULL, client_handler, (void *)ssl) !=
	    0) {
		perror("Failed to create client thread");
		SSL_free(ssl);
		close(client_fd);
		return;
	}
	pthread_detach(client_thread);
}

static void *start_server(void *data)
{
	struct server_args *args = data;

	// Create and configure server socket
	int server_fd = create_server_socket(args->port);

	// Accept client connections
	while (!terminate) {
		int client_fd = accept_client_connection(server_fd);
		if (client_fd == -1)
			break; // Signal interrupted
		if (client_fd == -2)
			continue; // Timeout or error, try again

		// Setup SSL for client
		SSL *ssl = setup_client_ssl(args->ctx, client_fd);
		if (!ssl)
			continue;

		// Verify client certificate
		if (verify_client_certificate(ssl) < 0) {
			SSL_shutdown(ssl);
			SSL_free(ssl);
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
	printf("  -m, --max-size N[K|M|G]  Set maximum clipboard size (0=unlimited)\n");
	printf("  -p, --oversize-policy reject|drop  Action on oversize write (default: reject)\n");
	printf("\nPort:\n");
	printf("  %d              Server port (all operations)\n", SERVER_PORT);
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
	char *max_size_arg = NULL;

	static struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
		{ "verbose", no_argument, 0, 'v' },
		{ "daemon", no_argument, 0, 'd' },
		{ "max-size", required_argument, 0, 'm' },
		{ "oversize-policy", required_argument, 0, 'p' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hvVdm:p:", long_options, NULL)) !=
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
		case 'm':
			max_size_arg = optarg;
			break;
		case 'p':
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
	SSL_CTX *ctx = init_ssl_context();
	struct server_args args = { .port = SERVER_PORT, .ctx = ctx };

	// Start server thread
	LOG_INFO("Starting server on port %d", SERVER_PORT);
	pthread_t server_thread;
	if (pthread_create(&server_thread, NULL, start_server, &args) != 0) {
		LOG_ERROR("Failed to create server thread");
		perror("Failed to create server thread");
		exit(EXIT_FAILURE);
	}

	pthread_join(server_thread, NULL);

	SSL_CTX_free(ctx);
	free(shared_buffer);
	return 0;
}
