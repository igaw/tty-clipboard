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
#if HAVE_PROTOBUF
#include <protobuf-c/protobuf-c.h>
#include "clipboard.pb-c.h"
#endif

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

// Protobuf client handler
void *client_handler(void *arg)
{
	SSL *ssl = (SSL *)arg;

	// Protobuf envelope handler
	while (!terminate) {
		// Read envelope frame
		uint64_t be_len = 0;
		int rr = SSL_read(ssl, &be_len, sizeof(be_len));
		if (rr <= 0)
			break;
		size_t mlen = (size_t)be64toh(be_len);
		if (mlen == 0)
			continue;
		unsigned char *mbuf = malloc(mlen);
		if (!mbuf)
			break;
		if (ssl_read_all(ssl, mbuf, mlen) < 0) {
			free(mbuf);
			break;
		}
		Ttycb__Envelope *env =
			ttycb__envelope__unpack(NULL, mlen, mbuf);
		free(mbuf);
		if (!env) {
			printf("Failed to unpack envelope\n");
			break;
		}

		// Handle message types
		if (env->body_case == TTYCB__ENVELOPE__BODY_WRITE &&
		    env->write) {
			size_t len = env->write->data.len;
			const unsigned char *data = env->write->data.data;
			int oversize =
				(max_buffer_size && len > max_buffer_size);
			if (oversize) {
				int ok = (oversize_policy == OVERSIZE_DROP);
				// Update nothing
				Ttycb__Envelope resp = TTYCB__ENVELOPE__INIT;
				Ttycb__WriteResponse wr =
					TTYCB__WRITE_RESPONSE__INIT;
				wr.ok = ok;
				if (!ok)
					wr.message = (char *)"oversize";
				wr.message_id =
					0; // No message_id for rejected writes
				resp.write_resp = &wr;
				resp.body_case =
					TTYCB__ENVELOPE__BODY_WRITE_RESP;
				size_t outsz =
					ttycb__envelope__get_packed_size(&resp);
				unsigned char *outbuf = malloc(outsz);
				if (!outbuf) {
					ttycb__envelope__free_unpacked(env,
								       NULL);
					break;
				}
				ttycb__envelope__pack(&resp, outbuf);
				uint64_t pfx = htobe64((uint64_t)outsz);
				if (ssl_write_all(ssl, &pfx, sizeof(pfx)) < 0 ||
				    ssl_write_all(ssl, outbuf, outsz) < 0) {
					free(outbuf);
					ttycb__envelope__free_unpacked(env,
								       NULL);
					break;
				}
				free(outbuf);
				ttycb__envelope__free_unpacked(env, NULL);
				continue;
			}
			// store
			pthread_mutex_lock(&buffer_mutex);
			if (len > shared_capacity) {
				char *nbuf = realloc(shared_buffer, len);
				if (!nbuf) {
					pthread_mutex_unlock(&buffer_mutex);
					ttycb__envelope__free_unpacked(env,
								       NULL);
					break;
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
			// reply ok
			Ttycb__Envelope resp = TTYCB__ENVELOPE__INIT;
			Ttycb__WriteResponse wr = TTYCB__WRITE_RESPONSE__INIT;
			wr.ok = 1;
			wr.message_id = msg_id;
			resp.write_resp = &wr;
			resp.body_case = TTYCB__ENVELOPE__BODY_WRITE_RESP;
			size_t outsz = ttycb__envelope__get_packed_size(&resp);
			unsigned char *outbuf = malloc(outsz);
			if (!outbuf) {
				ttycb__envelope__free_unpacked(env, NULL);
				break;
			}
			ttycb__envelope__pack(&resp, outbuf);
			uint64_t pfx = htobe64((uint64_t)outsz);
			if (ssl_write_all(ssl, &pfx, sizeof(pfx)) < 0 ||
			    ssl_write_all(ssl, outbuf, outsz) < 0) {
				free(outbuf);
				ttycb__envelope__free_unpacked(env, NULL);
				break;
			}
			free(outbuf);
		} else if (env->body_case == TTYCB__ENVELOPE__BODY_READ &&
			   env->read) {
			pthread_mutex_lock(&buffer_mutex);
			size_t len = shared_length;
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
				ttycb__envelope__free_unpacked(env, NULL);
				break;
			}
			ttycb__envelope__pack(&resp, outbuf);
			pthread_mutex_unlock(&buffer_mutex);
			uint64_t pfx = htobe64((uint64_t)outsz);
			if (ssl_write_all(ssl, &pfx, sizeof(pfx)) < 0 ||
			    ssl_write_all(ssl, outbuf, outsz) < 0) {
				free(outbuf);
				ttycb__envelope__free_unpacked(env, NULL);
				break;
			}
			free(outbuf);
		} else if (env->body_case == TTYCB__ENVELOPE__BODY_SUBSCRIBE &&
			   env->subscribe) {
			pthread_mutex_lock(&buffer_mutex);
			unsigned int seen =
				gen; // Start from current generation to only receive future updates
			uint64_t last_sent_message_id =
				shared_message_id; // Track last message_id sent to this subscriber
			pthread_mutex_unlock(&buffer_mutex);
			while (!terminate) {
				pthread_mutex_lock(&buffer_mutex);
				while (seen == gen && !terminate)
					pthread_cond_wait(&buffer_cond,
							  &buffer_mutex);
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
				size_t outsz =
					ttycb__envelope__get_packed_size(&resp);
				unsigned char *outbuf = malloc(outsz);
				if (!outbuf) {
					pthread_mutex_unlock(&buffer_mutex);
					break;
				}
				ttycb__envelope__pack(&resp, outbuf);
				pthread_mutex_unlock(&buffer_mutex);
				uint64_t pfx = htobe64((uint64_t)outsz);
				if (ssl_write_all(ssl, &pfx, sizeof(pfx)) < 0 ||
				    ssl_write_all(ssl, outbuf, outsz) < 0) {
					free(outbuf);
					break;
				}
				free(outbuf);
			}
		} else {
			// Unknown: ignore
		}
		ttycb__envelope__free_unpacked(env, NULL);
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
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt,
		       sizeof(opt)) == -1) {
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

		struct timeval timeout = { 1, 0 }; // Check periodically

		int ready =
			select(server_fd + 1, &readfds, NULL, NULL, &timeout);
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
			if ((client_fd = accept(server_fd,
						(struct sockaddr *)&address,
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

int main(int argc, char *argv[])
{
	int opt;
	int daemon_mode = 0;
	char *max_size_arg = NULL;

	static struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ "daemon", no_argument, 0, 'd' },
		{ "max-size", required_argument, 0, 'm' },
		{ "oversize-policy", required_argument, 0, 'p' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hvdm:p:", long_options, NULL)) !=
	       -1) {
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

	// Parse max size argument if provided
	if (max_size_arg) {
		char *end = NULL;
		unsigned long long v = strtoull(max_size_arg, &end, 10);
		if (end == max_size_arg) {
			fprintf(stderr, "Invalid --max-size value: %s\n",
				max_size_arg);
			exit(EXIT_FAILURE);
		}
		unsigned long long mult = 1ULL;
		if (*end) {
			if (end[1] != '\0') {
				fprintf(stderr,
					"Invalid --max-size suffix: %s\n", end);
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
			fprintf(stderr, "--max-size value too large: %s\n",
				max_size_arg);
			exit(EXIT_FAILURE);
		}
		max_buffer_size = (size_t)result;
		printf("Configured max clipboard size: %zu bytes\n",
		       max_buffer_size);
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
			printf("Server started in background with PID: %d\n",
			       pid);
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

	// Allocate initial shared buffer
	shared_capacity = BUFFER_SIZE;
	shared_buffer = malloc(shared_capacity);
	if (!shared_buffer) {
		perror("malloc shared buffer");
		exit(EXIT_FAILURE);
	}
	shared_length = 0;
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
	free(shared_buffer);
	return 0;
}
