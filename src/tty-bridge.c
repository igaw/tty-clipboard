/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Daniel Wagner <wagi@monom.org> */

#include "config.h"
#include "tty-clipboard.h"
#include "plugin.h"
#include "plugin-registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <mbedtls/version.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <sys/select.h>
#include <sys/time.h>
#include <stdint.h>
#include <endian.h>
#include <time.h>
#include <libgen.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <protobuf-c/protobuf-c.h>
#include "clipboard.pb-c.h"
#pragma GCC diagnostic pop

static FILE *tls_debug_file = NULL;

/* TLS debug callback */
static void tls_debug(void *ctx, int level, const char *file, int line,
		      const char *msg)
{
	(void)ctx;
	FILE *out = tls_debug_file ? tls_debug_file : stderr;
	fprintf(out, "[BRIDGE] mbedtls[%d] %24s:%5d: %s", level,
		basename((char *)file), line, msg);
	fflush(out);
}

/* Custom send/recv callbacks for mbedTLS that work with raw socket fds */
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

/* SSL/TLS config - shared across connections */
typedef struct {
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt clicert;
	mbedtls_pk_context pkey;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} bridge_tls_config_t;

/* Per-connection SSL context */
typedef struct {
	mbedtls_ssl_context ssl;
	int sock_fd;
} bridge_ssl_ctx_t;


/* Server endpoint configuration */
typedef struct {
	char host[256];
	uint16_t port;
} server_endpoint_t;


/* Per-server thread context */
typedef struct {
	const plugin_interface_t *plugin;
	plugin_handle_t plugin_handle;
	server_endpoint_t server;
	char local_hostname[256];
	bridge_tls_config_t *tls_config; // shared
	bridge_ssl_ctx_t *ssl_ctx; // per-connection
	clipboard_data_t *last_local_data;
	clipboard_data_t *last_remote_data;
	pthread_mutex_t data_mutex;
	volatile sig_atomic_t *terminate;
	const char *tls_debug_log;
} bridge_server_ctx_t;

static volatile sig_atomic_t terminate = 0;

static void signal_handler(int sig)
{
	(void)sig;
	terminate = 1;
}

static int setup_signals(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGINT, &sa, NULL) < 0 ||
	    sigaction(SIGTERM, &sa, NULL) < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

/**
 * Stub getaddrinfo for static builds
 * In static builds, getaddrinfo requires nss libraries which aren't available.
 * This stub warns users that hostname resolution isn't supported in static builds.
 */
#ifdef STATIC_BUILD
static int static_getaddrinfo(const char *node, const char *service,
			      const struct addrinfo *hints,
			      struct addrinfo **res)
{
	(void)hints; /* Suppress unused parameter warning */
	(void)res;
	(void)service;

	LOG_ERROR("Hostname resolution not supported in static build: '%s'",
		  node);
	LOG_ERROR("Please use IP addresses instead (e.g., 127.0.0.1:%s)",
		  service ? service : "5457");

	return EAI_NONAME;
}

#define getaddrinfo static_getaddrinfo
#endif

/**
 * Initialize TLS configuration (called once at startup)
 */
static int tls_config_init(bridge_tls_config_t *tls_cfg)
{
	int ret;
	char cert_path[512];
	char key_path[512];
	char ca_path[512];
	char *config_path = create_xdg_config_path("tty-clipboard");

	if (!config_path) {
		LOG_ERROR("Failed to get XDG config path");
		return -1;
	}

	snprintf(cert_path, sizeof(cert_path), "%s/certs/client.crt",
		 config_path);
	snprintf(key_path, sizeof(key_path), "%s/keys/client.key", config_path);
	snprintf(ca_path, sizeof(ca_path), "%s/certs/ca.crt", config_path);

	free(config_path);

	/* Initialize configuration structures */
	mbedtls_ssl_config_init(&tls_cfg->conf);
	mbedtls_entropy_init(&tls_cfg->entropy);
	mbedtls_ctr_drbg_init(&tls_cfg->ctr_drbg);
	mbedtls_x509_crt_init(&tls_cfg->cacert);
	mbedtls_x509_crt_init(&tls_cfg->clicert);
	mbedtls_pk_init(&tls_cfg->pkey);

	/* Seed RNG with personalization string to match client */
	const char *pers = "tty_clipboard_client";
	ret = mbedtls_ctr_drbg_seed(&tls_cfg->ctr_drbg, mbedtls_entropy_func,
			    &tls_cfg->entropy, (const unsigned char *)pers, strlen(pers));
	if (ret) {
		LOG_ERROR("mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
		return -1;
	}

	/* Load CA certificate */
	ret = mbedtls_x509_crt_parse_file(&tls_cfg->cacert, ca_path);
	if (ret) {
		LOG_ERROR("Failed to load CA cert from %s: -0x%04x", ca_path,
			  -ret);
		return -1;
	}
	LOG_DEBUG("Loaded CA certificate from %s", ca_path);

	/* Load client certificate */
	LOG_DEBUG("Loading client certificate from %s", cert_path);
	ret = mbedtls_x509_crt_parse_file(&tls_cfg->clicert, cert_path);
	if (ret) {
		LOG_ERROR("Failed to load client cert from %s: -0x%04x",
			  cert_path, -ret);
		return -1;
	}
	LOG_DEBUG("Loading client private key from %s", key_path);
	/* Load client private key */
#ifdef MBEDTLS_3X
	ret = mbedtls_pk_parse_keyfile(&tls_cfg->pkey, key_path, NULL,
				       mbedtls_ctr_drbg_random,
				       &tls_cfg->ctr_drbg);
#else
	ret = mbedtls_pk_parse_keyfile(&tls_cfg->pkey, key_path, NULL);
#endif
	if (ret) {
		LOG_ERROR("Failed to load client key from %s: -0x%04x",
			  key_path, -ret);
		return -1;
	}

	/* Configure SSL */
	ret = mbedtls_ssl_config_defaults(&tls_cfg->conf, MBEDTLS_SSL_IS_CLIENT,
					  MBEDTLS_SSL_TRANSPORT_STREAM,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret) {
		LOG_ERROR("mbedtls_ssl_config_defaults failed: -0x%04x", -ret);
		return -1;
	}

	mbedtls_ssl_conf_rng(&tls_cfg->conf, mbedtls_ctr_drbg_random,
			     &tls_cfg->ctr_drbg);

	/* Set TLS version constraints - prefer TLS 1.3 when available */
#ifdef MBEDTLS_3X
	mbedtls_ssl_conf_min_tls_version(&tls_cfg->conf,
					 MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(&tls_cfg->conf,
					 MBEDTLS_SSL_VERSION_TLS1_3);
#else
	/* mbedTLS 2.x supports up to TLS 1.2 only */
	mbedtls_ssl_conf_min_version(&tls_cfg->conf,
				     MBEDTLS_SSL_MAJOR_VERSION_3,
				     MBEDTLS_SSL_MINOR_VERSION_3);
	mbedtls_ssl_conf_max_version(&tls_cfg->conf,
				     MBEDTLS_SSL_MAJOR_VERSION_3,
				     MBEDTLS_SSL_MINOR_VERSION_3);
#endif

	/* Optional debug: enable detailed mbedTLS logging when MBEDTLS_DEBUG env var is set */
	const char *dbg = getenv("MBEDTLS_DEBUG");
	if (dbg && *dbg) {
		mbedtls_debug_set_threshold(4);
		mbedtls_ssl_conf_dbg(&tls_cfg->conf, tls_debug, NULL);
	}

	/* Set CA certificate for verification */
	mbedtls_ssl_conf_ca_chain(&tls_cfg->conf, &tls_cfg->cacert, NULL);

	/* Configure client certificate and key */
	ret = mbedtls_ssl_conf_own_cert(&tls_cfg->conf, &tls_cfg->clicert,
					&tls_cfg->pkey);
	if (ret) {
		LOG_ERROR("mbedtls_ssl_conf_own_cert failed: -0x%04x", -ret);
		return -1;
	}

	/* Require server certificate verification */
	mbedtls_ssl_conf_authmode(&tls_cfg->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	return 0;
}

static void tls_config_cleanup(bridge_tls_config_t *tls_cfg)
{
	mbedtls_ssl_config_free(&tls_cfg->conf);
	mbedtls_entropy_free(&tls_cfg->entropy);
	mbedtls_ctr_drbg_free(&tls_cfg->ctr_drbg);
	mbedtls_x509_crt_free(&tls_cfg->cacert);
	mbedtls_x509_crt_free(&tls_cfg->clicert);
	mbedtls_pk_free(&tls_cfg->pkey);
}

static void ssl_context_free(bridge_ssl_ctx_t *ssl_ctx)
{
	if (!ssl_ctx)
		return;

	mbedtls_ssl_close_notify(&ssl_ctx->ssl);
	mbedtls_ssl_free(&ssl_ctx->ssl);

	if (ssl_ctx->sock_fd >= 0) {
		close(ssl_ctx->sock_fd);
	}

	free(ssl_ctx);
}

/**
 * Allocate and initialize a new bridge_ssl_ctx_t, similar to client init_ssl_context
 */
static bridge_ssl_ctx_t *ssl_context_create(bridge_tls_config_t *tls_cfg,
					    int sock_fd)
{
	int ret;
	bridge_ssl_ctx_t *ssl_ctx = calloc(1, sizeof(bridge_ssl_ctx_t));
	if (!ssl_ctx) {
		LOG_ERROR("Unable to allocate SSL context");
		return NULL;
	}

	mbedtls_ssl_init(&ssl_ctx->ssl);
	ssl_ctx->sock_fd = sock_fd;

	// Setup the SSL context with the shared configuration
	ret = mbedtls_ssl_setup(&ssl_ctx->ssl, &tls_cfg->conf);
	if (ret) {
		LOG_ERROR("mbedtls_ssl_setup failed: -0x%04x", -ret);
		free(ssl_ctx);
		return NULL;
	}


#ifdef MBEDTLS_3X
	// mbedTLS 3.x requires setting hostname, matching the CN in our certificates
	ret = mbedtls_ssl_set_hostname(&ssl_ctx->ssl, "tty-clipboard-server");
	if (ret != 0) {
		LOG_ERROR("mbedtls_ssl_set_hostname failed: -0x%04x", -ret);
		mbedtls_ssl_free(&ssl_ctx->ssl);
		free(ssl_ctx);
		return NULL;
	}
	LOG_DEBUG("Hostname set to 'tty-clipboard-server' for certificate verification");
#endif

	return ssl_ctx;
}

/**
 * Send protobuf message to server
 */
static int send_protobuf_message(mbedtls_ssl_context *ssl,
				 ProtobufCMessage *msg)
{
	size_t size = protobuf_c_message_get_packed_size(msg);
	unsigned char *buf = malloc(size);
	if (!buf)
		return -1;

	/* Pack message */
	protobuf_c_message_pack(msg, buf);

	/* Send length as big-endian uint64 */
	uint64_t len = htobe64(size);
	if (mbedtls_ssl_write(ssl, (unsigned char *)&len, sizeof(len)) <= 0) {
		free(buf);
		return -1;
	}

	/* Send message in chunks */
	size_t total = 0;
	while (total < size) {
		int w = mbedtls_ssl_write(ssl, (unsigned char *)buf + total,
					  size - total);
		if (w <= 0) {
			free(buf);
			return -1;
		}
		total += (size_t)w;
	}

	free(buf);
	return 0;
}

/**
 * Receive protobuf message from server
 */
static Ttycb__Envelope *receive_protobuf_message(mbedtls_ssl_context *ssl)
{
	uint64_t len_be;
	int r = mbedtls_ssl_read(ssl, (unsigned char *)&len_be, sizeof(len_be));
	if (r <= 0) {
		if (terminate || r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			return NULL;
		LOG_ERROR("mbedtls_ssl_read prefix failed: -0x%04x", -r);
		return NULL;
	}

	size_t size = be64toh(len_be);
	if (size == 0 || size > 10 * 1024 * 1024) { /* 10MB sanity limit */
		LOG_ERROR("Invalid message size: %zu", size);
		return NULL;
	}

	unsigned char *buf = malloc(size);
	if (!buf)
		return NULL;

	size_t total = 0;
	while (total < size) {
		int rr = mbedtls_ssl_read(ssl, (unsigned char *)buf + total,
					  size - total);
		if (rr <= 0) {
			if (terminate ||
			    rr == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				free(buf);
				return NULL;
			}
			LOG_ERROR("mbedtls_ssl_read msg failed: -0x%04x", -rr);
			free(buf);
			return NULL;
		}
		total += (size_t)rr;
	}

	Ttycb__Envelope *env = ttycb__envelope__unpack(NULL, size, buf);
	free(buf);
	return env;
}

/**
 * Connect to clipboard server
 * [Force rebuild: 2025-12-05]
 */
static int connect_to_server(bridge_server_ctx_t *ctx, const char *host, uint16_t port)
{
	int ret;

	LOG_INFO("Connecting to %s:%u", host, port);

	/* Try direct IP address first (avoids getaddrinfo for simple IPs) */
	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port);

	int sock = -1;

	/* Try inet_pton first - works for IP addresses without getaddrinfo warning */
	if (inet_pton(AF_INET, host, &server_address.sin_addr) > 0) {
		/* Valid IP address, try direct connection */
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock >= 0) {
			if (connect(sock, (struct sockaddr *)&server_address,
				    sizeof(server_address)) == 0) {
				LOG_DEBUG("Connected to IP address %s:%u", host,
					  port);
				goto tls_setup;
			}
			LOG_DEBUG("Connection attempt failed with errno %d %s",
				  errno, strerror(errno));
			close(sock);
			sock = -1;
		}
	}

	/* Fall back to getaddrinfo for hostnames */
	struct addrinfo hints, *result, *rp;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%u", port);

	int gai_ret = getaddrinfo(host, port_str, &hints, &result);
	if (gai_ret != 0) {
		LOG_ERROR("Failed to resolve hostname %s: %s", host,
			  gai_strerror(gai_ret));
		return -1;
	}

	/* Try to connect to each resolved address */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock < 0) {
			continue;
		}

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
			break; /* Successfully connected */
		}

		close(sock);
		sock = -1;
	}

	freeaddrinfo(result);

	if (sock < 0) {
		LOG_ERROR("Connection to %s:%u failed: %s", host, port,
			  strerror(errno));
		return -1;
	}

tls_setup:

	LOG_DEBUG("TCP connection established");

	/* Set socket receive timeout to allow periodic checking of terminate flag */
	struct timeval tv;
	tv.tv_sec = 2; /* 2 second timeout */
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv,
		       sizeof(tv)) < 0) {
		LOG_WARN("Failed to set socket timeout: %s", strerror(errno));
		/* Continue anyway - timeout not critical */
	}

	/* Create a fresh SSL context for this connection */
	ctx->ssl_ctx = ssl_context_create(ctx->tls_config, sock);
	if (!ctx->ssl_ctx) {
		LOG_ERROR("Failed to create SSL context");
		close(sock);
		return -1;
	}

	/* Set the socket for the SSL session using custom callbacks */
	mbedtls_ssl_set_bio(&ctx->ssl_ctx->ssl, (void *)(intptr_t)sock,
				ssl_send_callback, ssl_recv_callback, NULL);

	/* Perform SSL handshake (loop for WANT_READ/WANT_WRITE) */
	LOG_DEBUG("Performing SSL handshake");
	while ((ret = mbedtls_ssl_handshake(&ctx->ssl_ctx->ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			LOG_ERROR("SSL handshake to %s:%u failed: -0x%04x", host, port, -ret);
			ssl_context_free(ctx->ssl_ctx);
			ctx->ssl_ctx = NULL;
			return -1;
		}
	}

	LOG_INFO("Connected to server");
	LOG_INFO("Connected to server");

	/* Generate a random client_id using the DRBG, as in tty-client */
	uint64_t client_id = 0;
	if (mbedtls_ctr_drbg_random(&ctx->tls_config->ctr_drbg,
				    (unsigned char *)&client_id,
				    sizeof(client_id)) != 0) {
		LOG_ERROR("Failed to generate client_id");
		ssl_context_free(ctx->ssl_ctx);
		ctx->ssl_ctx = NULL;
		return -1;
	}
	if (client_id == 0)
		client_id = 1; // ensure non-zero
	LOG_DEBUG("Generated client_id: %lu", client_id);

	/* Send initial SUBSCRIBE request to start receiving updates */
	Ttycb__SubscribeRequest sub = TTYCB__SUBSCRIBE_REQUEST__INIT;
	Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;
	sub.client_id = client_id;
	env.body_case = TTYCB__ENVELOPE__BODY_SUBSCRIBE;
	env.subscribe = &sub;

	if (send_protobuf_message(&ctx->ssl_ctx->ssl, &env.base) < 0) {
		LOG_ERROR("Failed to send initial SUBSCRIBE request");
		ssl_context_free(ctx->ssl_ctx);
		ctx->ssl_ctx = NULL;
		return -1;
	}

	LOG_DEBUG("Sent initial SUBSCRIBE request to server");
	return 0;
}

/**
 * Send clipboard data to server
 */
static int send_to_server(bridge_server_ctx_t *ctx, const clipboard_data_t *data)
{
	Ttycb__WriteRequest write = TTYCB__WRITE_REQUEST__INIT;
	Ttycb__Envelope env = TTYCB__ENVELOPE__INIT;

	write.data.data = data->data;
	write.data.len = data->size;

	/* Set metadata - hostname is a non-const pointer in protobuf */
	write.hostname = (char *)data->metadata.hostname;
	write.timestamp = data->metadata.timestamp;
	write.write_uuid.data = (uint8_t *)data->metadata.write_uuid;
	write.write_uuid.len = UUID_SIZE;

	env.body_case = TTYCB__ENVELOPE__BODY_WRITE;
	env.write = &write;

	return send_protobuf_message(&ctx->ssl_ctx->ssl, &env.base);
}

/**
 * Receive clipboard data from server
 */
static int receive_from_server(bridge_server_ctx_t *ctx, clipboard_data_t **out_data)
{
	Ttycb__Envelope *env = receive_protobuf_message(&ctx->ssl_ctx->ssl);
	if (!env)
		return -1;

	if (env->body_case != TTYCB__ENVELOPE__BODY_DATA) {
		LOG_ERROR("Expected DataFrame, got %d", env->body_case);
		ttycb__envelope__free_unpacked(env, NULL);
		return -1;
	}

	Ttycb__DataFrame *frame = env->data;
	clipboard_data_t *data = allocate_clipboard_data(frame->data.len);
	if (!data) {
		ttycb__envelope__free_unpacked(env, NULL);
		return -1;
	}

	memcpy(data->data, frame->data.data, frame->data.len);

	/* Extract metadata */
	if (frame->hostname) {
		strncpy(data->metadata.hostname, frame->hostname,
			sizeof(data->metadata.hostname) - 1);
		data->metadata.hostname[sizeof(data->metadata.hostname) - 1] =
			'\0';
	}
	data->metadata.timestamp = frame->timestamp;

	if (frame->write_uuid.len == UUID_SIZE) {
		memcpy(data->metadata.write_uuid, frame->write_uuid.data,
		       UUID_SIZE);
	}

	*out_data = data;
	ttycb__envelope__free_unpacked(env, NULL);
	return 0;
}

/**
 * Check if two clipboard data are identical (including metadata)
 */
static int clipboard_data_equal(const clipboard_data_t *a,
				const clipboard_data_t *b)
{
	if (!a || !b)
		return 0;

	if (a->size != b->size)
		return 0;

	if (memcmp(a->data, b->data, a->size) != 0)
		return 0;

	/* Compare metadata */
	if (strcmp(a->metadata.hostname, b->metadata.hostname) != 0)
		return 0;

	if (a->metadata.timestamp != b->metadata.timestamp)
		return 0;

	if (memcmp(a->metadata.write_uuid, b->metadata.write_uuid, UUID_SIZE) !=
	    0)
		return 0;

	return 1;
}

/**
 * Local clipboard -> Server (Wayland/Klipper -> TTY)
 */
static void *local_to_server_thread(void *arg)
{
	bridge_server_ctx_t *ctx = (bridge_server_ctx_t *)arg;

	LOG_INFO("Starting local->server thread");

	while (!terminate) {
		clipboard_data_t *data = ctx->plugin->read(ctx->plugin_handle);
		if (!data) {
			sleep(1);
			continue;
		}

		pthread_mutex_lock(&ctx->data_mutex);

		/* Check if this is the same data we just received from server */
		if (!clipboard_data_equal(data, ctx->last_remote_data)) {
			/* New data from local clipboard, send to server */
			LOG_DEBUG("Sending %zu bytes to server", data->size);
			if (send_to_server(ctx, data) < 0) {
				LOG_ERROR("Failed to send to server");
			}

			if (ctx->last_local_data) {
				ctx->plugin->free_clipboard_data(
					ctx->last_local_data);
			}
			ctx->last_local_data = data;
		} else {
			/* This is data we just wrote, skip it to prevent feedback loop */
			LOG_DEBUG(
				"Skipping echo: data matches last remote write");
			ctx->plugin->free_clipboard_data(data);
		}

		pthread_mutex_unlock(&ctx->data_mutex);
		sleep(1);
	}

	return NULL;
}

/**
 * Server -> Local clipboard (TTY -> Wayland/Klipper)
 */
static void *server_to_local_thread(void *arg)
{
	bridge_server_ctx_t *ctx = (bridge_server_ctx_t *)arg;

	LOG_INFO("Starting server->local thread");

	while (!terminate) {
		clipboard_data_t *data = NULL;
		if (receive_from_server(ctx, &data) < 0) {
			LOG_ERROR(
				"Failed to receive from server, reconnecting...");
			sleep(2);
			continue;
		}

		if (!data) {
			sleep(1);
			continue;
		}

		pthread_mutex_lock(&ctx->data_mutex);

		/* Check if this is the same data we just sent */
		if (!clipboard_data_equal(data, ctx->last_local_data)) {
			/* New data from server, write to local clipboard */
			LOG_DEBUG("Received %zu bytes from server (from %s)",
				  data->size, data->metadata.hostname);
			if (ctx->plugin->write(ctx->plugin_handle, data) < 0) {
				LOG_ERROR("Failed to write to local clipboard");
			} else {
				if (ctx->last_remote_data) {
					ctx->plugin->free_clipboard_data(
						ctx->last_remote_data);
				}
				ctx->last_remote_data = data;
			}
		} else {
			/* This is data we just sent, skip it to prevent feedback loop */
			LOG_DEBUG(
				"Skipping echo: data matches last local write");
			ctx->plugin->free_clipboard_data(data);
		}

		pthread_mutex_unlock(&ctx->data_mutex);
	}

	return NULL;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] --plugin <wayland|klipper|mock> --server <IP1:PORT1>[,<IP2:PORT2>]\n",
		prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "OPTIONS:\n");
	fprintf(stderr,
		"  -p, --plugin <name>     Clipboard plugin (wayland, klipper, mock)\n");
	fprintf(stderr,
		"  -s, --server <servers>  Server endpoints (IP:PORT format, comma-separated)\n");
	fprintf(stderr, "  -v, --verbose           Verbose output\n");
	fprintf(stderr, "  -d, --debug             Debug output\n");
	fprintf(stderr,
		"  --tls-debug-log <file>  Write TLS debug output to file (requires MBEDTLS_DEBUG=1)\n");
	fprintf(stderr, "  -h, --help              Show this help\n");
}


// Thread function for each server connection

static void *server_thread_func(void *arg) {
	bridge_server_ctx_t *ctx = (bridge_server_ctx_t *)arg;
	while (!*(ctx->terminate)) {
		// Connect to server (creates socket, TLS, handshake, subscribe)
		if (connect_to_server(ctx, ctx->server.host, ctx->server.port) != 0) {
			LOG_ERROR("[thread] Failed to connect to %s:%u, retrying...", ctx->server.host, ctx->server.port);
			sleep(2);
			continue;
		}

		// Start protocol threads (local->server, server->local)
		pthread_t l2s_thread, s2l_thread;
		if (pthread_create(&l2s_thread, NULL, local_to_server_thread, ctx) < 0) {
			LOG_ERROR("[thread] Failed to create local->server thread");
			ssl_context_free(ctx->ssl_ctx);
			ctx->ssl_ctx = NULL;
			sleep(2);
			continue;
		}
		if (pthread_create(&s2l_thread, NULL, server_to_local_thread, ctx) < 0) {
			LOG_ERROR("[thread] Failed to create server->local thread");
			*(ctx->terminate) = 1;
			pthread_join(l2s_thread, NULL);
			ssl_context_free(ctx->ssl_ctx);
			ctx->ssl_ctx = NULL;
			sleep(2);
			continue;
		}

		pthread_join(l2s_thread, NULL);
		pthread_join(s2l_thread, NULL);

		// Clean up connection
		if (ctx->ssl_ctx) {
			ssl_context_free(ctx->ssl_ctx);
			ctx->ssl_ctx = NULL;
		}
		// If not terminating, reconnect after delay
		if (!*(ctx->terminate)) {
			LOG_INFO("[thread] Disconnected, will attempt reconnect");
			sleep(2);
		}
	}
	return NULL;
}


int main(int argc, char **argv)
{
	// Install signal handlers for clean shutdown
	if (setup_signals() < 0) {
		LOG_ERROR("Failed to set up signal handlers");
		return 1;
	}
	// CLI/config parsing
	const char *plugin_name = NULL;
	const char *tls_debug_log = NULL;
	server_endpoint_t servers[2];
	int num_servers = 0;
	char local_hostname[256] = {0};
	const plugin_interface_t *plugin = NULL;
	plugin_handle_t plugin_handle = NULL;

	struct option long_opts[] = { { "plugin", required_argument, 0, 'p' },
								  { "server", required_argument, 0, 's' },
								  { "verbose", no_argument, 0, 'v' },
								  { "debug", no_argument, 0, 'd' },
								  { "help", no_argument, 0, 'h' },
								  { "tls-debug-log", required_argument, 0, 1 },
								  { 0, 0, 0, 0 } };
	int opt;
	while ((opt = getopt_long(argc, argv, "p:s:vdh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'p':
			plugin_name = optarg;
			break;
		case 's': {
			char *server_str = strdup(optarg);
			if (!server_str) {
				LOG_ERROR("Memory allocation failed");
				return 1;
			}
			char *saveptr = NULL;
			char *token = strtok_r(server_str, ",", &saveptr);
			int server_idx = 0;
			while (token && server_idx < 2) {
				char host[256];
				uint16_t port;
				if (sscanf(token, "%255[^:]:%hu", host, &port) != 2) {
					LOG_ERROR("Invalid server format: %s (expected IP:PORT)", token);
					free(server_str);
					return 1;
				}
				strncpy(servers[server_idx].host, host, sizeof(servers[server_idx].host) - 1);
				servers[server_idx].port = port;
				server_idx++;
				token = strtok_r(NULL, ",", &saveptr);
			}
			num_servers = server_idx;
			free(server_str);
			if (num_servers == 0) {
				LOG_ERROR("No valid servers specified");
				return 1;
			}
			break;
		}
		case 'v':
			current_log_level = LOG_LEVEL_INFO;
			break;
		case 'd':
			current_log_level = LOG_LEVEL_DEBUG;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case 1:
			tls_debug_log = optarg;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!plugin_name || num_servers == 0) {
		LOG_ERROR("Missing required arguments");
		usage(argv[0]);
		return 1;
	}

	plugin = get_plugin_by_name(plugin_name);
	if (!plugin) {
		LOG_ERROR("Plugin '%s' not found. Available plugins: wayland, klipper, mock", plugin_name);
		return 1;
	}
	plugin_handle = plugin->init();
	if (!plugin_handle) {
		LOG_ERROR("Failed to initialize %s plugin", plugin_name);
		return 1;
	}
	LOG_INFO("Initialized %s plugin", plugin->name);

	if (gethostname(local_hostname, sizeof(local_hostname) - 1) < 0) {
		LOG_WARN("Failed to get hostname");
		strcpy(local_hostname, "unknown");
	}

	// Open TLS debug file if debugging is enabled
	const char *dbg = getenv("MBEDTLS_DEBUG");
	if (dbg && *dbg) {
		const char *debug_filename;
		char auto_filename[1024];
		if (tls_debug_log) {
			debug_filename = tls_debug_log;
		} else {
			snprintf(auto_filename, sizeof(auto_filename),
					 "/tmp/tty-bridge-%s-%s-%u-tls-debug.log",
					 local_hostname, servers[0].host, servers[0].port);
			debug_filename = auto_filename;
		}
		tls_debug_file = fopen(debug_filename, "w");
		if (tls_debug_file) {
			fprintf(stderr, "[BRIDGE] TLS debug output redirected to %s\n", debug_filename);
		} else {
			fprintf(stderr, "[BRIDGE] Warning: Failed to open TLS debug file: %s\n", debug_filename);
		}
	}

	// Initialize TLS configuration (shared)
	bridge_tls_config_t tls_config;
	memset(&tls_config, 0, sizeof(tls_config));
	if (tls_config_init(&tls_config) < 0) {
		LOG_ERROR("Failed to initialize TLS configuration");
		return 1;
	}

	// Prepare per-server thread contexts
	pthread_t server_threads[2];
	bridge_server_ctx_t server_ctxs[2];
	for (int i = 0; i < num_servers; ++i) {
		memset(&server_ctxs[i], 0, sizeof(bridge_server_ctx_t));
		server_ctxs[i].plugin = plugin;
		server_ctxs[i].plugin_handle = plugin_handle;
		server_ctxs[i].server = servers[i];
		strncpy(server_ctxs[i].local_hostname, local_hostname, sizeof(server_ctxs[i].local_hostname)-1);
		server_ctxs[i].tls_config = &tls_config;
		pthread_mutex_init(&server_ctxs[i].data_mutex, NULL);
		server_ctxs[i].terminate = &terminate;
		server_ctxs[i].tls_debug_log = tls_debug_log;
		pthread_create(&server_threads[i], NULL, server_thread_func, &server_ctxs[i]);
	}

	// Main thread waits for all server threads
	for (int i = 0; i < num_servers; ++i) {
		pthread_join(server_threads[i], NULL);
		pthread_mutex_destroy(&server_ctxs[i].data_mutex);
	}

	// Cleanup
	tls_config_cleanup(&tls_config);
	plugin->cleanup(plugin_handle);
	if (tls_debug_file) fclose(tls_debug_file);
	return 0;
}
