#include "tty-clipboard.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

volatile sig_atomic_t terminate = 0;

// Signal handler
void handle_sigint(int sig)
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
		perror("Unable to create path for server certificate\n");
		exit(EXIT_FAILURE);
	}

	if (asprintf(&key, "%s/keys/client.key", path) < 0) {
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
		//size_t len = strlen(buffer);
		//printf("len %ld, buffer '%s'\n", len, buffer);
		fprintf(stdout, "%s\n", buffer);
		fflush(stdout);

	//	if (write(STDOUT_FILENO, buffer, len) != bytes_read)
	//		handle_error("write to stdout");
		// printf("\n");
	}
	if (bytes_read < 0)
		handle_error("SSL_read");
}

void write_to_server(SSL *ssl)
{
	char buffer[BUFFER_SIZE];
	ssize_t bytes_read, bytes_written;
//	printf("%s:%d\n", __func__, __LINE__);

	while ((bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE - 1)) > 0) {
		buffer[bytes_read] = 0;
		size_t len = strlen(buffer);
		if (buffer[len - 1] == '\n') {
			buffer[len - 1] = '\0';
			len--;
		}
//		printf("len %ld buffer '%s'\n", len, buffer);
		bytes_written = SSL_write(ssl, buffer, len);
		if (bytes_written <= 0)
			handle_error("error writing to server");
	}
	if (bytes_read < 0)
		handle_error("read from stdin");
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <read/write> <server_ip> [sync]\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	const char *role = argv[1];
	const char *server_ip = argv[2];
	int server_port;

	int sync = 0;
	if (argc > 3) {
		if (!strcmp("sync", argv[3]))
			sync = 1;
	}

	if (!strcmp(role, "read")) {
		if (sync)
			server_port = READ_BLOCKED_PORT;
		else
			server_port = READ_PORT;
	} else
		server_port = WRITE_PORT;

	// Set up signal handling
	struct sigaction sa;
	sa.sa_handler = handle_sigint;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

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
