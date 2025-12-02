/* Custom mbedTLS configuration overlay for tty-clipboard
 * This file supplements the default mbedtls_config.h
 */

/* Include the default configuration */
#include "mbedtls/mbedtls_config.h"

/* Enable PSA Crypto for TLS 1.3 support */
#ifndef MBEDTLS_USE_PSA_CRYPTO
#define MBEDTLS_USE_PSA_CRYPTO
#endif

/* Ensure PSA Crypto is enabled */
#ifndef MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_C
#endif

/* Enable TLS 1.3 */
#ifndef MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_PROTO_TLS1_3
#endif
