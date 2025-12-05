# TLS Debugging Guide

This document describes how to enable and use the TLS debugging feature in tty-clipboard. The server, client, and bridge all support detailed mbedTLS debug logging for troubleshooting SSL/TLS handshake issues.

## Quick Start

To enable TLS debugging, set the `MBEDTLS_DEBUG` environment variable to `1`:

```bash
# Debug client operations
MBEDTLS_DEBUG=1 tty-cb-client -s 192.168.1.100 read

# Debug server startup
MBEDTLS_DEBUG=1 tty-cb-server -b 192.168.1.100 -p 5457

# Debug bridge operations
MBEDTLS_DEBUG=1 tty-cb-bridge --plugin wayland -s 192.168.1.100 -P 5457,5458
```

Debug output is written to stderr and shows detailed information about the TLS handshake process.

## Bridge Testing with Debug Output

The mock bridge test respects the `MBEDTLS_DEBUG` environment variable:

```bash
MBEDTLS_DEBUG=1 meson test -C .build -v bridge-mock
```

When enabled, this will:
1. Enable detailed TLS debug output for all components (servers, client, bridge)
2. Capture server logs to files:
   - `.build/tests/test-bridge-mock-tmp/remote_server.log`
   - `.build/tests/test-bridge-mock-tmp/local_server.log`
   - `.build/tests/test-bridge-mock-tmp/bridge.log`
3. Display all logs when SSL errors occur

## Understanding Debug Output

Each debug line from mbedTLS includes:

```
mbedtls[LEVEL] FILENAME:LINE: MESSAGE
```

Where:
- **LEVEL**: Debug verbosity level (1-4, higher = more verbose)
  - Level 1: Basic information
  - Level 2: Verbose details
  - Level 3: Very verbose - internal state
  - Level 4: Most verbose - hex dumps of data
- **FILENAME**: The mbedTLS source file that generated the message
- **LINE**: Line number in that source file
- **MESSAGE**: Detailed debug information

### Example Debug Output

```
mbedtls[4]                ssl_tls.c: 1344: The SSL configuration is TLS 1.3 or TLS 1.2.
mbedtls[3]             ssl_client.c:  370: client hello, add ciphersuite: c030, TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
mbedtls[2]                ssl_msg.c: 2354: => flush output
mbedtls[2]                ssl_tls.c: 4586: client state: MBEDTLS_SSL_CLIENT_HELLO
```

## Common TLS Issues and Solutions

### SSL Handshake Fails with -0x3e00

```
[ERROR] Failed to load client cert from /path/to/client.crt: -0x3e00
```

**Solution:** Check that the certificate file exists and is readable:
```bash
ls -la ~/.config/tty-clipboard/certs/
ls -la ~/.config/tty-clipboard/keys/
```

The default XDG paths are:
- Certificates: `$XDG_CONFIG_HOME/tty-clipboard/certs/client.crt`
- Private key: `$XDG_CONFIG_HOME/tty-clipboard/keys/client.key`
- CA certificate: `$XDG_CONFIG_HOME/tty-clipboard/certs/ca.crt`

### SSL Handshake Fails with -0x004c

```
[ERROR] SSL handshake to 192.168.1.100:5457 failed: -0x004c
```

**Error Code:** NET - Reading information from the socket failed

**Possible Causes:**
1. Network connectivity issue (host unreachable, port not open)
2. Server not listening on that IP/port
3. Server closed connection during handshake

**Solution:**
- Verify server is running: `ps aux | grep tty-cb-server`
- Check port is open: `netstat -tlnp | grep 5457`
- Enable debug on both server and client to see where handshake fails
- Check firewall rules

### SSL Handshake Fails with -0x5d80

```
[ERROR] mbedtls_ssl_handshake failed: -0x5d80
```

**Error Code:** SSL - The handshake protocol is invalid

**Possible Causes:**
1. Client and server using incompatible TLS versions
2. Certificate validation failure
3. Cipher suite mismatch

**Solution:**
- Enable TLS debugging to see exact point of failure
- Verify both are using compatible TLS versions (1.2 or 1.3)
- Check certificate chain validity

### Certificate Verification Failures

Look for messages like:
```
mbedtls[2] x509_crt.c: verification failed: ... certificate verify failed
```

**Possible Causes:**
1. CA certificate not found or invalid
2. Server certificate not signed by CA
3. Certificate expired or not yet valid

**Solution:**
- Verify CA certificate is at `$XDG_CONFIG_HOME/tty-clipboard/certs/ca.crt`
- Regenerate certificates: `./scripts/setup.sh`
- Check certificate validity:
  ```bash
  openssl x509 -in ~/.config/tty-clipboard/certs/client.crt -noout -dates
  ```

## Advanced Debugging

### Capturing Full Debug Output

To save all debug output to a file:

```bash
MBEDTLS_DEBUG=1 tty-cb-client read 2> debug.log
cat debug.log
```

### Analyzing the Handshake Sequence

Look for state transitions in debug output:

1. **Client Hello:** Client sends supported ciphers and TLS versions
   ```
   client hello, add ciphersuite: ...
   => write client hello
   ```

2. **Server Hello:** Server chooses cipher and TLS version
   ```
   got server hello
   server selected cipher: ...
   ```

3. **Certificate Exchange:** Server sends certificate
   ```
   got certificate
   certificate verify callback failed  (if rejected)
   ```

4. **Key Exchange:** Parties exchange keys
   ```
   performing PSA-based ECDH computation
   ```

5. **Finished:** Both sides send finish messages
   ```
   client state: MBEDTLS_SSL_FINISHED
   ```

### Debugging Both Client and Server Simultaneously

Run server with debug in a separate terminal:

```bash
# Terminal 1: Server with debug
MBEDTLS_DEBUG=1 tty-cb-server -b 127.0.0.1 -p 5457

# Terminal 2: Client with debug
MBEDTLS_DEBUG=1 tty-cb-client -s 127.0.0.1 read
```

Compare the debug outputs to identify where they diverge.

## Certificate Setup

The test suite automatically generates test certificates. To regenerate them:

```bash
# Regenerate all test certificates
cd /workspaces/tty-clipboard/.build/tests
bash setup-test-certs.sh
```

For production use, certificates should be generated securely:

```bash
./scripts/create-certs.sh
```

## Performance Impact

Debug output has minimal performance impact (~1% overhead). It's safe to use in production for troubleshooting, but should be disabled for normal operation to avoid stderr bloat.

## See Also

- [USAGE.md](USAGE.md) - General usage documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design
- [mbedTLS Documentation](https://mbed-tls.readthedocs.io/) - Official mbedTLS docs
