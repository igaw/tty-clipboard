project('tty-clipboard', 'c',
  version : '0.1',
  license : 'GPL-2.0-only',
  default_options : [
    'warning_level=3',
    'c_std=gnu99'])

# Find required dependencies
mbedtls_dep = dependency('mbedtls', required: true)
mbedx509_dep = dependency('mbedx509', required: true)
mbedcrypto_dep = dependency('mbedcrypto', required: true)
protobuf_dep = dependency('libprotobuf-c', required: true)
protoc_c = find_program('protoc-c', required: true)

# Detect mbedTLS version for API compatibility
mbedtls_version = mbedtls_dep.version()
mbedtls_major = mbedtls_version.split('.')[0].to_int()

message('mbedTLS version: ' + mbedtls_version)
message('mbedTLS major version: ' + mbedtls_major.to_string())

# Include subdirectories
subdir('src')
subdir('tests')
