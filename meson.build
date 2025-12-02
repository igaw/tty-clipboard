project('tty-clipboard', 'c',
  version : '0.1',
  license : 'GPL-2.0-only',
  default_options : [
    'warning_level=3',
    'c_std=gnu99'])

# Find the OpenSSL package
openssl_dep = dependency('openssl', required: true)

# Optional protobuf-c support
with_protobuf = get_option('with_protobuf')
protobuf_dep = dependency('libprotobuf-c', required: with_protobuf)
protoc_c = find_program('protoc-c', required: with_protobuf)

# Include subdirectories
subdir('src')
subdir('tests')
