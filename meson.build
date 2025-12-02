project('tty-clipboard', 'c',
  version : '0.1',
  license : 'GPL-2.0-only',
  default_options : [
    'warning_level=3',
    'c_std=gnu99'])

# Find required dependencies
openssl_dep = dependency('openssl', required: true)
protobuf_dep = dependency('libprotobuf-c', required: true)
protoc_c = find_program('protoc-c', required: true)

# Include subdirectories
subdir('src')
subdir('tests')
