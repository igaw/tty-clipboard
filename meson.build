project('tty-clipboard', 'c',
  version : '0.1',
  license : 'GPL-2.0-only',
  default_options : [
    'warning_level=3',
    'c_std=gnu99'])

# Find the OpenSSL package
openssl_dep = dependency('openssl', required: true)

# Include subdirectories
subdir('src')
subdir('tests')
