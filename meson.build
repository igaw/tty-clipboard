project('tty-clipboard', 'c',
  version : '0.1',
  license : 'GPL-2.0-only',
  default_options : [
    'warning_level=3',
    'c_std=gnu99'])

# Find the OpenSSL package
openssl_dep = dependency('openssl', required: true)

cb_server = executable('tty-cb-server', ['tty-server.c', 'tty-clipboard.c'],
  dependencies: [openssl_dep],
  install : true)

cb_client = executable('tty-cb-client', ['tty-client.c', 'tty-clipboard.c'],
  dependencies: [openssl_dep],
  install : true)

test('tty-cb-server', cb_server)
test('tty-cb-client', cb_client)
