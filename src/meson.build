# SPDX-License-Identifier: GPL-2.0-only

cb_server = executable('tty-cb-server', ['tty-server.c', 'tty-clipboard.c'],
  dependencies: [openssl_dep],
  install : true)

cb_client = executable('tty-cb-client', ['tty-client.c', 'tty-clipboard.c'],
  dependencies: [openssl_dep],
  install : true)
