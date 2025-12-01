# SPDX-License-Identifier: GPL-2.0-only

# Generate config header
config_conf = configuration_data()
config_conf.set_quoted('VERSION', meson.project_version())
config_conf.set_quoted('LICENSE', meson.project_license()[0])
config_h = configure_file(
  output: 'config.h',
  configuration: config_conf
)

cb_server = executable('tty-cb-server', ['tty-server.c', 'tty-clipboard.c', config_h],
  dependencies: [openssl_dep],
  install : true)

cb_client = executable('tty-cb-client', ['tty-client.c', 'tty-clipboard.c', config_h],
  dependencies: [openssl_dep],
  install : true)
