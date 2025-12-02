# SPDX-License-Identifier: GPL-2.0-only

# Generate config header
config_conf = configuration_data()
config_conf.set_quoted('VERSION', meson.project_version())
config_conf.set_quoted('LICENSE', meson.project_license()[0])
# Define feature test macros for POSIX and GNU extensions
# _GNU_SOURCE provides: asprintf, be64toh, htobe64, sigaction, etc.
config_conf.set('_GNU_SOURCE', '1', description: 'Enable GNU extensions including POSIX features')

config_h = configure_file(
  output: 'config.h',
  configuration: config_conf
)

# Generate protobuf code
proto_file = files('../proto/clipboard.proto')
pb = custom_target('gen-proto',
  input: proto_file,
  output: ['clipboard.pb-c.c', 'clipboard.pb-c.h'],
  command: [protoc_c, '--c_out=@OUTDIR@', '--proto_path=@SOURCE_ROOT@/proto', 'clipboard.proto'],
)

pb_inc = include_directories('.')

# Compile protobuf-generated code with reduced warnings
pb_lib = static_library('protobuf-gen',
  pb,
  c_args: ['-Wno-pedantic'],
  dependencies: protobuf_dep,
  include_directories: pb_inc,
)

server_sources = ['tty-server.c', 'tty-clipboard.c', config_h]
client_sources = ['tty-client.c', 'tty-clipboard.c', config_h]

common_deps = [openssl_dep, protobuf_dep]
common_link_with = [pb_lib]

cb_server = executable('tty-cb-server', server_sources,
  dependencies: common_deps,
  link_with: common_link_with,
  include_directories: pb_inc,
  install : true)

cb_client = executable('tty-cb-client', client_sources,
  dependencies: common_deps,
  link_with: common_link_with,
  include_directories: pb_inc,
  install : true)
