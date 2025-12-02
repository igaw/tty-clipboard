# SPDX-License-Identifier: GPL-2.0-only

# Generate config header
config_conf = configuration_data()
config_conf.set_quoted('VERSION', meson.project_version())
config_conf.set_quoted('LICENSE', meson.project_license()[0])
# Expose protobuf enable as integer define in config.h
config_conf.set10('HAVE_PROTOBUF', with_protobuf)
config_h = configure_file(
  output: 'config.h',
  configuration: config_conf
)

gen_pb_sources = []
gen_pb_hdrs = []
pb_inc = []
if with_protobuf
  proto_file = files('../proto/clipboard.proto')
  pb = custom_target('gen-proto',
    input: proto_file,
    output: ['clipboard.pb-c.c', 'clipboard.pb-c.h'],
    command: [protoc_c, '--c_out=@OUTDIR@', '--proto_path=@SOURCE_ROOT@/proto', 'clipboard.proto'],
  )
  gen_pb_sources += pb
  gen_pb_hdrs += pb
  pb_inc = include_directories('.')
endif

server_sources = ['tty-server.c', 'tty-clipboard.c', config_h]
client_sources = ['tty-client.c', 'tty-clipboard.c', config_h]
if with_protobuf
  server_sources += gen_pb_sources
  client_sources += gen_pb_sources
endif

common_deps = [openssl_dep]
if with_protobuf
  common_deps += protobuf_dep
endif

cb_server = executable('tty-cb-server', server_sources,
  dependencies: common_deps,
  include_directories: [pb_inc],
  install : true)

cb_client = executable('tty-cb-client', client_sources,
  dependencies: common_deps,
  include_directories: [pb_inc],
  install : true)
