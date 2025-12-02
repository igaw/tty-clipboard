project('libprotobuf-c', 'c')

cc = meson.get_compiler('c')
source_root = meson.current_source_dir()
build_root = meson.current_build_dir()

# Build libprotobuf-c static library using autotools (autogen.sh + configure + make)
# Note: We only build the library here; protoc-c will be found from the system
protobufc_build = custom_target('protobuf-c-build',
  output: ['libprotobuf-c.a'],
  command: [
    'sh', '-c',
    (
      'src="@0@"; bld="@1@"; '
      + 'mkdir -p "$bld/autotools-build" && cd "$src" && '
      + '(test -f configure || ./autogen.sh) && '
      + 'cd "$bld/autotools-build" && '
      + '"$src"/configure --prefix="$bld/install" --disable-shared --enable-static --disable-protoc && '
      + 'make -j"$(nproc)" && '
      + 'cp protobuf-c/.libs/libprotobuf-c.a "$bld/"'
    ).format(source_root, build_root)
  ],
  build_by_default: true,
  console: true
)

protobufc_lib_path = join_paths(build_root, 'libprotobuf-c.a')

# Export dependency - protoc-c will be found from the system
protobuf_c_inc = include_directories('.')

protobuf_c_dep = declare_dependency(
  link_args: [protobufc_lib_path],
  include_directories: protobuf_c_inc,
  sources: protobufc_build
)
