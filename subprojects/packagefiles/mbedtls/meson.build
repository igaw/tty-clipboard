project('mbedtls', 'c')

# Build mbedTLS libraries directly using custom_target
# since the upstream project uses CMake and we want a Meson-provided fallback.

cc = meson.get_compiler('c')
source_root = meson.current_source_dir()
build_root = meson.current_build_dir()

# Detect support for GCC/Clang warning control flags to avoid distro-specific breakages.
# Prefer the specific diagnostic if supported; otherwise fall back to generic -Wno-error.
cflags = ''
if cc.has_argument('-Wno-error=unterminated-string-initialization')
  cflags = '-Wno-error=unterminated-string-initialization'
elif cc.has_argument('-Wno-error')
  cflags = '-Wno-error'
endif

# Compose optional CMake flags segment
cmake_cflags_arg = ''
if cflags != ''
  cmake_cflags_arg = ' -DCMAKE_C_FLAGS="' + cflags + '"'
endif

# Configure and build mbedTLS using cmake directly
# 1) Initialize submodules in the source dir (no-op if already present)
# 2) Copy custom config overlay to build dir
# 3) Configure inside the subproject build dir (cmake-build)
# 4) Build static libs and copy them next to this meson subproject build dir
custom_config_overlay = join_paths(meson.current_source_dir(), 'tty_clipboard_mbedtls_config.h')
mbedtls_build = custom_target('mbedtls-configure',
  output: ['libmbedtls.a', 'libmbedx509.a', 'libmbedcrypto.a'],
  command: [
    'sh', '-c',
    ('src="@0@"; bld="@1@"; overlay="@2@"; '
     + '(cd "$src" && git submodule update --init 2>/dev/null || true) && '
     + 'mkdir -p "$bld/cmake-build" && '
     + 'cp "$overlay" "$bld/cmake-build/mbedtls_config_overlay.h" && '
     + 'cd "$bld/cmake-build" && '
    + 'cmake "$src" -DCMAKE_BUILD_TYPE=Release -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DUSE_SHARED_LIBS=OFF -DMBEDTLS_FATAL_WARNINGS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DMBEDTLS_CONFIG_FILE=\\"mbedtls_config_overlay.h\\"@3@ && '
     + 'make -j"$(nproc)" mbedtls mbedx509 mbedcrypto && '
     + 'cp library/libmbedtls.a library/libmbedx509.a library/libmbedcrypto.a "$bld"')
    .format(source_root, build_root, custom_config_overlay, cmake_cflags_arg)
  ],
  build_by_default: true,
  console: true
)

# Paths to built static archives (copied next to this meson subproject build dir)
mbedtls_lib_path   = join_paths(build_root, 'libmbedtls.a')
mbedx509_lib_path  = join_paths(build_root, 'libmbedx509.a')
mbedcrypto_lib_path= join_paths(build_root, 'libmbedcrypto.a')

# Declare the dependencies; use link_args with absolute .a paths and ensure build ordering via sources
mbedtls_inc = include_directories('include')

mbedtls_dep = declare_dependency(
  link_args: [mbedtls_lib_path],
  include_directories: mbedtls_inc,
  sources: mbedtls_build
)

mbedx509_dep = declare_dependency(
  link_args: [mbedx509_lib_path],
  include_directories: mbedtls_inc,
  sources: mbedtls_build
)

mbedcrypto_dep = declare_dependency(
  link_args: [mbedcrypto_lib_path],
  include_directories: mbedtls_inc,
  sources: mbedtls_build
)
