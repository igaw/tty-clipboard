project('tty-clipboard', 'c',
  version : '0.1',
  license : 'GPL-2.0-only',
  default_options : [
    'warning_level=3', # Force rebuild
    'c_std=gnu99'])

# Find required dependencies
# Try system libraries first, fall back to subprojects if static build is requested or system libs not found
if get_option('static')
  message('Static build requested, using subprojects')
  
  # Check for build tools required by subprojects
  cmake = find_program('cmake', required: false)
  autoreconf = find_program('autoreconf', required: false)
  
  mbedtls_dep = dependency('mbedtls', required: false, static: true)
  mbedx509_dep = dependency('mbedx509', required: false, static: true)
  mbedcrypto_dep = dependency('mbedcrypto', required: false, static: true)
  
  if not mbedtls_dep.found() or not mbedx509_dep.found() or not mbedcrypto_dep.found()
    message('Static libraries not found, falling back to mbedtls subproject')
    if not cmake.found()
      error('cmake is required to build mbedtls subproject. Please install cmake.')
    endif
    mbedtls_proj = subproject('mbedtls')
    mbedtls_dep = mbedtls_proj.get_variable('mbedtls_dep')
    mbedx509_dep = mbedtls_proj.get_variable('mbedx509_dep')
    mbedcrypto_dep = mbedtls_proj.get_variable('mbedcrypto_dep')
  endif
else
  mbedtls_dep = dependency('mbedtls', required: false)
  mbedx509_dep = dependency('mbedx509', required: false)
  mbedcrypto_dep = dependency('mbedcrypto', required: false)
  
  if not mbedtls_dep.found() or not mbedx509_dep.found() or not mbedcrypto_dep.found()
    message('System mbedtls not found, falling back to subproject')
    cmake = find_program('cmake', required: true, 
      disabler: true,
      native: true)
    mbedtls_proj = subproject('mbedtls')
    mbedtls_dep = mbedtls_proj.get_variable('mbedtls_dep')
    mbedx509_dep = mbedtls_proj.get_variable('mbedx509_dep')
    mbedcrypto_dep = mbedtls_proj.get_variable('mbedcrypto_dep')
  endif
endif

# Protobuf-C
protoc_depends = []
protoc_c_prog = find_program('protoc-c', required: false)

if get_option('static')
  message('Static build: prefer static libprotobuf-c, fallback to subproject')
  protobuf_dep = dependency('libprotobuf-c', required: false, static: true)

  if not protobuf_dep.found()
    message('System static libprotobuf-c not found, using subproject')
    if not autoreconf.found()
      error('autoreconf is required to build libprotobuf-c subproject. Please install autoconf, automake, and libtool.')
    endif
    pb_sub = subproject('libprotobuf-c')
    protobuf_dep = pb_sub.get_variable('protobuf_c_dep')
    protoc_depends = [pb_sub.get_variable('protobufc_build')]
    protobuf_inc = pb_sub.get_variable('protobuf_c_inc')
    # Use protoc_c from subproject if system one not found
    if not protoc_c_prog.found()
      protoc_c_prog = pb_sub.get_variable('protoc_c')
    endif
  endif
else
  protobuf_dep = dependency('libprotobuf-c', required: false)

  if not protobuf_dep.found()
    message('System libprotobuf-c not found, using subproject')
    autoreconf = find_program('autoreconf', required: true,
      disabler: true,
      native: true)
    pb_sub = subproject('libprotobuf-c')
    protobuf_dep = pb_sub.get_variable('protobuf_c_dep')
    protoc_depends = [pb_sub.get_variable('protobufc_build')]
    protobuf_inc = pb_sub.get_variable('protobuf_c_inc')
    # Use protoc_c from subproject if system one not found
    if not protoc_c_prog.found()
      protoc_c_prog = pb_sub.get_variable('protoc_c')
    endif
  endif
endif

if not protoc_c_prog.found()
  error('protoc-c is required but not found. Please install libprotobuf-c-dev or protobuf-c-compiler.')
endif

if not is_variable('protobuf_inc')
  # Use empty include dirs for system case; headers are in default system include path
  protobuf_inc = include_directories()
endif

# Detect mbedTLS version for API compatibility
mbedtls_version = mbedtls_dep.version()
if mbedtls_version == 'unknown' or mbedtls_version == 'undefined'
  # Subproject doesn't provide version, assume 3.x (we're using v3.6.2 from wrap)
  message('mbedTLS version unknown (subproject), assuming 3.x')
  mbedtls_major = 3
else
  mbedtls_major = mbedtls_version.split('.')[0].to_int()
  message('mbedTLS version: ' + mbedtls_version)
  message('mbedTLS major version: ' + mbedtls_major.to_string())
endif

# Include subdirectories
subdir('src')
subdir('tests')
