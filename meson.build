project('tty-clipboard', 'c',
  version : '0.1',
  license : 'GPL-2.0-only',
  default_options : [
    'warning_level=3',
    'c_std=gnu99'])

# Find required dependencies
# Try system libraries first, fall back to subprojects if static build is requested or system libs not found
if get_option('static')
  message('Static build requested, using subprojects')
  mbedtls_dep = dependency('mbedtls', required: false, static: true)
  mbedx509_dep = dependency('mbedx509', required: false, static: true)
  mbedcrypto_dep = dependency('mbedcrypto', required: false, static: true)
  
  if not mbedtls_dep.found() or not mbedx509_dep.found() or not mbedcrypto_dep.found()
    message('Static libraries not found, falling back to mbedtls subproject')
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
    mbedtls_proj = subproject('mbedtls')
    mbedtls_dep = mbedtls_proj.get_variable('mbedtls_dep')
    mbedx509_dep = mbedtls_proj.get_variable('mbedx509_dep')
    mbedcrypto_dep = mbedtls_proj.get_variable('mbedcrypto_dep')
  endif
endif

protobuf_dep = dependency('libprotobuf-c', required: true)
protoc_c = find_program('protoc-c', required: true)

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
