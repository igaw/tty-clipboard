# SPDX-License-Identifier: GPL-2.0-only

# Setup test certificates once at build time
setup_certs_script = find_program('setup-test-certs.sh')
test_config_dir = meson.current_build_dir() / 'test-config' / 'tty-clipboard'

# Generate certificates as a build target (runs only when outputs don't exist or inputs change)
cert_files = custom_target('setup-test-certs',
  output: ['ca.crt', 'server.crt', 'client.crt', 'ca.key', 'server.key', 'client.key'],
  command: [
    setup_certs_script,
    test_config_dir,
    '@OUTDIR@',
  ],
  build_by_default: true,
)

# Define the test
test('basic-clipboard-test',
  find_program('test-basic.sh'),
  args: [
    cb_server.full_path(),
    cb_client.full_path(),
    meson.current_build_dir() / 'test-config',
  ],
  depends: [cert_files, cb_server, cb_client],
  timeout: 30,
  is_parallel: false,
)

# Encoding tests
test('encoding-text',
  find_program('test-encoding-text.sh'),
  args: [
    cb_server.full_path(),
    cb_client.full_path(),
    meson.current_build_dir() / 'test-config',
  ],
  depends: [cert_files, cb_server, cb_client],
  timeout: 30,
  is_parallel: false,
)

test('encoding-binary',
  find_program('test-encoding-binary.sh'),
  args: [
    cb_server.full_path(),
    cb_client.full_path(),
    meson.current_build_dir() / 'test-config',
  ],
  depends: [cert_files, cb_server, cb_client],
  timeout: 30,
  is_parallel: false,
)

test('large-transfer-4mb',
  find_program('test-large-transfer.sh'),
  args: [
    cb_server.full_path(),
    cb_client.full_path(),
    meson.current_build_dir() / 'test-config',
  ],
  depends: [cert_files, cb_server, cb_client],
  timeout: 60,
  is_parallel: false,
)

test('max-size-limit',
  find_program('test-max-size.sh'),
  args: [
    cb_server.full_path(),
    cb_client.full_path(),
    meson.current_build_dir() / 'test-config',
  ],
  depends: [cert_files, cb_server, cb_client],
  timeout: 30,
  is_parallel: false,
)

test('max-size-drop',
  find_program('test-max-size-drop.sh'),
  args: [
    cb_server.full_path(),
    cb_client.full_path(),
    meson.current_build_dir() / 'test-config',
  ],
  depends: [cert_files, cb_server, cb_client],
  timeout: 30,
  is_parallel: false,
)

# Protobuf test (only if enabled)
if with_protobuf
  test('protobuf-mode',
    find_program('test-protobuf.sh'),
    args: [
      cb_server.full_path(),
      cb_client.full_path(),
      meson.current_build_dir() / 'test-config',
    ],
    depends: [cert_files, cb_server, cb_client],
    timeout: 30,
    is_parallel: false,
  )

  test('no-loopback',
    find_program('test-no-loopback.sh'),
    args: [
      cb_server.full_path(),
      cb_client.full_path(),
      meson.current_build_dir() / 'test-config',
    ],
    depends: [cert_files, cb_server, cb_client],
    timeout: 30,
    is_parallel: false,
  )

  test('no-self-echo',
    find_program('test-no-self-echo.sh'),
    args: [
      cb_server.full_path(),
      cb_client.full_path(),
      meson.current_build_dir() / 'test-config',
    ],
    depends: [cert_files, cb_server, cb_client],
    timeout: 30,
    is_parallel: false,
  )
endif

