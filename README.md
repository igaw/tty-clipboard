# tty-clipboard
A clipboard for those who use consoles/ssh/tmux

## Dependencies

The project requires the following dependencies:

- mbedTLS (libmbedtls-dev / mbedtls-devel)
- protobuf-c (libprotobuf-c-dev / protobuf-c-devel)
- Meson build system
- Ninja build tool

### Installing Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get install libmbedtls-dev libprotobuf-c-dev meson ninja-build
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install mbedtls-devel protobuf-c-devel meson ninja-build
```

**Arch Linux:**
```bash
sudo pacman -S mbedtls protobuf-c meson ninja
```

**openSUSE:**
```bash
sudo zypper install mbedtls-devel protobuf-c-devel meson ninja
```

**macOS (via Homebrew):**
```bash
brew install mbedtls protobuf-c meson ninja
```

## Building

```bash
meson setup builddir
ninja -C builddir
```

## Installation

```bash
sudo ninja -C builddir install
```
