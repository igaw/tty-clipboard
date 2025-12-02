# tty-clipboard
A clipboard for those who use consoles/ssh/tmux

## Dependencies

The project requires the following dependencies:

- OpenSSL (libssl-dev / openssl-devel)
- protobuf-c (libprotobuf-c-dev / protobuf-c-devel)
- Meson build system
- Ninja build tool

### Installing Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get install libssl-dev libprotobuf-c-dev meson ninja-build
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install openssl-devel protobuf-c-devel meson ninja-build
```

**Arch Linux:**
```bash
sudo pacman -S openssl protobuf-c meson ninja
```

**openSUSE:**
```bash
sudo zypper install libopenssl-devel protobuf-c-devel meson ninja
```

**macOS (via Homebrew):**
```bash
brew install openssl protobuf-c meson ninja
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
