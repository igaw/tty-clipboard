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

### Standard Build (Dynamic Linking)

```bash
meson setup builddir
ninja -C builddir
```

### Static Build

To build fully static binaries with all dependencies statically linked:

```bash
meson setup builddir -Dstatic=true
ninja -C builddir
```

**Additional dependencies required for static builds:**

When system static libraries are not available, the build system will automatically fetch and build mbedTLS and libprotobuf-c from source. This requires:

- **cmake** - for building mbedTLS subproject
- **autoconf, automake, libtool** - for building libprotobuf-c subproject
- **git** - for fetching subprojects

**Installing build tools:**

**Debian/Ubuntu:**
```bash
sudo apt-get install cmake autoconf automake libtool git
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install cmake autoconf automake libtool git
```

**Arch Linux:**
```bash
sudo pacman -S cmake autoconf automake libtool git
```

**openSUSE:**
```bash
sudo zypper install cmake autoconf automake libtool git
```

**macOS (via Homebrew):**
```bash
brew install cmake autoconf automake libtool git
```

**Note:** Static builds are useful for creating portable binaries that can run on systems without the required runtime libraries installed.

## Installation

```bash
sudo ninja -C builddir install
```
