# SuperSerpent: A Dual-Mode File/FileSystem Encryption Tool

![Github Action](https://github.com/pingwcy/SuperSerpent/actions/workflows/build.yml/badge.svg)

<a href="https://scan.coverity.com/projects/pingwcy-superserpent">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/31700/badge.svg"/>
</a>

**SuperSerpent** is an experimental and educational project that implements both **transparent filesystem encryption** (via FUSE on Linux) and **interactive file-level encryption** with strong cryptographic algorithms and high portability.
**Known Security Issue: CTR Mode in FileSystem will reuse counters when changing files**
---

## ✨ Features

- 🔒 **Two Encryption Modes**:
  - **Transparent Filesystem Encryption** (Linux only, using FUSE)
  - **Interactive Single-File Encryption** (Linux and Windows)
- 🛡️ **Encryption Algorithm**: Serpent-256
- 🔐 **Encryption Modes**:
  - **Filesystem mode**: CTR
  - **File mode**: Optional CBC-HMAC or GCM
- 🔑 **Key Derivation**: PBKDF2-HMAC-Whirlpool
- 🧩 **Zero runtime dependencies** beyond the standard C library(glibc) OR only Linux Kernel(MUSL)
- 🧷 **Statically linked libfuse v2.9.9**:
  - Supports both glibc (≥ 2.31) and musl
  - Fully static binary on musl-based systems for maximum compatibility

---

## 🧪 Platform Support

| Platform | File Encryption | Filesystem Encryption |
|----------|------------------|------------------------|
| Linux    | ✅ Supported     | ✅ Supported (via FUSE) |
| Windows  | ✅ Supported     | 🚧 Not yet implemented *(planned via WinFsp or filter driver)* |

---

## 🛠️ Build Instructions

### Requirements

- **CMake**
- **A C compiler** (e.g., `gcc`, `clang`, `MSVC`)

### Linux (glibc or musl)

```bash
mkdir build && cd build
cmake ..
make
```
CMake will detect the system's C library:

For glibc, a standard static binary is built

For musl, a fully static binary is built with all dependencies included

### Windows
```bash
mkdir build && cd build
cmake -G ..
msbuild
```
FUSE-related components are excluded (via conditional compilation)

Only the file encryption tool is compiled
---

## 🚀 Usage
### 🔐 File Encryption Mode (Linux & Windows)
```bash
./main
```
Interactive command-line utility

Prompts for file path, mode (CBC-HMAC or GCM), and password

### 🔐 Transparent Filesystem Encryption (Linux Only)
```bash
./main [VIRTUAL_MOUNT_POINT] [ENCRYPTED_BACKEND_DIR]
```
Mounts a virtual encrypted filesystem using FUSE

Prompts for a password to derive the encryption key

All files written to ~/secure are transparently encrypted and stored in ~/vault.

## 🛣️ Roadmap
 Implement filesystem encryption on Windows (via WinFsp or filter driver)

 Add a GUI for file encryption

 // Explore Android support

## ⚠️ Disclaimer
This is an experimental project intended for educational use only.
Do not use for sensitive or production data without a thorough security audit.

## 📄 License
This project is licensed under the MIT License.

## 🙋 Contributing & Feedback
Contributions, issues, and suggestions are welcome!

Feel free to open a GitHub Issue or Pull Request, or start a Discussion.
