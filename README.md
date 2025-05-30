# 🐍 SuperSerpent: A Triple-Mode Cross-Platform Encryption Tool

![Build Status](https://github.com/pingwcy/SuperSerpent/actions/workflows/build.yml/badge.svg)
[![Coverity Scan](https://scan.coverity.com/projects/31700/badge.svg)](https://scan.coverity.com/projects/pingwcy-superserpent)

**SuperSerpent** is a powerful, cross-platform encryption tool supporting **three distinct encryption modes**:

1. 🔐 **Interactive File Encryption** – works on Linux & Windows  
2. 🧊 **Transparent Filesystem Encryption** – Linux-only, FUSE-based (like gocryptfs)  
3. 📦 **Encrypted Volume Support** – VeraCrypt-compatible volumes, with Linux-native mounting via `dm-crypt`

> ✅ Open-source, educational, and experimental. Built with security and portability in mind.

---

## ✨ Features

### 🔒 Triple Encryption Modes

- **📁 File Encryption** (Linux & Windows): Encrypt/decrypt individual files interactively.
- **🔄 Filesystem Encryption** (Linux-only): A FUSE-based encrypted filesystem (like gocryptfs).
- **💽 Volume Container Support**:
  - Create VeraCrypt-compatible volumes on Linux and Windows
  - Mount volumes via `dm-crypt` on Linux
  - Windows currently supports **only creation**, mounting requires the VeraCrypt software.

### 🔐 Cryptography Details

- **Algorithm**: Serpent-256
- **Modes of Operation**:
  - Volume Mode: `XTS`
  - Filesystem Mode: `CTR` *(⚠️ Known issue: counter reuse on modification)*
  - File Mode: `CBC-HMAC` or `GCM`
- **Key Derivation**: `PBKDF2-HMAC-Whirlpool`

### ⚙️ Portability

- Zero runtime dependencies (uses only the standard C library)
- Fully statically linked `libfuse v2.9.9` included
  - Supports both `glibc (≥ 2.31)` and `musl`
  - Fully static binary for `musl`-based distros

---

## 🧪 Platform Support

| Platform | File Encryption | Filesystem Encryption | Volume Encryption |
|----------|------------------|------------------------|--------------------|
| **Linux**    | ✅ Supported     | ✅ Supported (via FUSE) | ✅ Full support (via `dm-crypt`) |
| **Windows**  | ✅ Supported     | 🚧 Planned *(via WinFsp or filter driver)* | 🚧 Create-only (mounting requires VeraCrypt) |

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
cmake ..
msbuild
```
FUSE-related components are excluded (via conditional compilation)

Only the file encryption tool is compiled
---

## 🚀 Usage
### 🔐 File Encryption Mode (Linux & Windows) and Volume Encryption Mode (Linux Only)
```bash
./main
```
Interactive CLI:

Create / Mount / Unmount VeraCrypt volumes

Encrypt / Decrypt files

Select encryption mode: CBC-HMAC or GCM


### 🔐 Transparent Filesystem Encryption (Linux Only)
```bash
./main [VIRTUAL_MOUNT_POINT] [ENCRYPTED_BACKEND_DIR]
```
Mounts a virtual encrypted filesystem using FUSE

Prompts for a password to derive the encryption key

All files written to ~/secure are transparently encrypted and stored in ~/vault.


## 🛣️ Roadmap
 Implement filesystem encryption on Windows (via WinFsp or filter driver)

 Add a GUI for this tool

 // Explore Android support

## ⚠️ Disclaimer
This is an experimental project intended for educational use only.
Do not use for sensitive or production data without a thorough security audit.

## 📄 License
This project is licensed under the MIT License.

## 🙋 Contributing & Feedback
Contributions and suggestions are welcome!

Feel free to:

Open an Issue

Submit a Pull Request

Start a Discussion on GitHub