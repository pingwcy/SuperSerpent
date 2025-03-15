#!/bin/bash
set -e

BUILD_DIR="build"

echo "==> Cleaning previous build..."
rm -rf $BUILD_DIR
mkdir $BUILD_DIR
cd $BUILD_DIR

echo "==> Configuring with CMake..."
cmake ..

echo "==> Building..."
make -j$(nproc)

echo "==> Done! Binary located at: $(realpath bin/main)"
