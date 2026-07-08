#!/usr/bin/env bash
# Build the VaultMind C++ core into a shared library the Python app loads.
# Requires: g++, OpenSSL dev headers (Ubuntu/Debian: sudo apt install libssl-dev)
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p build
g++ -O2 -Wall -Wextra -std=c++17 -fPIC -shared \
    core/vault_core.cpp \
    -lcrypto \
    -o build/libvaultcore.so

echo "Built build/libvaultcore.so"
