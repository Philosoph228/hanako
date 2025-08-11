#!/bin/bash
# build-boost.sh: Automated Boost (Asio, Beast) build & install script
# Place this script in /home/philosoh228/ioid/thirdparty

set -euo pipefail

# ----- Configuration -----
# Source directory relative to script location
SOURCE_DIR="source/boost_1_88_0"
# Installation prefix (override by setting INSTALL_PREFIX env)
INSTALL_PREFIX="${INSTALL_PREFIX:-$(pwd)/dist/boost_1_88_0}"
# Build cache directory
BUILD_CACHE="${BUILD_CACHE:-$(pwd)/buildcache/boost_1_88_0}"
# Toolset to use (override by setting TOOLSET env), e.g. gcc or clang
TOOLSET="${TOOLSET:-clang}"
# C/C++ compilers (override via CC/CXX env)
: "${CC:=clang}"  # default C compiler
: "${CXX:=clang++}"  # default C++ compiler
# Libraries to build (Asio & Beast themselves are header-only)
LIBS=(system thread chrono regex filesystem program_options context)

# ----- Helper functions -----
info() {
  echo -e "[\e[32mINFO\e[0m] $*"
}

error() {
  echo -e "[\e[32mERROR\e[0m] $*" >&2
  exit 1   
}

# ----- Begin script -----
info "Script directory: $(pwd)"
[ -d "$SOURCE_DIR" ] || error "Source directory '$SOURCE_DIR' not found."
info "Using Boost source dir: $SOURCE_DIR"
info "Installation prefix: $INSTALL_PREFIX"
info "Build cache directory: $BUILD_CACHE"
info "Using Boost.Build toolset: $TOOLSET"
info "CC=$CC, CXX=$CXX"

# Create install directory
mkdir -p "$INSTALL_PREFIX"
mkdir -p "$BUILD_CACHE"

# Enter source directory
cd "$SOURCE_DIR"

# Bootstrap Boost.Build with specified toolset
# Some Boost distributions expect 'clang-linux' rather than 'clang'
if [[ "$TOOLSET" == "clang" ]]; then
    BS_TOOLSET="clang-linux"
else
    BS_TOOLSET="$TOOLSET"
fi

# Bootstrap Boost.Build
info "Running bootstrap.sh with toolset=$TOOLSET..."
# Export compilers so bootstrap script picks them up
export CC CXX
CC="$CC" CXX="$CXX" ./bootstrap.sh \
    --with-toolset="$TOOLSET" \
    --prefix="$INSTALL_PREFIX" \
    --with-libraries="$(IFS=,; echo "${LIBS[*]}")"

# Build and install
info "Building and installing Boost with toolset=$TOOLSET..."
# Use C++23 by default
CXXFLAGS="-std=c++23 -O2"
export CXXFLAGS
CC="$CC" CXX="$CXX" ./b2 install \
    --build-dir="$BUILD_CACHE" \
    toolset=$TOOLSET \
    variant=release \
    link=shared \
    threading=multi \
    runtime-link=shared \
    cxxflags="$CXXFLAGS" \
    -j"$(nproc)"

info "Boost build complete. Installed in: $INSTALL_PREFIX"