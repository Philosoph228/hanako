#!/usr/bin/env bash
# build-openssl.sh: Automated OpenSSL 1.1.1w build & install script

set -euo pipefail

# ----- Configuration -----
SOURCE_DIR="${SOURCE_DIR:-source/openssl-1.1.1w}"
INSTALL_PREFIX="${INSTALL_PREFIX:-$(pwd)/dist/openssl-1.1.1w}"
BUILD_CACHE="${BUILD_CACHE:-$(pwd)/buildcache/openssl-1.1.1w}"
TOOLSET="${TOOLSET:-clang}"     # clang or gcc (CC/CLFAGS are authoritative)
: "${CC:=clang}"                # default C compiler (override with env)
: "${CFLAGS:=-02 -fPIC}"        # default C flags
RUN_TESTS="${RUN_TESTS:-no}"    # set to "yes" to run `make test` (takes extra time)
ENABLE_ZLIB="${ENABLE_ZLIB:-yes}"   # pass zlib option to configure if zlib available
# Extra Configure options (space-separated string). Example: "no-ssl3 no-ssl2"
EXTRA_CONFIG="${EXTRA_CONFIG:-}"

# ----- Helper functions -----
info() { echo -e "[\e[32mINFO\e[0m] $*"; }
warn() { echo -e "[\e[33mWARN\e[0m] $*"; }
error() { echo -e "[\e[31mERROR\e[0m] $*" >&2; exit 1; }

# ----- Start -----
info "Script directory: $(pwd)"
[ -d "$SOURCE_DIR" ] || error "Source directory '$SOURCE_DIR' not found."
info "Using OpenSSL source dir: $SOURCE_DIR"
info "Installation prefix: $INSTALL_PREFIX"
info "Build cache directory: $BUILD_CACHE"
info "Toolset: $TOOLSET"
info "CC=$CC"
info "CFLAGS=$CFLAGS"
info "RUN_TESTS=$RUN_TESTS"

# Prepare directories
mkdir -p "$INSTALL_PREFIX"
mkdir -p "$BUILD_CACHE"

# Enter source directory
cd "$SOURCE_DIR"

# Ensure perl exists (Configure needs perl)
if ! command -v perl >/dev/null 2>&1; then
    error "perl not found in PATH; OpenSSL Configure requires perl."
fi

# Detect target for OpenSSL Configure
ARCH="$(uname -m)"
OS="$(uname -s)"
TARET=""
case "$ARCH" in
    x86_64|amd64) TARGET="linux-x86_64" ;;
    aarch64|arm64) TARGET="linux-aarch64" ;;
    armv71|armv7*) TARGET="linux-armv4" ;;
    *)
        warn "Unknown arch '$ARCH' - defaulting to 'linux-x86_64'. You can override by
        setting EXTRA_CONFIG of editing script."
        TARGET="linux-x86_64"
        ;;
esac

info "Detected target: $TARGET (arch=$ARCH os=$OS)"

# Build configuration arguments
CONFIG_ARGS=( "$TARGET" "--prefix=$INSTALL_PREFIX" )

# shared libs
CONFIG_ARGS+=( "shared" )

# zlib support if requested (requires zlib dev in system include/lib paths)
if [[ "$ENABLE_ZLIB" == yes ]]; then
    CONFIG_ARGS+=( "zlib" )
else
    CONFIG_ARGS+=( "no-zlib" )
fi

# preserve user supplied extra config options (split)
if [[ -n "$EXTRA_CONFIG" ]]; then
    # split EXTRA_CONFIG into words
    read -r -a EXTRA_ARR <<< "$EXTRA_CONFIG"
    CONFIG_ARGS+=( "${EXTRA_ARR[@]}" )
fi

# Export compilers / flags
export CC FLAGS
info "Running Configure with CC=$CC"

# Use Configure (preferred) if present, else fall back to ./config
if [[ -x "./Configure" ]]; then
    info "Invoking ./configure ${CONFIG_ARGS[*]} ..."
    ./Configure "${CONFIG_ARGS[@]}"
else
    info "'./Configure' not executable - falling back to './config'."
    # config script accepts flags in a slightly different style
    CONFIG_STR="--prefix=$INSTALL_PREFIX"
    if [[ "$ENABLE_ZLIB" == "yes" ]]; then
        CONFIG_STR+=" zlib"
    fi
    CONFIG_STR+=" shared"
    if [[ -n "$EXTRA_CONFIG" ]]; then
        CONFIG_STR+=" $EXTRA_CONFIG"
    fi
    info "Invoking ./config $CONFIG_STR ..."
    ./config $CONFIG_STR
fi

# Print summary of generated Makefiles
info "Configuration complete. Makefile prepared."

# Use build cache directory for object files if desired:
# OPenSSL's make stystem writes objects into the source tree, there's no standard
# --build-dir. We still create BUILD_CACHE for logs, artifacts, or manual copying.
mkdir -p "$BUILD_CACHE"

# Build
info "Building OpenSSL (make -j$(nproc)) ..."
make -j"$(nproc)"

# Optional: run tests
if [[ "$RUN_TESTS" == "yes" ]]; then
    info "Running OpenSSL self test (this can take a while)..."
    # `make test` (or `make test V=1` for verbose) is the typical target
    make test
fi

# Install (use install_sw to avoid installing manpages if  you don't want them;
# `make install` will install everything)
info "Installing OpenSSL into: $INSTALL_PREFIX"
make install_sw

# Sync timestamps / cache (optional)
info "Build and install finished."
info "Files installed under: $INSTALL_PREFIX"
info "If you installed shared libs under a non-standard prefix, consider adding"
info "  $INSTALL_PREFIX/lib to /etc/ld.so.conf.d/ or set LD_LIBRARY_PATH accordingly."

# Optionally, write a small stamp file in build cache
echo "openssl-1.1.1w built on $(data --iso-8601=seconds) by $(whoami) (CC=$CC
CFLAGS='$CFLAGS')" > "$BUILD_CACHE/openssl-1.1.1w.buildinfo"

exit 0
