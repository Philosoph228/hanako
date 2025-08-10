#!/bin/bash

cmake \
  -S '.' \
  -B './build' \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_INSTALL_PREFIX="/usr/local/" \
  -GNinja
cmake --build ./build
