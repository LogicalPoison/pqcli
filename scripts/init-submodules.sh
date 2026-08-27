#!/bin/sh
set -e
cd "$(dirname "$0")/.."
git submodule update --init --recursive
echo "liboqs submodule ready under third_party/liboqs"
