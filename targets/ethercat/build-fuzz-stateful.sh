#!/usr/bin/env bash
# Phase-1b instrumented build -- ecx_inframe()'s stateful "already buffered" branches, see
# harness-stateful.cc's header comment. Same linkage as build-fuzz.sh.
set -euo pipefail

SRC="${SOEM_SRC:-$HOME/research/fieldbus-fuzzer/targets/ethercat/src}"
OUT="${SOEM_FUZZ_STATEFUL_OUT:-$HOME/research/fieldbus-fuzzer/targets/ethercat/build-fuzz-stateful}"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$SRC/build/include/soem/ec_options.h" ]; then
  echo "Generated ec_options.h not found -- run a stock 'cmake .. && make' in $SRC/build first." >&2
  exit 1
fi

CXX=clang++
CC=clang
SANITIZE_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all"
TARGET_FLAGS="-fsanitize=fuzzer-no-link $SANITIZE_FLAGS"
HARNESS_FLAGS="-fsanitize=fuzzer $SANITIZE_FLAGS"
INCLUDES="-I$SRC/include -I$SRC/build/include -I$SRC/oshw/linux -I$SRC/osal -I$SRC/osal/linux"
CFLAGS="-g -O1 $INCLUDES -D_GNU_SOURCE"

mkdir -p "$OUT/obj"
cd "$OUT"

$CC -c $TARGET_FLAGS $CFLAGS -o obj/nicdrv.o "$SRC/oshw/linux/nicdrv.c"
$CC -c $TARGET_FLAGS $CFLAGS -o obj/osal.o "$SRC/osal/linux/osal.c"
$CXX -c $HARNESS_FLAGS -std=c++17 $CFLAGS -o obj/harness-stateful.o "$HARNESS_DIR/harness-stateful.cc"

$CXX $HARNESS_FLAGS -o ecat-inframe-stateful-fuzzer obj/nicdrv.o obj/osal.o obj/harness-stateful.o -lpthread

echo "Built: $OUT/ecat-inframe-stateful-fuzzer"
