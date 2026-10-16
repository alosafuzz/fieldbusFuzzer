#!/usr/bin/env bash
# Phase-1 instrumented (libFuzzer + ASan/UBSan) build for the ecx_inframe() harness.
# Links directly against SOEM's real source (oshw/linux/nicdrv.c + osal/linux/osal.c) -- not a
# modified copy. Uses the cmake-generated ec_options.h from a stock build (build-stock.sh must
# have been run at least once) since EC_BUFSIZE/EC_MAXBUF are configure-time constants, not
# hardcoded in the headers.
set -euo pipefail

SRC="${SOEM_SRC:-$HOME/research/fieldbus-fuzzer/targets/ethercat/src}"
OUT="${SOEM_FUZZ_OUT:-$HOME/research/fieldbus-fuzzer/targets/ethercat/build-fuzz}"
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
$CXX -c $HARNESS_FLAGS -std=c++17 $CFLAGS -o obj/harness.o "$HARNESS_DIR/harness.cc"

$CXX $HARNESS_FLAGS -o ecat-inframe-fuzzer obj/nicdrv.o obj/osal.o obj/harness.o -lpthread

echo "Built: $OUT/ecat-inframe-fuzzer"
