#!/usr/bin/env bash
# Phase-2 instrumented build -- ecx_SoEread() via a real (non-cyclic) mailbox request/response
# cycle, serviced by harness-soeread.cc's own datagram-generator responder thread. See that file's
# header comment for the design.
set -euo pipefail

SRC="${SOEM_SRC:-$HOME/research/fieldbus-fuzzer/targets/ethercat/src}"
OUT="${SOEM_FUZZ_SOEREAD_OUT:-$HOME/research/fieldbus-fuzzer/targets/ethercat/build-fuzz-soeread}"
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

C_SRCS=(
  "$SRC/oshw/linux/nicdrv.c"
  "$SRC/oshw/linux/oshw.c"
  "$SRC/osal/linux/osal.c"
  "$SRC/src/ec_base.c"
  "$SRC/src/ec_main.c"
  "$SRC/src/ec_soe.c"
  "$SRC/src/ec_coe.c"
  "$SRC/src/ec_dc.c"
  "$SRC/src/ec_config.c"
  "$SRC/src/ec_print.c"
  "$SRC/src/ec_foe.c"
  "$SRC/src/ec_eoe.c"
)
OBJS=()
for f in "${C_SRCS[@]}"; do
  base=$(basename "$f" .c)
  obj="$OUT/obj/${base}.o"
  $CC -c $TARGET_FLAGS $CFLAGS -o "$obj" "$f"
  OBJS+=("$obj")
done

$CXX -c $HARNESS_FLAGS -std=c++17 $CFLAGS -o obj/harness-soeread.o "$HARNESS_DIR/harness-soeread.cc"

$CXX $HARNESS_FLAGS -o ecat-soeread-fuzzer "${OBJS[@]}" obj/harness-soeread.o -lpthread

echo "Built: $OUT/ecat-soeread-fuzzer"
