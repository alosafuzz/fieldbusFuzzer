#!/usr/bin/env bash
# Phase-2c instrumented build -- ecx_FOEread() (FoE), same datagram-generator responder
# architecture as build-fuzz-coe.sh/build-fuzz-soeread.sh. See harness-foe.cc's header comment for
# the design and the specific segmentdata unsigned-underflow lead being tested.
set -euo pipefail

SRC="${SOEM_SRC:-$HOME/research/fieldbus-fuzzer/targets/ethercat/src}"
OUT="${SOEM_FUZZ_FOE_OUT:-$HOME/research/fieldbus-fuzzer/targets/ethercat/build-fuzz-foe}"
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

$CXX -c $HARNESS_FLAGS -std=c++17 $CFLAGS -o obj/harness-foe.o "$HARNESS_DIR/harness-foe.cc"

$CXX $HARNESS_FLAGS -o ecat-foe-fuzzer "${OBJS[@]}" obj/harness-foe.o -lpthread

echo "Built: $OUT/ecat-foe-fuzzer"
