#!/usr/bin/env bash
# Coverage build: same harness as build-fuzz.sh + source-based coverage mapping,
# for an llvm-cov source-level report on the libscpi core (the suite's tracked metric).
set -euo pipefail
SCPI_SRC="${SCPI_SRC:-$HOME/scpi-fuzzer/src}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HOME/scpi-fuzzer/build}"
mkdir -p "$OUT"
INC="-I$SCPI_SRC/libscpi/inc -I$SCPI_SRC/examples/common"
SAN="-fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined"
COV="-fprofile-instr-generate -fcoverage-mapping"
CFLAGS="-g -O0 -Wall $SAN $COV $INC"
SRCS=(
  "$SCPI_SRC"/libscpi/src/error.c "$SCPI_SRC"/libscpi/src/expression.c
  "$SCPI_SRC"/libscpi/src/fifo.c "$SCPI_SRC"/libscpi/src/ieee488.c
  "$SCPI_SRC"/libscpi/src/lexer.c "$SCPI_SRC"/libscpi/src/minimal.c
  "$SCPI_SRC"/libscpi/src/parser.c "$SCPI_SRC"/libscpi/src/units.c
  "$SCPI_SRC"/libscpi/src/utils.c
  "${SCPI_DEF:-$HERE/scpi-def-patched.c}"
  "$HERE"/harness.c
)
echo "[*] building coverage binary -> $OUT/scpi-cov"
clang $CFLAGS "${SRCS[@]}" -o "$OUT/scpi-cov"
echo "[*] done"
