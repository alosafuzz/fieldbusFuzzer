#!/usr/bin/env bash
# Build the libscpi coverage-guided fuzz harness (clang + libFuzzer + ASan/UBSan).
#
# Source clone lives on ext4 (NTFS/drvfs can't hold .git) — override with SCPI_SRC.
# Pinned commit recorded in TARGET.md. Output binary -> $OUT (default ext4 build dir).
set -euo pipefail

SCPI_SRC="${SCPI_SRC:-$HOME/scpi-fuzzer/src}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HOME/scpi-fuzzer/build}"
mkdir -p "$OUT"

INC="-I$SCPI_SRC/libscpi/inc -I$SCPI_SRC/examples/common"
SAN="-fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined"
CFLAGS="-g -O1 -Wall $SAN $INC"

# libscpi core translation units + the example command definition (realistic tree)
SRCS=(
  "$SCPI_SRC"/libscpi/src/error.c
  "$SCPI_SRC"/libscpi/src/expression.c
  "$SCPI_SRC"/libscpi/src/fifo.c
  "$SCPI_SRC"/libscpi/src/ieee488.c
  "$SCPI_SRC"/libscpi/src/lexer.c
  "$SCPI_SRC"/libscpi/src/minimal.c
  "$SCPI_SRC"/libscpi/src/parser.c
  "$SCPI_SRC"/libscpi/src/units.c
  "$SCPI_SRC"/libscpi/src/utils.c
  "${SCPI_DEF:-$SCPI_SRC/examples/common/scpi-def.c}"
  "$HERE"/harness.c
)

echo "[*] SCPI_SRC = $SCPI_SRC  (HEAD $(git -C "$SCPI_SRC" rev-parse --short HEAD 2>/dev/null || echo '?'))"
echo "[*] building -> $OUT/scpi-fuzz"
clang $CFLAGS "${SRCS[@]}" -o "$OUT/scpi-fuzz"
echo "[*] done: $OUT/scpi-fuzz"
