#!/usr/bin/env bash
# Build a real libscpi TCP instrument server (raw-socket SCPI, port 5025) under
# ASan/UBSan — the phase-2 wire target. Uses the de-confounded demo command tree
# (scpi-def-patched.c) so the server is a clean, realistic instrument. This is a
# normal server binary (its own main), NOT a libFuzzer harness.
#
# It is the local stand-in for a real instrument; the phase-2 rig (scpi_wire_rig.py)
# is target-agnostic (--host/--port), so the same rig later drives a QEMU-emulated
# instrument SCPI daemon on 5025.
set -euo pipefail
SCPI_SRC="${SCPI_SRC:-$HOME/scpi-fuzzer/src}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HOME/scpi-fuzzer/build}"; mkdir -p "$OUT"
INC="-I$SCPI_SRC/libscpi/inc -I$SCPI_SRC/examples/common"
SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
CFLAGS="-g -O1 -Wall $SAN $INC"
SRCS=(
  "$SCPI_SRC"/libscpi/src/error.c "$SCPI_SRC"/libscpi/src/expression.c
  "$SCPI_SRC"/libscpi/src/fifo.c "$SCPI_SRC"/libscpi/src/ieee488.c
  "$SCPI_SRC"/libscpi/src/lexer.c "$SCPI_SRC"/libscpi/src/minimal.c
  "$SCPI_SRC"/libscpi/src/parser.c "$SCPI_SRC"/libscpi/src/units.c
  "$SCPI_SRC"/libscpi/src/utils.c
  "${SCPI_DEF:-$HERE/scpi-def-patched.c}"
  "$HERE"/server-sigpipe-ignore.c
  "$SCPI_SRC"/examples/test-tcp/main.c
)
echo "[*] building TCP SCPI server -> $OUT/scpi-tcp-server (ASan/UBSan, port 5025)"
clang $CFLAGS "${SRCS[@]}" -o "$OUT/scpi-tcp-server"
echo "[*] done"
