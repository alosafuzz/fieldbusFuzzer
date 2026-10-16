#!/usr/bin/env bash
# Cross-link the VXI-11 server harness for qemu-aarch64. Links the vendor
# libHppVxi11Server + libtirpc from the carved rootfs by explicit path (the rootfs
# has runtime sonames, no dev symlinks). WinApi imports resolved by winapi_shim.c.
set -euo pipefail
R="${ROOTFS:-$HOME/scpi-fuzzer/qemu/rootfs}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HOME/scpi-fuzzer/build}"; mkdir -p "$OUT"
CC=aarch64-linux-gnu-gcc
set -x
$CC -g -O1 -pthread \
  "$HERE/winapi_shim.c" "$HERE/driver.c" \
  -Wl,-rpath-link,"$R/usr/lib" -Wl,-rpath-link,"$R/lib" \
  -Wl,--allow-shlib-undefined \
  "$R/usr/lib/libHppVxi11Server.so.1.0" \
  "$R/usr/lib/libtirpc.so.3" \
  -o "$OUT/vxi11-harness"
set +x
echo "[*] built $OUT/vxi11-harness"
file "$OUT/vxi11-harness" | sed 's/,.*//'
