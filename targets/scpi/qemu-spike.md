# QEMU firmware spike — Keysight Truevolt DMM (phase 3, real-instrument path)

*Time-boxed spike 2026-10-09 to decide whether fuzzing a REAL instrument's SCPI/LAN surface under
QEMU is viable. Target firmware: `DM3446XA_rev_01.02-01.00-02.07-52.swu` (Keysight 3446XA Truevolt
DMM family, carved by the firmware-sidecar, `/mnt/d/ics-scanner-ingest/keysight/`).*

## Tier 1 — carve + recon: DONE
- Toolchain present: **qemu-user-static installed** (`qemu-aarch64-static`), clang-18, unsquashfs,
  binwalk, cpio, passwordless sudo. All unblocked.
- `.swu` = SVR4 cpio (SWUpdate). Contains `tlo-instrument-image-p550.squashfs` (95 MB) + TI boot
  chain (`tiboot3.bin`/`tispl.bin`/`u-boot.img`) + `fitImage` kernel → **TI K3 / AM62-class SoC**.
- Rootfs unpacked to `~/scpi-fuzzer/qemu/rootfs` (257 MB). **Arch = aarch64** (`busybox.nosuid` ELF).
- **SCPI engine = `/usr/bin/Torreys`** (13.6 MB) — carries the full SCPI/`*IDN?`/HiSLIP/VXI-11/Sockets
  command set (its strings are the SCPI command help). No binary hardcodes port 5024/5025 → the LAN
  front-end relays SCPI to Torreys via IPC (the predicted net-frontend / instrument-backend split).

## Tier 2 — run the app under qemu-user: BLOCKED (predicted hardware-coupling wall)
- qemu-user sanity OK (ran `busybox` from the rootfs under `qemu-aarch64-static -L rootfs`).
- **`Torreys` segfaults immediately at `dllEntry`** (its first init) under qemu-user. It links
  `libinstrhal.so` (hardware abstraction layer), `libpalio.so`, `lib34_KeysightApplicationIfcModule.so`
  — a GUI+measurement app coupled to hardware/IPC/display. Full-app emulation is **not viable**
  without major work (system-mode QEMU with board models, or deep hardware stubbing). Expected.

## The pivot — a SELF-CONTAINED narrow target: `libHppVxi11Server.so.1.0`
Torreys' deps revealed a real vendor **VXI-11 server library**. Its `readelf -d` NEEDED set is only
**`libtirpc.so.3` (ONC-RPC) + libstdc++/libgcc_s/libc/ld** — **no `libinstrhal`, no hardware HAL.**
It exports just two C symbols: `inet_start_VXI11_server` / `inet_shutdown_VXI11_server`. So the
VXI-11 **RPC framing + create_link/device_write/device_read argument decode** (the parser surface the
gap survey flagged as having NO open-source equivalent) lives in this self-contained lib + libtirpc,
decoupled from the measurement hardware.

**This is the tractable, novel-finding path** (days, not the multi-week full-RE), with real CVE
potential (Keysight PSIRT; Siglent SCPI-CVE precedent).

## Verdict & next step (decision-gated)
- Full-firmware emulation: **not pursued** (Torreys hardware wall).
- **Recommended next: harness `libHppVxi11Server` under qemu-aarch64.** Concrete sub-tasks:
  1. ~~RE `inet_start_VXI11_server()`'s signature~~ **DONE (2026-10-09):** disasm shows it takes
     **NO arguments** — `int inet_start_VXI11_server(void)`. It calls
     `RegisterThreadProcessNotifications` then `CreateThread(thread_fn=0x61d0,…)` to spawn the VXI-11
     RPC service on a worker thread, guarded by an already-started flag, returns 0 ok / -1 fail. So
     the driver just calls it (no SCPI-relay callback arg). Caveat: `CreateThread` /
     `RegisterThreadProcessNotifications` are PLT imports (Keysight abstraction, likely `libpalio.so.5`)
     — link libpalio (if it's hardware-free) or **stub those two functions** in the driver.
  2. Cross-compile a tiny aarch64 driver (clang `--target=aarch64-linux-gnu --sysroot=rootfs`,
     `-fuse-ld=lld`) that calls it with a **stub SCPI-relay callback** (ack only → the RPC parse path
     runs fully before reaching the stub; no Torreys/hardware needed).
  3. Stand it up under `qemu-aarch64-static -L rootfs`; handle the ONC-RPC **portmapper** (run
     `rpcbind`, or bypass). Reuse the icsScanner VXI-11 portmapper probe + the **phase-2 rig**
     (`scpi_wire_rig.py`, target-agnostic) as the driver/liveness client.
  4. Fuzz the VXI-11 RPC framing (record-mark length lies, opcode/arg decode, `device_write` length vs
     payload) — AFL++ QEMU-mode on the lib, or structured cases via the rig.
- Risk: `inet_start_VXI11_server` may need more context than a stub provides (pull in other Hpp libs);
  reassess after sub-task 1–2. Still far more tractable than Torreys.

Artifacts: `~/scpi-fuzzer/qemu/rootfs` (extracted), this note. The phase-2 rig plugs directly into
whatever VXI-11 endpoint the harness stands up.

## OUTCOME — HARNESS BUILT & WORKING (2026-10-09)
Built it (not deferred). `targets/scpi/qemu-vxi11/` — `winapi_shim.c` (POSIX impl of the ~25 Win32
imports the lib needs: CreateThread→pthread, CriticalSection→mutex, Event→cond, Tls*→pthread_key,
`_strnicmp`/`strncpy_s`/`strtok_s`→POSIX), `driver.c` (calls `inet_start_VXI11_server()` then idles),
`build-vxi11-harness.sh` (cross-link via `aarch64-linux-gnu-gcc`, vendor `.so` by path), `REPRODUCE.md`
(full steps). **Result: the real Keysight vendor VXI-11 server runs under `qemu-aarch64-static`,
registers program 395183/0x607af with the portmapper on a dynamic TCP port, and DECODES VXI-11 RPCs**
— `python-vxi11` `create_link` elicited a real VXI-11 error reply (error 18 = absent instrument
backend; the RPC **decode** path ran), server stays up. The VXI-11 RPC-framing fuzz surface is now
live under emulation. **Fuzzing is the ready next step** (rig / AFL++ QEMU-mode on the RPC decode);
findings → Keysight PSIRT. Resolved the signature-RE wall (no-arg entry) AND the hardware-coupling
wall (harness the self-contained server lib, not Torreys).
