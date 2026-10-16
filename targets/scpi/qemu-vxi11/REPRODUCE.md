# Reproducible: fuzzing Keysight's real VXI-11 server under qemu-aarch64

**Status (2026-10-09): WORKING.** The Keysight Truevolt DMM's vendor VXI-11 RPC server
(`libHppVxi11Server.so`) runs under `qemu-aarch64-static`, registers with the ONC-RPC portmapper, and
decodes VXI-11 RPCs (`create_link` returns a real VXI-11 error reply). This is a real-instrument
network-parser fuzz target — the surface the SCPI/LXI gap survey said had no open-source equivalent.
The full instrument app (`/usr/bin/Torreys`) is NOT needed and does not run under qemu-user (hardware
HAL, segfaults at `dllEntry`) — we harness just the self-contained VXI-11 server library.

## Host prerequisites (Ubuntu/WSL2, all installed 2026-10-09)
```
sudo apt-get install -y qemu-user-static gcc-aarch64-linux-gnu lld rpcbind squashfs-tools
pip install python-vxi11 --user --break-system-packages      # optional client for validation
```

## 1. Carve the firmware rootfs (one-time)
Source: `/mnt/d/ics-scanner-ingest/keysight/DM3446XA_rev_01.02-01.00-02.07-52.swu` (Keysight 3446XA
Truevolt DMM; SWUpdate = SVR4 cpio). Arch = **aarch64** (TI K3/AM62 SoC).
```
mkdir -p ~/scpi-fuzzer/qemu/extract && cd ~/scpi-fuzzer/qemu/extract
cpio -idv --no-absolute-filenames < <the .swu>        # yields tlo-instrument-image-p550.squashfs
unsquashfs -d ~/scpi-fuzzer/qemu/rootfs tlo-instrument-image-p550.squashfs
```
Target lib: `~/scpi-fuzzer/qemu/rootfs/usr/lib/libHppVxi11Server.so.1.0`
(exports `inet_start_VXI11_server(void)` / `inet_shutdown_VXI11_server`; NEEDED = libtirpc + C/C++
runtime only — no hardware HAL).

## 2. Build the harness
`winapi_shim.c` implements the ~25 Win32 symbols the lib imports (Torreys is a Windows port:
CreateThread→pthread, CriticalSection→mutex, Event→cond, Tls*→pthread_key, `_strnicmp`→strncasecmp,
etc.). `driver.c` calls `inet_start_VXI11_server()` then idles so the RPC worker thread serves.
```
ROOTFS=~/scpi-fuzzer/qemu/rootfs ./build-vxi11-harness.sh      # -> ~/scpi-fuzzer/build/vxi11-harness
```
(Cross-links the vendor `.so` by explicit path since the rootfs has no dev symlinks;
`aarch64-linux-gnu-gcc`, `--allow-shlib-undefined`, rpath-link into the rootfs.)

## 3. Run the server under qemu
```
sudo rpcbind -w                                               # ONC-RPC portmapper :111
qemu-aarch64-static -L ~/scpi-fuzzer/qemu/rootfs ~/scpi-fuzzer/build/vxi11-harness &
# verify: VXI-11 Device Core program 395183 (0x607af) v1 registered on a dynamic TCP port
rpcinfo -p 127.0.0.1 | grep 395183
```
Expected: `395183  1  tcp  <port>`. Harness log prints `inet_start_VXI11_server() returned 0; serving`.

## 4. Drive / fuzz
- Functional check: `python3 -c "import vxi11; vxi11.Instrument('127.0.0.1').open()"` → the server
  decodes `create_link` and replies (VXI-11 error 18 = no instrument backend behind it; the RPC
  **decode** path — the fuzz target — ran).
- **Fuzzing (the teed-up next step):** the VXI-11 RPC framing (ONC-RPC record marking,
  `create_link`/`device_write`/`device_read` arg-struct decode, length-vs-payload) is now reachable.
  Options: (a) the phase-2 rig `../scpi_wire_rig.py --port <dynamic>` with VXI-11-framed payloads /
  raw malformed RPC records; (b) AFL++ QEMU-mode on `libHppVxi11Server` via a persistent-mode harness
  that feeds one RPC record per iteration into the service dispatch; (c) a boofuzz/sulley ONC-RPC
  model. Watch for: crash of the qemu'd server (segv in the vendor decode = a real memory-safety
  finding), vs. graceful VXI-11 error replies (benign). Disclosure route if a finding lands:
  **Keysight PSIRT** (Siglent SCPI-CVE precedent shows T&M vendors issue these).

## Files (this dir = `targets/scpi/qemu-vxi11/`)
- `winapi_shim.c` — POSIX implementation of the vendor's Win32 imports.
- `driver.c` — minimal main that starts the server.
- `build-vxi11-harness.sh` — cross-link script (`ROOTFS`/`OUT` overridable).
- `REPRODUCE.md` — this file.
Not version-controlled here: the carved rootfs (`~/scpi-fuzzer/qemu/rootfs`) and the built binary
(`~/scpi-fuzzer/build/vxi11-harness`) live on ext4; re-create via steps 1–2.

## Caveats / notes
- The SCPI *command* parser inside Torreys is a deeper target (hardware-coupled); this harness covers
  the **VXI-11 transport/RPC decode**, which is the unauthenticated, network-reachable front door.
- `CloseHandle` leaks events/threads by design (harness lifetime is short). Coarse global critical
  section (correctness-lossy but adequate to run the RPC loop). If a fuzz finding needs precise
  repro, tighten the shim first to rule it out as a shim artifact (same rigor as the scpi-def leads).
- Legal/ethical: defensive research on firmware the user possesses; any finding → coordinated
  disclosure to Keysight PSIRT, PoC withheld per the suite playbook.

---

## Fuzzing results & RIGOR PROTOCOL (2026-10-09)

### Structured black-box fuzzer (`vxi11_rpc_fuzz.py`) — DONE, first pass
Target-manages the qemu'd server, mutates valid create_link/device_write/device_read RPC records
(record-mark + ONC-RPC header + arg structs, incl. opaque/string length-lies), oracle = the qemu
process dying (guest segv => `qemu: uncaught target signal 11`). Auto-restarts to collect distinct
crashes. 25s sanity: 270 cases, 0 crashes, server robust.

### The crash that MUST NOT be over-claimed (rigor gate in action)
A 600s campaign segfaulted the server once (case 1916), input = a **truncated `device_write`
RPC with a record-mark length-lie** (declared 68 / actual 51 bytes), saved
`vxi11-crashes/vxi11-crash-1-*.bin`. **But isolated replay does NOT reproduce it (3/3 SURVIVED;
`-strace` shows the server cleanly processes the 55 bytes and returns to `accept()`).**
=> state/load-dependent, NOT a clean single-input fault => **most likely a HARNESS/SHIM ARTIFACT**,
not a vendor bug. Prime suspect: the shim's `CloseHandle` was a no-op that LEAKED every Event object
=> sustained-load resource exhaustion => allocation failure => segv after ~1916 connections.
**Action taken:** hardened `CloseHandle` to destroy+free events; re-running the campaign. If the crash
vanishes => confirmed shim artifact (non-finding). If it persists AND becomes reproducible => real lead.
**No finding is claimed unless and until it reproduces in isolation AND is root-caused to the vendor
decoder (not the shim/libtirpc).**

### RIGOR PROTOCOL for any VXI-11 crash (defendable-research bar)
1. **Reproduce in isolation** — replay the single saved input against a fresh server >=3x. A
   non-reproducible/load-dependent crash is an unconfirmed LEAD, not a finding.
2. **Attribute the module** — the fault must be in `libHppVxi11Server` (vendor), not in the
   `winapi_shim` (our code) or `libtirpc` (system). Backtrace via qemu gdbstub (`qemu-aarch64-static
   -g <port>` + `gdb-multiarch`, `info symbol $pc`) — NOTE: gdbstub appeared constrained in this
   sandbox; alternative = harden the suspected shim function and re-test (differential attribution).
3. **Rule out shim artifacts** — coarse stubs (global CriticalSection, no-op/freed handles) can both
   cause AND mask faults; tighten the relevant shim and confirm the crash is invariant to it.
4. **Minimize** the RPC record; **CWE** it precisely (OOB read vs write vs length-underflow).
5. **Wire-reachability** — confirmed by construction (found over a real TCP socket to the real
   decoder), but note the emulation+shim caveat: full severity needs a **real-device** repro.
6. **Disclose** to Keysight PSIRT, PoC-withheld (Siglent SCPI-CVE precedent).

### AFL++ coverage-guided (Route B) — PLAN (not yet built)
Persistent-mode on the RE'd RPC decode entry. RE so far: the server registers its dispatch via
`svc_register` at `libHppVxi11Server.so` offsets ~`0x4180/0x41c0/0x4200` (TCP+UDP, core/async/intr),
dispatch fn loaded into x3 before each; the worker thread is `0x61d0`. Next: identify the per-proc
xdr decode (`device_write` args) entry + its arg registers, set `AFL_QEMU_PERSISTENT_ADDR` on
`afl-qemu-trace` (needs AFL++ built with **aarch64** qemu-mode — `afl++` pkg is x86 qemu-mode; verify
cross-build). **Every AFL++ crash is funneled through the rigor protocol above (esp. wire-repro +
shim attribution) before it is called a finding** — an RE'd persistent harness on top of the shim is
the LEAST defensible discovery context, so its output is leads, confirmed only over the wire.

### VERDICT (2026-10-09, after 3 campaigns + rigorous triage) — NO DEFENSIBLE VENDOR FINDING
Three campaigns (~8,700 malformed-RPC cases total) each produced exactly ONE segfault of the qemu'd
server. All three were triaged to the rigor bar and FAILED it:
| campaign | shim state | crash proc | rec-mark | isolation repro |
|---|---|---|---|---|
| 1 | original (CloseHandle no-op) | device_write (11) | length-lie (68/51) | 0/3 |
| 2 | event-leak fixed | device_read (12) | length-lie (323814/60) | 0/5 |
| 3 | tagged handles (thread≠event) | create_link (10) | well-formed (64/64) | 0/5 |

The crash is **input-INDEPENDENT** (3 different procs; one input had a correct length, so it's not a
length-lie bug), **non-reproducible in isolation** (0/13 replays), and **persisted through two distinct
shim fixes** (event-leak, handle-confusion). Signature = a rare (~1/2900 connections) concurrency /
per-connection-thread-lifecycle race, almost certainly **in the qemu-user thread emulation + our
CreateThread/pthread shim + coarse global CriticalSection**, NOT the vendor RPC decoder. A concurrency
crash under qemu-user's thread model is exactly the class that typically does NOT exist on real
hardware. gdbstub backtrace was constrained in this sandbox, so module attribution relied on
differential shim-hardening (the rigorous alternative).

**Defensible conclusions:**
1. **Harness/methodology: validated + novel** — a real Keysight vendor VXI-11 RPC server runs under
   qemu-aarch64 and is fuzzed over the wire; fully reproducible (this doc). The surface the gap survey
   said had no OSS equivalent is now reachable.
2. **Robustness (qualified):** across ~8,700 malformed VXI-11 RPCs the vendor decoder produced **no
   single-input-reproducible crash** — every crash input replays clean. No memory-safety finding in
   the RPC-decode path at this (black-box, shallow) coverage.
3. **The rare crash is an UNATTRIBUTED, likely-harness/emulation concurrency artifact — explicitly NOT
   claimed as a finding.** To pursue it rigorously would require a working backtrace (native/other
   gdbstub) AND a real-device repro to exclude the qemu-user thread model; absent those, claiming a
   Keysight CVE from it would be indefensible.

**Status: STOPPED here on purpose** (diminishing returns chasing an emulation-artifact lead). Next if
resumed: AFL++ Route B for DEEPER coverage (the black-box pass is shallow), with the same rigor gate;
or a single-connection / fresh-server-per-case mode to fully exclude the concurrency artifact.

### CONFIRMATION — fresh-per-case run (2026-10-09): artifact verdict upgraded "likely" -> CONFIRMED
`vxi11_rpc_fuzz.py --fresh-per-case` (a disposable server per input: no accumulated state, no
overlapping per-connection threads) ran **400 cases, 0 crashes**. With the two artifact vectors
removed, the vendor decoder does not fault. Together with the 0/13 isolation replays of the actual
crash inputs, this **confirms** the sustained-mode segfaults were cumulative/concurrency artifacts
(long-lived state + overlapping qemu-user threads + the shim), NOT per-input vendor memory-safety
bugs. The qualified-robustness conclusion stands on firmer ground; no vendor finding.

---

## AFL++ coverage-guided (Route B) — BUILT, RAN, verdict (2026-10-09)

**Toolchain (reproducible):** AFL++ v5.03c built from source + `CPU_TARGET=aarch64 build_qemu_support.sh`
(needs: afl core `make` first, then meson/ninja/glib/pixman) → `~/scpi-fuzzer/aflpp/afl-qemu-trace`
(aarch64), validated on a rootfs binary.

**Harness (fidelity-preserving, `afl_vxi11_driver.c`):** brings up the REAL vendor server in-process
(`inet_start_VXI11_server`), hand-rolled portmapper GETPORT, reads ONE RPC record from stdin, drives
it over loopback. `afl-qemu-trace` instruments the whole process incl. the vendor decode thread.
No desock, no RE'd internal fn, no out-of-context exec → least artifact-prone AFL setup.
Run: `QEMU_LD_PREFIX=<rootfs> AFL_SKIP_CPUFREQ=1 ~/scpi-fuzzer/aflpp/afl-fuzz -Q -i afl-in -o afl-out
-- ~/scpi-fuzzer/build/afl_vxi11_driver`. (Each exec forks fresh + re-inits the server ≈ fresh-per-case;
AFL_ENTRYPOINT past init would speed it up but reintroduces fork-with-live-threads.)

**Result:** 211s, **7,532 execs @ 35.7/s** (3× the black-box rate), 87 edges, 8 corpus, **1 saved crash.**
Crash input = 4 bytes `00000b00` (a bare partial record-mark), **0/5 reproducible in isolation**.
**Decisive corroboration: AFL `stability = 86.21%`** — AFL's own metric says the target is
NON-DETERMINISTIC (same input → different coverage), i.e. threading/emulation non-determinism. That is
exactly why every crash across all methods is non-reproducible.

**TRIPLY-CONFIRMED VERDICT (structured + fresh-per-case + AFL++):**
- No defensible vendor memory-safety finding. Every crash (4 total across methods = 3 structured
  campaigns + 1 AFL++; fresh-per-case 0) is non-reproducible in isolation, input-independent, and the
  target is measurably non-deterministic (AFL stability 86%).
- **Methodological finding:** the qemu-user + Win32-shim + threaded-RPC-server combination is too
  non-deterministic for reliable coverage-guided fuzzing — a flaky (<90% stability) target undermines
  AFL's feedback. The STRUCTURED black-box + fresh-per-case approach gave the cleaner, more defensible
  signal here. Coverage reached is shallow (0.13%), decode-path-only.
- **Capability delivered + reproducible:** AFL++ aarch64 qemu-mode coverage-guided fuzzing of a real
  closed-firmware vendor VXI-11 server — a novel setup — stands up and runs; artifacts here + in memory.
- To push further rigorously: a DETERMINISTIC harness (single-threaded: call the RPC decode without the
  worker-thread/svc_run loop — requires RE'ing the decode entry, the artifact-risky route) would be
  needed for AFL to be effective; and any crash still requires wire-repro on a real device.
