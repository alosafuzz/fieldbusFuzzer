# SCPI target — findings so far: two bugs, both in the UPSTREAM EXAMPLE (`scpi-def.c`), not libscpi core

**Classification up front (rigor):** the `scpi` coverage-guided harness links libscpi's real
parser (`lexer.c`/`parser.c`/`expression.c`/`units.c`/`utils.c`) **plus** the upstream demo command
table `examples/common/scpi-def.c` — included so the parameter/expression readers are actually
reached. The two bugs found so far both live in **`scpi-def.c` (the demo handlers)**, NOT in the
libscpi parser under test. They are the SCPI analogue of a prior reference server phase-1's harness-shape artifact:
real UB/OOB, but in scaffolding, so they were **de-confounded** (patched in the local
`scpi-def-patched.c`) rather than reported as libscpi findings. libscpi core has held up (see TARGET.md).

**Caveat that keeps them interesting:** `scpi-def.c` is the canonical example and is widely
copy-pasted into real instrument firmware. Both patterns below therefore have **downstream reach** —
if a vendor shipped the example's channel-list or measure handler verbatim, the bug ships too. That
is a reachability question per the SCPI/LXI guide's "library-bug → product" note, not a libscpi CVE.

## Lead 01 — uninitialized `scpi_number_t` read (CWE-457 / UB)

- **Where:** `examples/common/scpi-def.c`, `DMM_MeasureVoltageDcQ` / `DMM_MeasureVoltageAcQ`.
- **Shape:** `scpi_number_t param1, param2;` (uninitialized) → `SCPI_ParamNumber(ctx, …, &param1,
  FALSE)` with the `if (!…) { /* do something */ }` branch **empty** → on a missing optional
  parameter `param1` is left uninitialized → `SCPI_NumberToStr(…, &param1, …)` reads
  `value->special` (a `scpi_bool_t`) uninitialized. UBSan: `units.c:485 load of value 172, which is
  not a valid value for 'bool'`.
- **Trigger:** a measure-query with a missing/invalid optional parameter, e.g. `MEAS:VOLT:DC?`.
- **Determinism:** non-deterministic — only trips UBSan when the stack residue is a non-0/1 byte
  (hence it fired mid-campaign but not on standalone replay). Still genuine UB.
- **Root cause:** the demo violates `SCPI_ParamNumber`'s contract (don't read the out-param when it
  returns FALSE). libscpi `SCPI_NumberToStr` is correct — it operates on a caller value it is
  entitled to assume initialized.
- **De-confound:** `scpi_number_t param1 = {0}, param2 = {0};` in `scpi-def-patched.c`.

## Lead 02 — stack-buffer-overflow, channel-list dimensions (CWE-787)

- **Where:** `examples/common/scpi-def.c`, `TEST_Chanlst`. ASan WRITE of size 4 at `utils.c:279`
  (`strBaseToInt32`'s `*val = strtol(...)`), via
  `SCPI_ExprChannelListEntry → channelRange → channelSpec → ParamSignToUInt32`.
- **Shape:** the demo declares `int32_t values_from[MAXDIM]; int32_t values_to[MAXDIM];` with
  **`MAXDIM = 2`**, but calls `SCPI_ExprChannelListEntry(…, values_from, values_to, 4, &dimensions)`
  — passing **`length = 4`** for 2-element arrays. libscpi's `channelSpec` faithfully writes
  `values[i]` for all `i < length` (`i < 4`), so a channel spec with **≥3 dimensions** overflows the
  stack arrays.
- **Trigger (reproduced 3/3, deterministic):** `TEST:CHANnellist (@2!2!4,5!6)` — the `2!2!4` channel
  has 3 `!`-dimensions → writes `values_from[2]` past `int32_t[2]`.
- **Root cause:** demo bug — `length` argument (4) must not exceed the real array size (`MAXDIM`=2).
  libscpi `channelSpec` is correct: it bounds writes by the `length` it is given. (Minor libscpi
  observation, not a bug: `channelSpec` sets `*dimensions = i+1` which can exceed `length`, so a
  caller that trusts `dimensions` without having sized its arrays for it is easy to get wrong — the
  example demonstrates exactly that footgun. Worth an upstream doc/assert note, not a CVE.)
- **De-confound:** pass `MAXDIM` instead of `4` at both `TEST_Chanlst` call sites in
  `scpi-def-patched.c`.

## Status
Both de-confounded in `scpi-def-patched.c`; campaign continues against the libscpi parser core.
Neither is a libscpi-core finding. If any value is pursued, it is a **courtesy upstream note** that
the reference example `scpi-def.c` has an uninitialized-read and a channel-list length/array
mismatch that downstream copies inherit — framed as example-hardening, PoC-withheld, per the suite
playbook.

## Lead 03 — whole-server DoS in the `test-tcp` EXAMPLE server (phase-2, NOT libscpi)

- **Where:** `examples/test-tcp/main.c` (the libscpi TCP server example) — its accept/recv/`SCPI_Write`
  socket loop, NOT the parser.
- **Symptom:** after a client disconnects around a reply, the server either (a) is **SIGPIPE-killed**
  (`SCPI_Write` → `write()` to a closed socket; the example installs no SIGPIPE handler), or (b) with
  SIGPIPE ignored, **spins at ~99% CPU forever** and never returns to `accept()` → whole-server DoS
  (new connections' `*IDN?` time out). Reproduced deterministically; **payload-independent** (triggers
  on a bare `*CLS`/`*IDN?` followed by client close in this WSL2 environment). `SCPI_Write`
  (`main.c:60`) returns `write()`'s result but the loop ignores it, so peer-close during the write
  phase isn't detected.
- **NOT libscpi:** isolated two ways — (a) the suspect wire payload fed to `SCPI_Input` in 10-byte
  chunks + follow-up `*IDN?` on the persistent context returns cleanly; (b) all 3,100 corpus files
  fed in 10-byte chunks on one persistent context under ASan/UBSan (`repro-wire-replay.c`) → 0 hang /
  0 crash. libscpi's incremental-input + persistent-session path is robust.
- **Value:** example socket code, like leads 01/02 — but the `test-tcp` server is widely copied into
  real instrument firmware, so the "ignore `write()` errors / no SIGPIPE handling / busy-spin on peer
  close" pattern has downstream reach. Fold into the same courtesy-upstream note (example hardening):
  check `write()`/`send()` returns, ignore SIGPIPE, and detect peer close in the server loop.
- **Rig note:** the phase-2 rig worked exactly as designed — its stateless liveness oracle correctly
  flagged a genuine whole-server availability failure. The flaky example server just isn't a reliable
  local parser oracle; the in-process chunked replay (`repro-wire-replay.c`) is the clean libscpi
  wire-path check, and the rig stays as the baseline for a real/QEMU instrument target.
