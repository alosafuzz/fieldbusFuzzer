# fieldbusFuzzer

A coverage-guided fuzzing suite for industrial fieldbus and test-instrument protocol
stacks. Each target drives a real implementation in-process with **libFuzzer + ASan/UBSan**
under source-verified coverage (`llvm-cov`), and ships live two-process reproduction
harnesses so every crash can be confirmed against the real stack, not just the fuzzer.

> **Authorized use only.** fieldbusFuzzer exercises protocol parsers with deliberately
> malformed input that can crash or hang control-system software. Only run it against code
> or systems you own or have explicit written permission to test. See [SECURITY.md](SECURITY.md).

This is a modular, multi-target suite; targets are added as their disclosure cycles close.

## Targets

| Target | Stack under test | Transport | Outcome |
|---|---|---|---|
| **EtherCAT** | [SOEM](https://github.com/OpenEtherCATsociety/SOEM) (Simple Open EtherCAT Master), RT-Labs | EtherCAT mailbox (SoE/CoE/EoE/FoE) + frame processing | **4 CVEs**, fixed in SOEM 2.0.1 |
| **SCPI / LXI** | [libscpi](https://github.com/j123b567/scpi-parser) + a carved vendor VXI-11 server (QEMU) | TCP 5025 / VXI-11 (ONC-RPC) / HiSLIP | robustness result, no vendor CVE |

### EtherCAT / SOEM

Seven harnesses (`inframe`, `stateful`, `coe`, `soeread`, `foe`, `eoe`, `eoegetip`) drive
SOEM's frame-receive and mailbox parsers. The campaign produced eight findings that RT-Labs
consolidated with other researchers' reports into four CVEs, all **adjacent-network (AV:A)**
and all fixed in **SOEM 2.0.1**:

- **CVE-2026-70388** (HIGH) — integer-underflow out-of-bounds write across the SoE/CoE/EoE/FoE
  mailbox length handling.
- **CVE-2026-82947** (HIGH) — multiple out-of-bounds reads in frame processing.
- **CVE-2026-82943** (MEDIUM) — out-of-bounds read via unchecked length (information disclosure).
- **CVE-2026-82946** (MEDIUM) — NULL-pointer dereference in mailbox error handling.

The `livetest-*`/`prodtest-*` harnesses reproduce each finding two-process over a `veth` pair.
Root-cause detail is in RT-Labs' advisory
([rt-labs.com/cyber-security](https://rt-labs.com/cyber-security/)) and the writeup linked below.

### SCPI / LXI

SCPI command parsing — the surface behind raw-5025, VXI-11, and HiSLIP — was fuzzed two ways:
`libscpi` in-process (~95M executions, source-verified coverage, **zero** parser crashes), and
a real vendor VXI-11 server carved from a DMM firmware image and run under `qemu-aarch64` via a
Win32→POSIX shim. The parser held up; the only crashes on the emulated vendor stack were shown
to be harness/emulation artifacts, not vendor bugs — a deliberately qualified, negative result.
See `targets/scpi/qemu-vxi11/REPRODUCE.md` and the writeup.

## Building and running

Each target self-contains its build. For example:

```bash
cd targets/ethercat
./build-fuzz.sh          # builds the libFuzzer harness against a pinned SOEM checkout
./ethercat-fuzz corpus/  # run the fuzzer
```

The SCPI target's `build-*.sh` and `qemu-vxi11/REPRODUCE.md` document the libscpi and
carved-firmware setups respectively. Build scripts expect a local checkout of the stack under
test (SOEM, libscpi); paths are set at the top of each script.

## Writeups

- **Fuzzing EtherCAT: four CVEs in SOEM's mailbox handlers** — methodology, the recurring
  integer-underflow bug class, and the coordinated disclosure with RT-Labs.
- **Fuzzing SCPI, from the open parser to real firmware under QEMU** — libscpi robustness and
  the carved-vendor VXI-11 experiment.

Both at [alosafuzz.github.io](https://alosafuzz.github.io/writeups/).

## Security & responsible use

Read [SECURITY.md](SECURITY.md) before use. If you find a vulnerability in a vendor's product
with this tool, coordinate disclosure with the vendor before publishing.

## License

[MIT](LICENSE) © 2026 Shad Malloy (alosafuzz).

## Author

Built by Shad Malloy (**alosafuzz**), independent ICS/OT security research.
Contact: alosafuzz@proton.me
