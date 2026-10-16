#!/usr/bin/env python3
"""
SCPI raw-socket (TCP 5025) wire-reachability rig  —  fieldbusFuzzer scpi target, phase 2.

Target-AGNOSTIC baseline harness. It drives SCPI payloads at ANY raw-socket SCPI
endpoint and decides crash-vs-benign with a STATELESS liveness oracle. Used now against
the local libscpi `scpi-tcp-server`; it is also the intended baseline for QEMU firmware
testing — point --host/--port at a `qemu-arm`-emulated instrument SCPI daemon on 5025 and
the same crash/liveness logic applies unchanged.

What it validates beyond in-process fuzzing: the socket + line-assembly layer (TCP
segmentation, partial lines, missing terminators, the input-buffer boundary), connection
lifecycle, and that the robustness result holds end-to-end on a running server.

Calibration (the LwM2M/OPC-UA lesson): a server dropping/erroring a malformed line is NOT
a crash. After each case we run a STATELESS liveness probe on a FRESH socket (`*IDN?`);
only if that ALSO fails (confirmed over retries) is it a crash. Stateless so the oracle
itself can't exhaust the target (the OPC-UA session-exhaustion footgun).

Usage:
  scpi_wire_rig.py --host 127.0.0.1 --port 5025 --corpus ~/scpi-fuzzer/corpus2 [--segment] [--max N]
"""
import argparse, os, random, socket, sys, time

def send_case(host, port, payload, timeout, segment, drain_timeout):
    """Send one payload (optionally split across writes to exercise segmentation),
    drain the reply. Returns ('refused'|'ok'|'reset'|'timeout'). drain_timeout is
    short because most SCPI commands are non-queries and never reply."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, OSError):
        return "refused"
    try:
        s.settimeout(drain_timeout)
        if segment and len(payload) > 1:
            i = 0
            while i < len(payload):
                n = random.randint(1, max(1, len(payload) // 3))
                s.sendall(payload[i:i + n]); i += n
                time.sleep(0.001)
        else:
            s.sendall(payload)
        try:
            s.recv(65536)          # drain whatever (if anything) comes back
        except socket.timeout:
            return "timeout"       # benign on its own — not a crash
        return "ok"
    except (ConnectionResetError, BrokenPipeError, OSError):
        return "reset"             # benign on its own — liveness decides
    finally:
        try: s.close()
        except OSError: pass

def liveness(host, port, timeout, retries=3):
    """STATELESS probe on a fresh socket: *IDN? must get a reply. True = server alive."""
    for _ in range(retries):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(b"*IDN?\n")
            data = s.recv(4096)
            s.close()
            if data:
                return True
        except OSError:
            pass
        time.sleep(0.25)
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5025)
    ap.add_argument("--corpus", default=os.path.expanduser("~/scpi-fuzzer/corpus2"))
    ap.add_argument("--timeout", type=float, default=1.5, help="connect/liveness timeout")
    ap.add_argument("--drain-timeout", type=float, default=0.25, help="per-case reply drain wait")
    ap.add_argument("--max", type=int, default=0, help="0 = all corpus files")
    ap.add_argument("--segment", action="store_true", help="split sends to probe TCP segmentation")
    ap.add_argument("--crash-dir", default="wire-crashes")
    args = ap.parse_args()

    files = sorted(os.path.join(args.corpus, f) for f in os.listdir(args.corpus)
                   if os.path.isfile(os.path.join(args.corpus, f)))
    if args.max:
        files = files[:args.max]
    os.makedirs(args.crash_dir, exist_ok=True)

    if not liveness(args.host, args.port, args.timeout):
        print(f"[FATAL] target {args.host}:{args.port} not alive at start", file=sys.stderr)
        return 2

    print(f"[*] target {args.host}:{args.port}  cases={len(files)}  segment={args.segment}")
    stats = {"ok": 0, "timeout": 0, "reset": 0, "refused": 0}
    crashes = 0
    for idx, path in enumerate(files):
        payload = open(path, "rb").read()
        r = send_case(args.host, args.port, payload, args.timeout, args.segment, args.drain_timeout)
        stats[r] += 1
        # liveness check after any non-ok result, and periodically
        if r != "ok" or idx % 100 == 0:
            if not liveness(args.host, args.port, args.timeout):
                crashes += 1
                dst = os.path.join(args.crash_dir, f"wire-crash-{os.path.basename(path)}")
                open(dst, "wb").write(payload)
                print(f"[CRASH] liveness FAILED after case {os.path.basename(path)} "
                      f"(result={r}) -> saved {dst}", file=sys.stderr)
                return 1   # server down; stop (a real finding)
    print(f"[DONE] cases={len(files)} stats={stats} crashes={crashes}")
    print("[RESULT] server SURVIVED — robustness holds over the wire" if crashes == 0
          else f"[RESULT] {crashes} crash(es)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
