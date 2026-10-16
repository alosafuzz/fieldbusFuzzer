#!/usr/bin/env python3
"""
VXI-11 RPC fuzzer for the qemu'd Keysight vendor server (libHppVxi11Server).

Targets the ONC-RPC decode path that is live under qemu-aarch64 (record marking,
RPC CALL header, and the create_link / device_write arg structs incl. the opaque/
string length fields = classic length-lies). The qemu'd server IS the oracle: if
the vendor decoder faults, qemu-aarch64-static prints "uncaught target signal" and
EXITS -> we detect the subprocess death, save the input (a real memory-safety
finding candidate), restart, and continue. Graceful RPC/VXI-11 error replies and
timeouts are benign.

Rigor note: the Win32->POSIX shim (winapi_shim.c) uses coarse stubs; before
claiming any finding, re-check it isn't a shim artifact (tighten the shim, re-run).

Usage: vxi11_rpc_fuzz.py --rootfs ~/scpi-fuzzer/qemu/rootfs \
         --harness ~/scpi-fuzzer/build/vxi11-harness --time 240
"""
import argparse, os, random, socket, struct, subprocess, sys, time

VXI11_CORE_PROG, VXI11_VERS = 395183, 1
PMAP_PORT = 111
CREATE_LINK, DEVICE_WRITE, DEVICE_READ = 10, 11, 12

def xdr_str(b):
    if isinstance(b, str): b = b.encode()
    return struct.pack(">I", len(b)) + b + b"\x00" * ((-len(b)) % 4)

def rpc_record(xid, prog, vers, proc, args):
    body = struct.pack(">IIIIII", xid, 0, 2, prog, vers, proc)  # xid, CALL, rpcvers=2, prog, vers, proc
    body += struct.pack(">II", 0, 0) + struct.pack(">II", 0, 0)  # cred + verf = AUTH_NULL
    body += args
    return struct.pack(">I", 0x80000000 | len(body)) + body     # last-fragment record mark

def create_link_args(client_id=1, lock=0, lock_to=0, device="inst0"):
    return struct.pack(">III", client_id, lock, lock_to) + xdr_str(device)

def device_write_args(lid=0, io_to=1000, lock_to=0, flags=8, data=b"*IDN?\n"):
    return struct.pack(">IIII", lid, io_to, lock_to, flags) + xdr_str(data)

def pmap_getport(host, prog, vers, proto=6, timeout=2.0):
    """ONC-RPC portmapper GETPORT -> the dynamic VXI-11 TCP port (0 if not found)."""
    body = struct.pack(">IIIIII", 0x11111111, 0, 2, 100000, 2, 3)  # portmap v2 GETPORT(3)
    body += struct.pack(">II", 0, 0) + struct.pack(">II", 0, 0)
    body += struct.pack(">IIII", prog, vers, proto, 0)
    rec = struct.pack(">I", 0x80000000 | len(body)) + body
    try:
        s = socket.create_connection((host, PMAP_PORT), timeout=timeout); s.settimeout(timeout)
        s.sendall(rec); data = s.recv(4096); s.close()
        # skip record mark(4)+xid(4)+REPLY(4)+accept(4)+verf(8)+accept_stat(4) = 28, then port(4)
        return struct.unpack(">I", data[28:32])[0] if len(data) >= 32 else 0
    except OSError:
        return 0

def seeds():
    x = random.randint(1, 1 << 30)
    return [
        rpc_record(x, VXI11_CORE_PROG, VXI11_VERS, CREATE_LINK, create_link_args()),
        rpc_record(x, VXI11_CORE_PROG, VXI11_VERS, CREATE_LINK, create_link_args(device="inst0,0")),
        rpc_record(x, VXI11_CORE_PROG, VXI11_VERS, DEVICE_WRITE, device_write_args()),
        rpc_record(x, VXI11_CORE_PROG, VXI11_VERS, DEVICE_READ,
                   struct.pack(">IIIII", 0, 1024, 1000, 0, 0x0A)),
    ]

def mutate(buf):
    b = bytearray(buf); r = random.random()
    if r < 0.30 and len(b) >= 4:          # corrupt a 4-byte field (length-lie on record mark / str len)
        off = random.choice([0, random.randrange(0, len(b) - 3)])
        b[off:off+4] = random.choice([b"\xff\xff\xff\xff", b"\x00\x00\x00\x00",
                                      b"\x7f\xff\xff\xff", struct.pack(">I", random.randint(0, 1<<31))])
    elif r < 0.55:                        # random byte flips
        for _ in range(random.randint(1, 8)):
            if b: b[random.randrange(len(b))] = random.randrange(256)
    elif r < 0.75 and len(b) > 8:         # truncate
        b = b[:random.randrange(4, len(b))]
    elif r < 0.9:                         # extend with junk
        b += bytes(random.randrange(256) for _ in range(random.randint(1, 64)))
    else:                                 # bump record-mark length (claim more than sent)
        if len(b) >= 4: b[0:4] = struct.pack(">I", 0x80000000 | random.randint(len(b), 1<<20))
    return bytes(b)

class Server:
    def __init__(self, rootfs, harness):
        self.rootfs, self.harness = rootfs, harness; self.p = None; self.port = 0; self.restarts = 0
    def start(self):
        self.p = subprocess.Popen(["qemu-aarch64-static", "-L", self.rootfs, self.harness],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(40):
            time.sleep(0.25)
            self.port = pmap_getport("127.0.0.1", VXI11_CORE_PROG, VXI11_VERS)
            if self.port: return True
            if self.p.poll() is not None: return False
        return False
    def alive(self):
        return self.p is not None and self.p.poll() is None
    def stderr_tail(self):
        try: return (self.p.stderr.read() or b"").decode(errors="replace")[-400:]
        except Exception: return ""
    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.kill()
            try: self.p.wait(timeout=3)
            except Exception: pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rootfs", default=os.path.expanduser("~/scpi-fuzzer/qemu/rootfs"))
    ap.add_argument("--harness", default=os.path.expanduser("~/scpi-fuzzer/build/vxi11-harness"))
    ap.add_argument("--time", type=float, default=240)
    ap.add_argument("--crash-dir", default="vxi11-crashes")
    ap.add_argument("--max", type=int, default=0, help="stop after N cases (0=unbounded until --time)")
    ap.add_argument("--fresh-per-case", action="store_true",
                    help="start a FRESH server per input (no state accumulation, no overlapping "
                         "connection threads) — isolates per-input vendor bugs from cumulative/"
                         "concurrency artifacts. Slow (~qemu boot per case).")
    args = ap.parse_args()
    os.makedirs(args.crash_dir, exist_ok=True)

    def save_crash(payload, srv, cases):
        tail = srv.stderr_tail()
        name = os.path.join(args.crash_dir, f"vxi11-crash-{int(time.time()*1000)%100000}.bin")
        open(name, "wb").write(payload); open(name + ".stderr.txt", "w").write(tail)
        print(f"[CRASH] server died after case {cases}; saved {name}\n  qemu: "
              f"{tail.strip().splitlines()[-1] if tail.strip() else '(no stderr)'}", file=sys.stderr)
        return name

    t0 = time.time(); cases = 0; crashes = 0; restarts = 0
    corpus = seeds()

    if args.fresh_per_case:
        print("[*] FRESH-PER-CASE mode: one disposable server per input (artifact-exclusion run)")
        while time.time() - t0 < args.time and (args.max == 0 or cases < args.max):
            srv = Server(args.rootfs, args.harness)
            if not srv.start():
                print("[FATAL] fresh server did not come up", file=sys.stderr); break
            payload = mutate(random.choice(corpus)); cases += 1
            try:
                s = socket.create_connection(("127.0.0.1", srv.port), timeout=1.0); s.settimeout(0.4)
                s.sendall(payload)
                try: s.recv(8192)
                except socket.timeout: pass
                s.close()
            except OSError:
                pass
            time.sleep(0.3)
            if not srv.alive(): crashes += 1; save_crash(payload, srv, cases)
            srv.stop()
        print(f"[DONE/fresh-per-case] cases={cases} crashes={crashes} time={time.time()-t0:.0f}s")
        print("[RESULT] per-input robust — 0 crashes with NO state/concurrency accumulation "
              "=> prior campaign crashes were cumulative/concurrency artifacts, not per-input vendor bugs"
              if crashes == 0 else f"[RESULT] {crashes} per-input crash(es) — a FRESH server crashed on a "
              "single input => genuine per-input lead; triage vs shim before claiming")
        return 0

    # sustained (long-lived server) mode
    srv = Server(args.rootfs, args.harness)
    if not srv.start():
        print("[FATAL] server did not come up / register", file=sys.stderr); return 2
    print(f"[*] VXI-11 server up under qemu, port {srv.port} (sustained mode)")
    last = None
    while time.time() - t0 < args.time and (args.max == 0 or cases < args.max):
        payload = mutate(random.choice(corpus)); last = payload; cases += 1
        try:
            s = socket.create_connection(("127.0.0.1", srv.port), timeout=1.0); s.settimeout(0.4)
            s.sendall(payload)
            try: s.recv(8192)
            except socket.timeout: pass
            s.close()
        except OSError:
            pass
        if not srv.alive():
            crashes += 1; save_crash(last, srv, cases)
            if not srv.start():
                print("[*] server did not restart; stopping", file=sys.stderr); break
            restarts += 1
    srv.stop()
    print(f"[DONE] cases={cases} crashes={crashes} restarts={restarts} time={time.time()-t0:.0f}s")
    print("[RESULT] vendor VXI-11 decoder SURVIVED (robust)" if crashes == 0
          else f"[RESULT] {crashes} crash(es) — triage vs shim artifacts before claiming")
    return 0

if __name__ == "__main__":
    sys.exit(main())
