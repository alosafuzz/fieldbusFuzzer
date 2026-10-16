// Phase-2 libFuzzer harness for ecx_SoEread() (src/ec_soe.c) -- the SoE mailbox read path tied to
// GitHub issue #981 (the reason this suite picked EtherCAT as target #2 at all). Unlike
// ecx_inframe() (phase 1), ecx_SoEread() isn't reachable by feeding one buffer to one function --
// it drives a real blocking request/response cycle through ecx_mbxsend()/ecx_mbxreceive(), which
// (in the non-cyclic/default mailbox-handler mode used here) send real EC_CMD_FPWR/EC_CMD_FPRD
// EtherCAT datagrams via ecx_outframe()/ecx_waitinframe() -- the exact ecx_inframe() code phase 1
// already fuzzed, one layer further down.
//
// Rather than bypass that real datagram exchange, this harness includes a minimal DATAGRAM
// GENERATOR/RESPONDER: a background thread that plays the role of a single EtherCAT slave,
// reading whatever real EC_CMD_FPWR/FPRD datagrams ecx_SoEread() actually transmits (over the same
// AF_UNIX/SOCK_DGRAM socketpair substitution phase 1 uses for CAP_NET_RAW) and answering them with
// real, correctly-shaped EtherCAT response datagrams -- built with ecx_setupdatagram()/
// ecx_setupheader(), the same functions the real driver itself uses, not hand-rolled byte layout.
// Fuzzed content goes into the mailbox-data read response specifically (identified by the request's
// own `dlength` field: 1 byte = SM status register poll, answered with a fixed "data ready" byte;
// larger = the actual mailbox payload read, answered with THIS iteration's fuzzed bytes) -- the
// same "attacker input is what a corrupted/malicious slave would send back" threat model phase 1
// used, just one layer deeper (the SoE mailbox response payload instead of the raw frame).
//
// The very first drain call inside ecx_SoEread() (`ecx_mbxreceive(..., timeout=0)`, "empty slave
// out mailbox if something is in") is deliberately left unanswered by the responder so it times
// out fast and MbxIn stays NULL going in -- matching the real "nothing pending yet" precondition,
// not artificially triggering the already-known/reported issue #981 staleness bug as a confound.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <atomic>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
#include "soem/soem.h"
#include "nicdrv.h"

int ecx_inframe(ecx_portt *port, uint8 idx, int stacknumber);
}

#ifndef ETH_P_ECAT
#define ETH_P_ECAT 0x88A4
#endif

namespace {

constexpr uint16_t kSlave = 1;
constexpr uint16_t kConfigAdr = 0x1001;

ecx_contextt g_context;
int g_sv[2];
std::thread g_responder;
std::atomic<bool> g_stop{false};

// Set once per LLVMFuzzerTestOneInput call, read (not written) by the responder thread while
// ecx_SoEread() is blocked on it -- no concurrent read/write overlap, no lock needed (see file
// header rationale).
const uint8_t *g_fuzz_data = nullptr;
size_t g_fuzz_size = 0;

// Minimal ec_comt field reader/writer -- offsets match ec_type.h's ec_comt layout exactly
// (elength:2, command:1, index:1, ADP:2, ADO:2, dlength:2, irpt:2), read directly rather than
// through the real struct to keep the responder decoupled from any one frame buffer's alignment.
uint16_t rd16(const uint8_t *p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
void wr16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
}

// Builds one Ethernet+EtherCAT response frame (header + one datagram + WKC) using the real
// ec_setupheader() for the Ethernet part, matching how ecx_setupdatagram() (ec_base.c) lays out
// the EtherCAT datagram -- not hand-rolled beyond what those two real functions don't cover.
void respond(int idx_byte, uint16_t requested_dlength, const uint8_t *payload, uint16_t payload_len) {
    uint8_t frame[ETH_HEADERSIZE + EC_HEADERSIZE + 1518];
    ec_setupheader(frame);
    uint8_t *dg = frame + ETH_HEADERSIZE;
    wr16(dg + 0, EC_ECATTYPE + EC_HEADERSIZE + requested_dlength); // elength
    dg[2] = 0;                                                    // command (irrelevant on reply)
    dg[3] = static_cast<uint8_t>(idx_byte);                        // index -- must echo request's
    wr16(dg + 4, kConfigAdr);                                      // ADP
    wr16(dg + 6, 0);                                                // ADO
    wr16(dg + 8, requested_dlength);                               // dlength
    wr16(dg + 10, 0);                                              // irpt

    uint16_t n = payload_len < requested_dlength ? payload_len : requested_dlength;
    if (n > 0 && payload != nullptr) {
        memcpy(dg + EC_HEADERSIZE, payload, n);
    }
    if (n < requested_dlength) {
        memset(dg + EC_HEADERSIZE + n, 0, requested_dlength - n);
    }
    // WKC = 1 (one device processed this datagram) -- ecx_FPRD/FPWR only treat wkc>0 as success.
    wr16(dg + EC_HEADERSIZE + requested_dlength, 1);

    size_t framelen = ETH_HEADERSIZE + EC_HEADERSIZE + requested_dlength + EC_WKCSIZE;
    write(g_sv[1], frame, framelen);
}

void responder_loop() {
    // BUG FOUND 2026-08-10: `responded` used to be a per-call-to-responder_loop() counter capped
    // at kMaxRespondsPerInput -- but responder_loop() is the THREAD ENTRY POINT, called exactly
    // ONCE for the whole process, not once per fuzz iteration. The old code capped total
    // responses across the ENTIRE corpus replay at 32, not 32 per input -- after ~10-16 files
    // (each needing 2-4 responses), the responder silently stopped answering anything for the
    // rest of the run. This was the actual cause investigated as "lead-soeread-timeout" -- ruled
    // out mailbox-pool and full-context state bleed first, then found this. No longer capped;
    // the loop already blocks on recv() so an uncapped loop doesn't spin/waste CPU when idle.
    uint8_t buf[EC_BUFSIZE];
    while (!g_stop.load(std::memory_order_relaxed)) {
        ssize_t n = recv(g_sv[1], buf, sizeof(buf), 0); // blocking -- this thread's only job
        if (n <= 0) {
            if (g_stop.load(std::memory_order_relaxed)) return;
            continue;
        }
        if (static_cast<size_t>(n) < ETH_HEADERSIZE + EC_HEADERSIZE) continue;
        // etype is set via ec_setupheader()'s htons(ETH_P_ECAT) -- real Ethernet-level network
        // (big-endian) byte order, UNLIKE the EtherCAT-internal fields below (htoes, identity/
        // little-endian on this host). Comparing raw bytes, not via the little-endian rd16()
        // helper below -- using rd16() here silently failed this check on every single frame,
        // meaning the responder never actually answered anything in this file's original
        // fuzzing sessions. Caught 2026-08-09 while investigating why harness-coe.cc's targeted
        // seed produced zero responder activity; same bug existed here since this file's
        // responder was copied from the same design. See TARGET.md for the re-verification this
        // triggered.
        if (buf[12] != 0x88 || buf[13] != 0xA4) continue;

        const uint8_t *dg = buf + ETH_HEADERSIZE;
        uint8_t command = dg[2];
        uint8_t idx_byte = dg[3];
        uint16_t dlength = rd16(dg + 8);

        if (command == EC_CMD_FPWR) {
            // Our own outbound mailbox write (the SoE read request) -- not what's under fuzz
            // here (see file header); just ack it so ecx_mbxsend() succeeds and ecx_SoEread()
            // proceeds into the interesting read/reassembly logic.
            respond(idx_byte, dlength, nullptr, 0);
        } else if (command == EC_CMD_FPRD) {
            if (dlength <= 4) {
                // ecx_readmbxstatus()'s SM status register poll -- answer "mailbox has data"
                // (bit 0x08) so ecx_mbxreceive() proceeds to the real mailbox-data read below.
                uint8_t status = 0x08;
                respond(idx_byte, dlength, &status, 1);
            } else {
                // The actual mailbox-data read -- THIS is where this iteration's fuzzed bytes
                // become the slave's SoE response, feeding ecx_SoEread()'s reassembly logic.
                respond(idx_byte, dlength, g_fuzz_data, static_cast<uint16_t>(g_fuzz_size));
            }
        }
        // Anything else (including the very first timeout=0 drain call, which real code doesn't
        // wait around for anyway): deliberately not answered, see file header.
    }
}

// DIAGNOSTIC (2026-08-10): full context+slave re-init, extracted into a function called both at
// startup and again at the top of every LLVMFuzzerTestOneInput -- testing whether
// lead-soeread-timeout-2026-08-09.bin's hang is caused by cross-iteration state bleed in
// g_context (not just the mailbox pool, already ruled out separately) rather than a genuine
// per-input infinite/very-slow loop in the target. See TARGET.md before making this permanent.
void init_context() {
    memset(&g_context, 0, sizeof(g_context));

    ecx_portt *port = &g_context.port;
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(&port->getindex_mutex, &mutexattr);
    pthread_mutex_init(&port->tx_mutex, &mutexattr);
    pthread_mutex_init(&port->rx_mutex, &mutexattr);
    port->redstate = 0;
    port->stack.sock = &port->sockhandle;
    port->stack.txbuf = &port->txbuf;
    port->stack.txbuflength = &port->txbuflength;
    port->stack.tempbuf = &port->tempinbuf;
    port->stack.rxbuf = &port->rxbuf;
    port->stack.rxbufstat = &port->rxbufstat;
    port->stack.rxsa = &port->rxsa;
    for (int i = 0; i < EC_MAXBUF; i++) {
        ec_setupheader(&port->txbuf[i]);
        port->rxbufstat[i] = EC_BUF_EMPTY;
    }
    port->sockhandle = g_sv[0]; // fd itself is persistent, only the struct state resets

    ecx_initmbxpool(&g_context);

    ec_slavet *sl = &g_context.slavelist[kSlave];
    sl->configadr = kConfigAdr;
    sl->state = EC_STATE_PRE_OP;
    sl->mbxhandlerstate = ECT_MBXH_NONE; // non-cyclic -- real FPWR/FPRD path, not the queue shortcut
    sl->mbx_l = 64;
    sl->mbx_wo = 0x1000;
    sl->mbx_rl = 64;
    sl->mbx_ro = 0x1100;
    sl->mbx_cnt = 0;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_sv) != 0) {
        return 1;
    }

    init_context();

    g_responder = std::thread(responder_loop);
    // Detached: this responder runs for the whole process lifetime, servicing every fuzz
    // iteration. Detaching (rather than joining at some explicit shutdown point libFuzzer doesn't
    // reliably provide) avoids std::thread's destructor calling std::terminate() on a still-
    // joinable thread when the process exits.
    g_responder.detach();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > EC_MAXMBX) {
        return 0;
    }

    init_context();
    // Drain any stray/delayed datagram left on the master's own socket end from a previous
    // iteration (e.g. a response the responder sent after the master had already stopped
    // listening) before this iteration starts -- part of the same diagnostic, testing whether
    // cross-iteration socket-buffer bleed (not just g_context state) explains the hang.
    {
        uint8_t drain[EC_BUFSIZE];
        while (recv(g_sv[0], drain, sizeof(drain), MSG_DONTWAIT) > 0) {
        }
    }

    g_fuzz_data = data;
    g_fuzz_size = size;

    int psize = static_cast<int>(size) + 64; // caller-supplied buffer, deliberately generous
    static uint8_t out[EC_MAXMBX + 64];
    memset(out, 0, sizeof(out));

    ecx_SoEread(&g_context, kSlave, /*driveNo=*/0, /*elementflags=*/0x07, /*idn=*/1,
                &psize, out, /*timeout=*/20000);

    g_fuzz_data = nullptr;
    g_fuzz_size = 0;
    return 0;
}
