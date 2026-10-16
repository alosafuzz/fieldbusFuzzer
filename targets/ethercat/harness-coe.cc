// Phase-2b libFuzzer harness for ecx_SDOread() (src/ec_coe.c) -- the CoE (CANopen over EtherCAT)
// SDO read path. Highest real-world value of the untested mailbox protocols (CoE is the most
// commonly used one in real deployments) -- picked ahead of ecx_SoEwrite/FoE/EoE for that reason,
// not because it was the target's original selection motivation (that was SoE/issue #981).
//
// Same datagram-generator responder architecture as harness-soeread.cc -- see that file's header
// for the full design rationale, not repeated here. One difference: ecx_SDOread()'s own drain call
// (line ~132, `wkc = ecx_mbxreceive(context, slave, &MbxIn, 0);`) is used safely later (a real
// `if (MbxIn)` NULL check at line ~166) unlike ecx_SoEread()'s original issue-#981 bug, so no
// de-confounding patch is needed here to reach the interesting logic -- confirmed by reading the
// source first, not assumed.
//
// Specific lead being tested, not just generic fuzzing: `SDOlen = etohl(aSDOp->ldata[0])` is a
// SIGNED int32 read directly from the (fuzzed) slave response, gated by `SDOlen <= *psize`
// (signed comparison -- a negative SDOlen trivially satisfies this for any positive psize), then
// used as `memcpy(bp, &aSDOp->ldata[1], SDOlen)`'s length -- memcpy's size_t parameter would
// reinterpret a negative SDOlen as an enormous unsigned copy size. Seeded explicitly to test this
// hypothesis directly (see gen-seed step in build/run instructions), not left purely to random
// mutation to stumble onto.

#include <cstdint>
#include <cstddef>
#include <cstdio>
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

const uint8_t *g_fuzz_data = nullptr;
size_t g_fuzz_size = 0;

uint16_t rd16(const uint8_t *p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
void wr16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
}

void respond(int idx_byte, uint16_t requested_dlength, const uint8_t *payload, uint16_t payload_len) {
    uint8_t frame[ETH_HEADERSIZE + EC_HEADERSIZE + 1518];
    ec_setupheader(frame);
    uint8_t *dg = frame + ETH_HEADERSIZE;
    wr16(dg + 0, EC_ECATTYPE + EC_HEADERSIZE + requested_dlength);
    dg[2] = 0;
    dg[3] = static_cast<uint8_t>(idx_byte);
    wr16(dg + 4, kConfigAdr);
    wr16(dg + 6, 0);
    wr16(dg + 8, requested_dlength);
    wr16(dg + 10, 0);

    uint16_t n = payload_len < requested_dlength ? payload_len : requested_dlength;
    if (n > 0 && payload != nullptr) {
        memcpy(dg + EC_HEADERSIZE, payload, n);
    }
    if (n < requested_dlength) {
        memset(dg + EC_HEADERSIZE + n, 0, requested_dlength - n);
    }
    wr16(dg + EC_HEADERSIZE + requested_dlength, 1);

    size_t framelen = ETH_HEADERSIZE + EC_HEADERSIZE + requested_dlength + EC_WKCSIZE;
    write(g_sv[1], frame, framelen);
}

void responder_loop() {
    // BUG FOUND 2026-08-10 (same as harness-soeread.cc): this is the thread entry point, called
    // ONCE for the whole process -- a per-call response cap here silently starves every fuzz
    // iteration after the first ~10-16 files' worth of exchanges for the rest of the run. No
    // longer capped; blocks on recv() so it doesn't spin when idle.
    uint8_t buf[EC_BUFSIZE];
    while (true) {
        ssize_t n = recv(g_sv[1], buf, sizeof(buf), 0);
        if (n <= 0) continue;
        if (static_cast<size_t>(n) < ETH_HEADERSIZE + EC_HEADERSIZE) continue;
        // etype is set via ec_setupheader()'s htons(ETH_P_ECAT) -- real Ethernet-level network
        // (big-endian) byte order, UNLIKE the EtherCAT-internal fields below (which use htoes,
        // identity/little-endian on this host). Compare raw bytes, not via the little-endian
        // rd16() helper -- using rd16() here silently failed this check on every frame (caught
        // 2026-08-09 while investigating why a targeted seed produced zero responder activity).
        if (buf[12] != 0x88 || buf[13] != 0xA4) continue;

        const uint8_t *dg = buf + ETH_HEADERSIZE;
        uint8_t command = dg[2];
        uint8_t idx_byte = dg[3];
        uint16_t dlength = rd16(dg + 8);

        if (command == EC_CMD_FPWR) {
            respond(idx_byte, dlength, nullptr, 0);
        } else if (command == EC_CMD_FPRD) {
            if (dlength <= 4) {
                uint8_t status = 0x08;
                respond(idx_byte, dlength, &status, 1);
            } else {
                respond(idx_byte, dlength, g_fuzz_data, static_cast<uint16_t>(g_fuzz_size));
            }
        }
    }
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
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
    }

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_sv) != 0) {
        return 1;
    }
    port->sockhandle = g_sv[0];

    ecx_initmbxpool(&g_context);

    ec_slavet *sl = &g_context.slavelist[kSlave];
    sl->configadr = kConfigAdr;
    sl->state = EC_STATE_PRE_OP;
    sl->mbxhandlerstate = ECT_MBXH_NONE;
    sl->mbx_l = 512;
    sl->mbx_wo = 0x1000;
    sl->mbx_rl = 512;
    sl->mbx_ro = 0x1100;
    sl->mbx_cnt = 0;

    g_responder = std::thread(responder_loop);
    g_responder.detach();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > EC_MAXMBX) {
        return 0;
    }

    g_context.slavelist[kSlave].mbx_cnt = 0;
    g_fuzz_data = data;
    g_fuzz_size = size;

    int psize = 128; // fixed, realistic caller-supplied buffer size -- deliberately NOT tied to
                      // the fuzzed input, matching the real threat model (SDOlen is what a
                      // malicious/corrupted slave claims, psize is what the caller actually
                      // allocated -- these must be independent for the size-check-bypass lead to
                      // mean anything).
    static uint8_t out[4096]; // generously larger than psize so a real overflow past psize (but
                               // within this array) is still observable via ASan's own redzone,
                               // not masked by hitting an immediately-adjacent unrelated crash.
    memset(out, 0, sizeof(out));

    ecx_SDOread(&g_context, kSlave, /*index=*/0x6000, /*subindex=*/0,
                /*CA=*/FALSE, &psize, out, /*timeout=*/20000);

    g_fuzz_data = nullptr;
    g_fuzz_size = 0;
    return 0;
}
