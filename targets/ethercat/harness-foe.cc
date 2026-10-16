// Phase-2c libFuzzer harness for ecx_FOEread() (src/ec_foe.c) -- FoE (File over EtherCAT), used
// for firmware/file transfer to a slave. Same datagram-generator responder architecture as
// harness-coe.cc/harness-soeread.cc -- see harness-soeread.cc's header for the full design
// rationale, not repeated here.
//
// Specific lead being tested, not just generic fuzzing: `ec_foe.c:134`,
// `segmentdata = etohs(aFOEp->MbxHeader.length) - 0x0006` is computed as **unsigned** `uint16`
// (unlike findings 03/05's signed underflow) -- a short `MbxHeader.length` (<6) wraps it to a huge
// positive value instead of a negative one, so it would normally FAIL the caller's own bounds
// check (`dataread + segmentdata <= buffersize`) rather than bypass it, the opposite shape from
// findings 03/05. BUT FoE's own real threat model routinely uses large caller buffers (firmware
// files can be large), unlike SDO/SoE's small parameter buffers -- if the caller's buffersize
// (`*psize`) is itself >= the wrapped value (up to 65535), the check passes and
// `memcpy(p, &aFOEp->Data[0], segmentdata)` reads up to ~65KB from `aFOEp->Data[0]`, which is only
// really backed by a much smaller real mailbox buffer (`EC_MAXFOEDATA`, well under 1.5KB) --
// a genuine OOB READ past the mailbox buffer, copied into the caller's own (legitimately large)
// output buffer. This harness deliberately uses a LARGE psize (see LLVMFuzzerTestOneInput) to test
// this specific hypothesis, not left purely to random mutation to stumble onto.

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
#include "soem/soem.h"
#include "nicdrv.h"
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
    // Same process-lifetime-not-per-iteration lesson as harness-soeread.cc/harness-coe.cc: no
    // response cap here, blocks on recv() so it doesn't spin when idle.
    uint8_t buf[EC_BUFSIZE];
    while (true) {
        ssize_t n = recv(g_sv[1], buf, sizeof(buf), 0);
        if (n <= 0) continue;
        if (static_cast<size_t>(n) < ETH_HEADERSIZE + EC_HEADERSIZE) continue;
        // etype: real network/big-endian (htons() inside ec_setupheader()) -- compare raw bytes,
        // not the little-endian rd16() helper. See harness-coe.cc's comment for the full story.
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

    // Deliberately LARGE psize -- see header comment. A realistic FoE caller (firmware/file
    // transfer) legitimately allocates a big buffer, unlike SDO/SoE's small parameter buffers.
    // Large enough to accept segmentdata's full possible wrapped range (uint16, max 65535).
    int psize = 70000;
    static uint8_t out[70000];
    memset(out, 0, sizeof(out));

    char filename[] = "test.bin"; // fixed; only affects the outbound request, not the fuzzed
                                   // response, matching the established outbound-path-not-fuzzed
                                   // scope (see TARGET.md's coverage gaps).
    ecx_FOEread(&g_context, kSlave, filename, /*password=*/0, &psize, out, /*timeout=*/20000);

    g_fuzz_data = nullptr;
    g_fuzz_size = 0;
    return 0;
}
