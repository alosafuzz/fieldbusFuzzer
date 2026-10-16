// Phase-2e libFuzzer harness for ecx_EOEgetIp() (src/ec_eoe.c) -- EoE GetIP, requesting a slave's
// IP configuration. Same datagram-generator responder architecture as harness-eoe.cc -- see
// harness-soeread.cc's header for the full design rationale, not repeated here.
//
// Specific lead being tested, not just generic fuzzing: `ec_eoe.c`'s `ecx_EOEgetIp()` walks
// through six optional IP-parameter fields gated by a slave-controlled `flags` byte, advancing a
// running `uint8 data_offset` for each field present, copying each via a fixed-size memcpy --
// BEFORE validating that the claimed response length (`eoedatasize`) actually covers what's been
// read. The last field (dns_name) computes:
//   if ((eoedatasize - data_offset) < EOE_DNS_NAME_LENGTH) dns_len = (eoedatasize - data_offset);
// `eoedatasize - data_offset` is computed in `int` and can go NEGATIVE if enough earlier flags
// pushed `data_offset` past a deliberately small `eoedatasize` -- assigning that negative int into
// `uint16_t dns_len` wraps it to ~65530, sizing `memcpy(ipparam->dns_name, ..., dns_len)` into a
// FIXED 32-byte destination field. Predicted trigger: flags=0x3F (all six bits set, pushing
// data_offset to 26 by the time the dns_name check runs) with mbxheader.length crafted so
// eoedatasize < 26. Seeded explicitly to test this hypothesis directly, not left purely to random
// mutation to stumble onto -- same discipline as findings 03/05/06/07.

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
    uint8_t buf[EC_BUFSIZE];
    while (true) {
        ssize_t n = recv(g_sv[1], buf, sizeof(buf), 0);
        if (n <= 0) continue;
        if (static_cast<size_t>(n) < ETH_HEADERSIZE + EC_HEADERSIZE) continue;
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

    eoe_param_t ipparam;
    memset(&ipparam, 0, sizeof(ipparam));

    ecx_EOEgetIp(&g_context, kSlave, /*port=*/0, &ipparam, /*timeout=*/20000);

    g_fuzz_data = nullptr;
    g_fuzz_size = 0;
    return 0;
}
