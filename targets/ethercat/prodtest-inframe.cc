// Stock (non-sanitized) production-build impact test for findings 01/02 -- same rigor a prior target's
// findings got (explicit test against a plain build, not just ASan/UBSan). Not a libFuzzer
// harness: an ordinary standalone program, built with no sanitizers, that replays the exact
// finding 01/02 crash inputs against the real, unmodified ecx_inframe() and reports whether the
// process crashes (SIGSEGV/etc, checked via the caller's exit status) or silently continues.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <fstream>
#include <vector>

extern "C" {
#include "soem/soem.h"
#include "nicdrv.h"
int ecx_inframe(ecx_portt *port, uint8 idx, int stacknumber);
}

#ifndef ETH_P_ECAT
#define ETH_P_ECAT 0x88A4
#endif

static ecx_portt g_port;
static int g_sv[2];

std::vector<uint8_t> read_file(const char *path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s [inframe|stateful] <crash-input-file>\n", argv[0]);
        return 2;
    }
    bool stateful = strcmp(argv[1], "stateful") == 0;

    memset(&g_port, 0, sizeof(g_port));
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(&g_port.getindex_mutex, &mutexattr);
    pthread_mutex_init(&g_port.tx_mutex, &mutexattr);
    pthread_mutex_init(&g_port.rx_mutex, &mutexattr);
    g_port.redstate = 0;
    g_port.stack.sock = &g_port.sockhandle;
    g_port.stack.txbuf = &g_port.txbuf;
    g_port.stack.txbuflength = &g_port.txbuflength;
    g_port.stack.tempbuf = &g_port.tempinbuf;
    g_port.stack.rxbuf = &g_port.rxbuf;
    g_port.stack.rxbufstat = &g_port.rxbufstat;
    g_port.stack.rxsa = &g_port.rxsa;
    for (int i = 0; i < EC_MAXBUF; i++) {
        ec_setupheader(&g_port.txbuf[i]);
        g_port.txbuflength[i] = 60;
    }
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_sv) != 0) {
        perror("socketpair");
        return 2;
    }
    g_port.sockhandle = g_sv[0];

    auto data = read_file(argv[2]);
    fprintf(stderr, "Loaded %zu bytes from %s\n", data.size(), argv[2]);

    if (!stateful) {
        g_port.rxbufstat[0] = EC_BUF_EMPTY;
        write(g_sv[1], data.data(), data.size());
        int rval = ecx_inframe(&g_port, 0, 0);
        fprintf(stderr, "ecx_inframe returned %d -- no crash\n", rval);
    } else {
        g_port.rxbufstat[0] = EC_BUF_EMPTY;
        for (int i = 1; i < EC_MAXBUF; i++) g_port.rxbufstat[i] = EC_BUF_TX;
        write(g_sv[1], data.data(), data.size());
        ecx_inframe(&g_port, 0, 0);
        for (int i = 1; i < EC_MAXBUF; i++) {
            int rval = ecx_inframe(&g_port, static_cast<uint8>(i), 0);
            fprintf(stderr, "ecx_inframe(idx=%d) returned %d\n", i, rval);
        }
        fprintf(stderr, "no crash\n");
    }
    return 0;
}
