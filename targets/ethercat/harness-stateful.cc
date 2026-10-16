// Phase-1b libFuzzer harness for ecx_inframe()'s STATEFUL branches (oshw/linux/nicdrv.c:399-419) --
// the "already buffered" fast paths that harness.cc's single-call design can't reach (they need
// rxbufstat[idx] == EC_BUF_RCVD going in, which only ecx_inframe() itself ever sets, via its own
// "someone else is waiting for it" branch at nicdrv.c:446-455).
//
// Sequence, both calls driven by ONE fuzzed frame (no need to encode two separate frames):
//   1. rxbufstat[0] = EC_BUF_EMPTY (our own polling index), rxbufstat[1..EC_MAXBUF-1] = EC_BUF_TX
//      (representing "we transmitted requests under these indices, awaiting responses" -- a real
//      precondition ecx_outframe() sets in normal operation, not attacker-controlled).
//   2. ecx_inframe(&port, 0, 0) with the fuzzed frame injected -- if the frame's own `index` byte
//      names some idxf in [1, EC_MAXBUF-1], real code stores the frame's payload into
//      rxbuf[idxf] and marks rxbufstat[idxf] = EC_BUF_RCVD (nicdrv.c:446-455, already exercised
//      by harness.cc, not new here).
//   3. ecx_inframe(&port, i, 0) for every i in [1, EC_MAXBUF-1] -- exactly one (the idxf the frame
//      selected) now has rxbufstat[i] == EC_BUF_RCVD and hits the untested fast path
//      (nicdrv.c:399-403 / :412-419), which recomputes an unbounds-checked index from the
//      *already-stored* rxbuf bytes -- same underlying pattern as finding 01, different call site,
//      no ecx_recvpkt()/tempbuf involved this time. The other 14 indices are still EC_BUF_TX,
//      so ecx_inframe() falls into ecx_recvpkt() again, finds no new data pending (EAGAIN), and
//      returns immediately -- harmless, not the path under test.
//
// Same environment workaround as harness.cc (CAP_NET_RAW unavailable, socketpair substitutes for
// the raw socket) -- see that file's header comment and targets/ethercat/TARGET.md for the full
// rationale; not repeated here.

#include <cstdint>
#include <cstddef>
#include <cstring>
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

static ecx_portt g_port;
static int g_sv[2];

static constexpr int kFixedTxBufLength = 60;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
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
        g_port.txbuflength[i] = kFixedTxBufLength;
    }

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_sv) != 0) {
        return 1;
    }
    g_port.sockhandle = g_sv[0];
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > EC_BUFSIZE) {
        return 0;
    }

    // Deterministic per-iteration precondition: index 0 is ours (empty, about to poll), 1..15 are
    // "outstanding requests" (EC_BUF_TX) -- matches what ecx_outframe() sets in real operation.
    g_port.rxbufstat[0] = EC_BUF_EMPTY;
    for (int i = 1; i < EC_MAXBUF; i++) {
        g_port.rxbufstat[i] = EC_BUF_TX;
    }
    memset(&g_port.tempinbuf, 0, sizeof(g_port.tempinbuf));

    ssize_t written = write(g_sv[1], data, size);
    if (written < 0) {
        return 0;
    }

    // Call 1: may populate rxbuf[idxf]/rxbufstat[idxf]=EC_BUF_RCVD for whichever idxf the frame's
    // own `index` byte names (real code, nicdrv.c:446-455).
    ecx_inframe(&g_port, 0, 0);

    // Call 2: sweep every outstanding index -- exactly one (if any) will have flipped to
    // EC_BUF_RCVD and hit the untested fast path; the rest hit ecx_recvpkt() with no new data
    // and return immediately.
    for (int i = 1; i < EC_MAXBUF; i++) {
        ecx_inframe(&g_port, static_cast<uint8>(i), 0);
    }

    return 0;
}
