// Phase-1 libFuzzer harness for SOEM's ecx_inframe() (oshw/linux/nicdrv.c) -- the top-level
// inbound EtherCAT frame parser. Entry point identified by reading source directly (not guessed
// from file names), per this suite's method commitments -- see targets/ethercat/TARGET.md.
//
// ecx_inframe() is not a pure buffer-in/struct-out function like a prior target's request parser --
// it calls ecx_recvpkt() -> recv(*stack->sock, ...) internally. The real driver
// (ecx_setupnic()) opens a PF_PACKET/SOCK_RAW socket bound to a real NIC, which requires
// CAP_NET_RAW (confirmed unavailable in this sandboxed environment: a bare
// socket(AF_PACKET, SOCK_RAW, ...) call fails with EPERM here). Rather than run ecx_setupnic()
// unmodified, this harness reproduces its non-socket initialization (mutexes, stack pointers,
// rxbufstat clear -- see ecx_setupnic() in nicdrv.c for the parts being mirrored) and substitutes
// an AF_UNIX SOCK_DGRAM socketpair for the raw socket. ecx_recvpkt()'s recv() call doesn't care
// about socket family -- this exercises the real ecx_inframe()/ecx_recvpkt() code, wire bytes in,
// with no source modification, same "harness works around environment, not around the target"
// principle a prior target's phase-1 harness used for HandlerMessages' pure-virtual stubs.
//
// Threat model: txbuflength[idx] represents what THIS master transmitted (never attacker-
// controlled -- set from our own ecx_outframe() calls in real usage), fixed here at a plausible
// constant. The fuzzed bytes represent what came back over the wire -- realistic malicious/
// corrupted-slave or on-wire-tampering content, independent in both content and length from what
// was sent. This is deliberately the same split a prior target's harness used between "attacker input"
// and "our own already-validated state."

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
#include "soem/soem.h"
#include "nicdrv.h"

// ecx_inframe() is defined (non-static) in nicdrv.c but, unlike every other public function in
// that file, isn't declared in nicdrv.h -- an upstream header omission, not a harness workaround.
// Forward-declared here rather than patching the vendored header, matching this suite's
// commitment not to modify target source for build convenience.
int ecx_inframe(ecx_portt *port, uint8 idx, int stacknumber);
}

#ifndef ETH_P_ECAT
#define ETH_P_ECAT 0x88A4
#endif

static ecx_portt g_port;
static int g_sv[2];

// txbuflength[idx] must reflect a value THIS master set from its own prior ecx_outframe() call --
// never fuzzer-controlled (see file header). 60 bytes is a minimal realistic EtherCAT frame
// (14-byte Ethernet header + 12-byte EtherCAT header + one small datagram + WKC), matching the
// smallest real frame ecx_outframe() would produce.
static constexpr int kFixedTxBufLength = 60;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    memset(&g_port, 0, sizeof(g_port));

    // Mirrors ecx_setupnic()'s non-socket initialization (nicdrv.c) -- mutexes, stack pointers,
    // rxbufstat clear. Deliberately skips the PF_PACKET/SOCK_RAW open + ioctl + bind sequence,
    // which needs CAP_NET_RAW this environment doesn't have.
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(&g_port.getindex_mutex, &mutexattr);
    pthread_mutex_init(&g_port.tx_mutex, &mutexattr);
    pthread_mutex_init(&g_port.rx_mutex, &mutexattr);
    g_port.redstate = 0; // ECT_RED_NONE
    g_port.stack.sock = &g_port.sockhandle;
    g_port.stack.txbuf = &g_port.txbuf;
    g_port.stack.txbuflength = &g_port.txbuflength;
    g_port.stack.tempbuf = &g_port.tempinbuf;
    g_port.stack.rxbuf = &g_port.rxbuf;
    g_port.stack.rxbufstat = &g_port.rxbufstat;
    g_port.stack.rxsa = &g_port.rxsa;
    for (int i = 0; i < EC_MAXBUF; i++) {
        ec_setupheader(&g_port.txbuf[i]);
        g_port.rxbufstat[i] = EC_BUF_EMPTY;
        g_port.txbuflength[i] = kFixedTxBufLength;
    }

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_sv) != 0) {
        return 1;
    }
    g_port.sockhandle = g_sv[0];
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // EC_BUFSIZE (1518) is the real per-frame buffer size (ec_bufT) -- cap fuzz input to it so
    // the injected datagram can never exceed what a real recv() call could return into tempbuf,
    // matching a prior target's phase-1 lesson (harness buffer shape must match the real one exactly,
    // not just be "big enough", or an overread lands off the harness's own allocation instead of
    // reflecting real in-bounds stale-buffer content).
    if (size == 0 || size > EC_BUFSIZE) {
        return 0;
    }

    const uint8_t idx = 0;
    // Zero tempbuf deterministically each iteration so any bytes ecx_inframe() reads beyond
    // `size` (e.g. reading ehp->etype from a frame shorter than the Ethernet header) are a
    // reproducible zero-fill, not stale content left over from a previous iteration -- keeps
    // findings deterministic (this suite's reproduce->=3x rigor bar) instead of order-dependent.
    memset(&g_port.tempinbuf, 0, sizeof(g_port.tempinbuf));
    g_port.rxbufstat[idx] = EC_BUF_EMPTY;

    ssize_t written = write(g_sv[1], data, size);
    if (written < 0) {
        return 0;
    }

    ecx_inframe(&g_port, idx, 0);
    return 0;
}
