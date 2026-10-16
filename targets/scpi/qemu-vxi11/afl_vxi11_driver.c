/*
 * AFL++ qemu-mode driver for the real Keysight VXI-11 server (Route B, coverage-guided).
 *
 * FIDELITY-PRESERVING design (per the rigor goal): brings up the REAL vendor server
 * in-process (inet_start_VXI11_server spawns its RPC worker thread), then reads ONE
 * RPC record from stdin and drives it at the server over loopback. afl-qemu-trace
 * instruments the WHOLE process — including the vendor decode running on the server
 * thread — so AFL gets edge coverage of the genuine decode path, in its real context,
 * with input from stdin (AFL-native). No desock, no RE'd internal function, no
 * out-of-context execution => the LEAST artifact-prone AFL setup for this target.
 *
 * Run: QEMU_LD_PREFIX=<rootfs> afl-fuzz -Q -i seeds -o out -- ./afl_vxi11_driver
 * (afl-fuzz -Q uses the aarch64 afl-qemu-trace we built). For speed, set
 * AFL_ENTRYPOINT past the init block so the forkserver reuses the already-started
 * server instead of re-running inet_start per exec (see run-afl.sh).
 *
 * RIGOR GATE: any AFL crash here is a LEAD, confirmed only by (1) isolation replay,
 * (2) fresh-per-case, (3) wire-repro on a normally-run server, (4) module attribution
 * (vendor vs winapi_shim vs libtirpc) — same bar the structured campaign used.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern int inet_start_VXI11_server(void);
#define VXI11_PROG 395183u
#define VXI11_VERS 1u

static unsigned short g_port = 0;

/* Hand-rolled ONC-RPC portmapper GETPORT (no libtirpc headers needed): ask
 * 127.0.0.1:111 for the dynamic VXI-11 Device Core TCP port. */
static unsigned short pmap_getport_vxi11(void) {
    uint32_t body[14] = {
        htonl(0x11111111), 0, htonl(2), htonl(100000), htonl(2), htonl(3),   /* portmap v2 GETPORT */
        0, 0, 0, 0,                                                          /* cred + verf AUTH_NULL */
        htonl(VXI11_PROG), htonl(VXI11_VERS), htonl(6), 0 };                 /* prog,vers,IPPROTO_TCP,port=0 */
    uint8_t rec[4 + sizeof body];
    *(uint32_t*)rec = htonl(0x80000000u | (uint32_t)sizeof body);
    memcpy(rec + 4, body, sizeof body);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = inet_addr("127.0.0.1"); a.sin_port = htons(111);
    unsigned short port = 0;
    if (connect(s, (struct sockaddr*)&a, sizeof a) == 0 && write(s, rec, sizeof rec) > 0) {
        uint8_t resp[64]; ssize_t n = recv(s, resp, sizeof resp, 0);
        if (n >= 32) port = (unsigned short)ntohl(*(uint32_t*)(resp + 28));  /* port at offset 28 */
    }
    close(s);
    return port;
}

static void init_server(void) {
    inet_start_VXI11_server();                 /* real server on its worker thread */
    for (int i = 0; i < 50 && !g_port; i++) {
        g_port = pmap_getport_vxi11();
        if (!g_port) usleep(100000);
    }
}

/* AFL_ENTRYPOINT can be set to this symbol so the forkserver snapshots AFTER init. */
__attribute__((noinline)) void afl_one_request(void) {
    unsigned char buf[65536];
    ssize_t n = read(0, buf, sizeof buf);      /* AFL feeds the RPC record on stdin */
    if (n <= 0) return;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = inet_addr("127.0.0.1"); a.sin_port = htons(g_port);
    if (connect(s, (struct sockaddr*)&a, sizeof a) == 0) {
        if (write(s, buf, n) > 0) { char r[8192]; (void)!recv(s, r, sizeof r, MSG_DONTWAIT); }
    }
    close(s);
}

int main(void) {
    init_server();
    if (!g_port) { fprintf(stderr, "[afl-driver] server did not register\n"); return 0; }
    afl_one_request();
    return 0;
}
