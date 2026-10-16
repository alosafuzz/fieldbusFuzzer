// Live, two-process reproduction for findings 01/02 -- unlike every other harness in this target,
// this uses the REAL ecx_setupnic() (real PF_PACKET/SOCK_RAW socket, real NIC bind) against a
// veth pair, exactly mirroring how GitHub issue #981's own reporter reproduced that bug. Needs
// CAP_NET_RAW (run under sudo, or setcap'd). No socketpair substitution -- this is the genuine
// wire path this project's own rigor bar calls for before treating a finding as fully proven.
#include <cstdio>
#include <cstring>
#include <unistd.h>

extern "C" {
#include "soem/soem.h"
#include "nicdrv.h"
int ecx_inframe(ecx_portt *port, uint8 idx, int stacknumber); // missing from nicdrv.h upstream
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
        return 2;
    }

    ecx_portt port;
    memset(&port, 0, sizeof(port));

    if (!ecx_setupnic(&port, argv[1], 0)) {
        fprintf(stderr, "ecx_setupnic(%s) failed\n", argv[1]);
        return 1;
    }
    // ecx_setupnic() doesn't set txbuflength[idx] -- that's normally set by a prior
    // ecx_outframe() call (this master's own transmit). This test skips ever transmitting (we're
    // injecting a "response" with no matching request), so without this, txbuflength[0] stays 0
    // and (*stack->txbuflength)[idx] - ETH_HEADERSIZE underflows in ecx_inframe()'s memcpy --
    // caught this exact confound on the first run (negative-size-param at nicdrv.c:436, a
    // harness-setup artifact, not finding 01's bug). Set explicitly here to the same value the
    // phase-1 fuzzing harnesses used, matching the real "what we transmitted" precondition.
    port.txbuflength[0] = 60;
    fprintf(stderr, "Listening on real interface %s via real ecx_setupnic(), waiting for a "
                     "frame (idx=0)...\n", argv[1]);

    for (int i = 0; i < 500; i++) {
        int rval = ecx_inframe(&port, 0, 0);
        if (rval != EC_NOFRAME) {
            fprintf(stderr, "ecx_inframe returned %d after %d polls -- no crash\n", rval, i);
            ecx_closenic(&port);
            return 0;
        }
        usleep(10000); // 10ms poll interval
    }
    fprintf(stderr, "Timed out waiting for a frame -- no crash, but also never received one\n");
    ecx_closenic(&port);
    return 3;
}
