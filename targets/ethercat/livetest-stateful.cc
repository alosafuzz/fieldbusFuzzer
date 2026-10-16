// Live, two-process reproduction for finding 02 (the stateful "already buffered" sibling).
// Same real ecx_setupnic()/veth approach as livetest-inframe.cc -- see that file's header for the
// rationale. Sets up rxbufstat[1..EC_MAXBUF-1]=EC_BUF_TX (a real "we're awaiting these responses"
// precondition, matching what ecx_outframe() sets in real operation -- not attacker-controlled),
// polls idx=0 once to receive+store the injected frame via the real "someone else is waiting for
// it" branch, then sweeps every outstanding index to hit the fast path the stored bytes trigger.
#include <cstdio>
#include <cstring>
#include <unistd.h>

extern "C" {
#include "soem/soem.h"
#include "nicdrv.h"
int ecx_inframe(ecx_portt *port, uint8 idx, int stacknumber);
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
    // Every outstanding index needs its own txbuflength set (what THIS master would have sent
    // under that index) -- the "someone else waiting" branch indexes txbuflength[idxf], not
    // txbuflength[idx]. Missing this on the first run caused the same underflow-memcpy confound
    // as livetest-inframe.cc's first run, just at nicdrv.c:451 instead of :436.
    for (int i = 0; i < EC_MAXBUF; i++) {
        port.txbuflength[i] = 60;
    }
    for (int i = 1; i < EC_MAXBUF; i++) {
        port.rxbufstat[i] = EC_BUF_TX;
    }
    fprintf(stderr, "Listening on real interface %s, waiting for a frame (idx=0, mismatch "
                     "path)...\n", argv[1]);

    bool got_one = false;
    for (int i = 0; i < 500 && !got_one; i++) {
        int rval = ecx_inframe(&port, 0, 0);
        if (rval != EC_NOFRAME) {
            got_one = true;
            break;
        }
        usleep(10000);
    }
    if (!got_one) {
        fprintf(stderr, "Timed out waiting for the first frame\n");
        ecx_closenic(&port);
        return 3;
    }
    fprintf(stderr, "First call returned -- sweeping outstanding indices for the stored-buffer "
                     "fast path...\n");
    for (int i = 1; i < EC_MAXBUF; i++) {
        int rval = ecx_inframe(&port, static_cast<uint8>(i), 0);
        fprintf(stderr, "ecx_inframe(idx=%d) = %d\n", i, rval);
    }
    fprintf(stderr, "no crash\n");
    ecx_closenic(&port);
    return 0;
}
