// Live, two-process reproduction for finding 05 (ecx_SoEread negative framedatasize OOB write).
// Real ecx_setupnic() against a veth pair, paired with tools-live-slave.py acting as the
// malicious/corrupted slave over the real wire. See livetest-coe.cc for the base pattern.
//
// Built against src-patched (not the canonical clone) deliberately: issue #981's bug (already
// fixed there) computes a pointer offset from a possibly-NULL MbxIn unconditionally on every
// call, which is UB the instant ecx_SoEread() runs, regardless of what this finding's own trigger
// needs -- without that fix in place, this live test would trip #981 first and never reach
// finding 05's own code. Finding 05 itself is NOT patched in src-patched -- only #981 and the
// unrelated finding 04 fix are.
#include <cstdio>
#include <cstring>

extern "C" {
#include "soem/soem.h"
#include "nicdrv.h"
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <ifname>\n", argv[0]); return 2; }

    ecx_contextt context;
    memset(&context, 0, sizeof(context));

    if (!ecx_setupnic(&context.port, argv[1], 0)) {
        fprintf(stderr, "ecx_setupnic(%s) failed\n", argv[1]);
        return 1;
    }
    ecx_initmbxpool(&context);

    ec_slavet *sl = &context.slavelist[1];
    sl->configadr = 0x1001;
    sl->state = EC_STATE_PRE_OP;
    sl->mbxhandlerstate = ECT_MBXH_NONE;
    sl->mbx_l = 64;
    sl->mbx_wo = 0x1000;
    sl->mbx_rl = 64;
    sl->mbx_ro = 0x1100;

    fprintf(stderr, "Listening on real interface %s, calling ecx_SoEread()...\n", argv[1]);

    int psize = 64;
    static uint8_t out[128];
    memset(out, 0, sizeof(out));
    int wkc = ecx_SoEread(&context, 1, /*driveNo=*/0, /*elementflags=*/0x07, /*idn=*/1,
                           &psize, out, /*timeout=*/20000);
    fprintf(stderr, "ecx_SoEread returned wkc=%d psize=%d -- no crash\n", wkc, psize);
    ecx_closenic(&context.port);
    return 0;
}
