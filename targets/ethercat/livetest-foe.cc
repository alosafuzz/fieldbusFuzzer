// Live, two-process reproduction for finding 06 (ecx_FOEread segmentdata unsigned-underflow OOB
// read). Real ecx_setupnic() against a veth pair, paired with tools-live-slave.py acting as the
// malicious/corrupted slave over the real wire. See livetest-coe.cc (finding 03) for the base
// pattern this follows. Built against src-patched, consistent with every other live test on this
// target; finding 06 itself is NOT patched there.
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
    sl->mbx_l = 512;
    sl->mbx_wo = 0x1000;
    sl->mbx_rl = 512;
    sl->mbx_ro = 0x1100;

    fprintf(stderr, "Listening on real interface %s, calling ecx_FOEread()...\n", argv[1]);

    // Deliberately LARGE psize -- see harness-foe.cc's header comment for why (a realistic FoE
    // caller legitimately allocates a big firmware/file-transfer buffer).
    int psize = 70000;
    static uint8_t out[70000];
    memset(out, 0, sizeof(out));
    char filename[] = "test.bin";
    int wkc = ecx_FOEread(&context, 1, filename, /*password=*/0, &psize, out, /*timeout=*/20000);
    fprintf(stderr, "ecx_FOEread returned wkc=%d psize=%d -- no crash\n", wkc, psize);
    ecx_closenic(&context.port);
    return 0;
}
