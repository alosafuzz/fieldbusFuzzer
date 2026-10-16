// Live, two-process reproduction for finding 03 (ecx_SDOread negative-SDOlen OOB write). Real
// ecx_setupnic() against a veth pair, paired with live_slave.py acting as the malicious/corrupted
// slave over the real wire. See livetest-inframe.cc (findings 01/02) for the base pattern this
// follows.
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

    fprintf(stderr, "Listening on real interface %s, calling ecx_SDOread()...\n", argv[1]);

    int psize = 128;
    static uint8_t out[4096];
    memset(out, 0, sizeof(out));
    int wkc = ecx_SDOread(&context, 1, 0x6000, 0, FALSE, &psize, out, 20000);
    fprintf(stderr, "ecx_SDOread returned wkc=%d psize=%d -- no crash\n", wkc, psize);
    ecx_closenic(&context.port);
    return 0;
}
