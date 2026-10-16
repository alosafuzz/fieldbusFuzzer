// Live, two-process reproduction for finding 04 (ecx_mbxreceive NULL-retry write). Real
// ecx_setupnic() against a veth pair, calling ecx_mbxreceive() directly (not via ecx_SoEread) to
// isolate this finding to its true minimal scope, same reasoning as prodtest-mbxreceive.cc.
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

    fprintf(stderr, "Listening on real interface %s, calling ecx_mbxreceive()...\n", argv[1]);

    ec_mbxbuft *mbx = nullptr;
    int wkc = ecx_mbxreceive(&context, 1, &mbx, 2000000);
    fprintf(stderr, "ecx_mbxreceive returned wkc=%d mbx=%p -- no crash\n", wkc, (void *)mbx);
    ecx_closenic(&context.port);
    return 0;
}
