// Cheap empirical test of slave-index boundary handling (TARGET.md's multi-slave/address-boundary
// coverage-expansion item). Not a fuzzing harness -- ecx_mbxsend()/ecx_mbxreceive() take `slave`
// (uint16, 0-65535) as a raw parameter and index `context->slavelist[slave]` with zero internal
// bounds check against EC_MAXSLAVE (200). The one genuinely wire-derived boundary (slavecount,
// from ecx_detect_slaves()'s broadcast WKC) is already safely clamped in ec_config.c -- this test
// checks the OTHER angle: what happens if a raw out-of-range slave index reaches these functions
// directly, regardless of how it got there. `context->slavelist` is not the last member of
// ecx_contextt (slavecount, grouplist[EC_MAXGROUP], and more follow it), so a moderately
// out-of-range index should land outside the whole context object into unrelated memory.
#include <cstdio>
#include <cstring>

extern "C" {
#include "soem/soem.h"
#include "nicdrv.h"
}

int try_slave(ecx_contextt *context, uint16_t slave, const char *label) {
    fprintf(stderr, "--- slave=%u (%s) ---\n", slave, label);
    ec_mbxbuft *mbx = nullptr;
    int wkc = ecx_mbxreceive(context, slave, &mbx, /*timeout=*/0);
    fprintf(stderr, "ecx_mbxreceive(slave=%u) returned wkc=%d -- no crash\n", slave, wkc);
    return wkc;
}

int main() {
    ecx_contextt context;
    memset(&context, 0, sizeof(context));

    ecx_portt *port = &context.port;
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(&port->getindex_mutex, &mutexattr);
    pthread_mutex_init(&port->tx_mutex, &mutexattr);
    pthread_mutex_init(&port->rx_mutex, &mutexattr);

    ecx_initmbxpool(&context);

    // Sanity baseline: a real, in-range slave index should behave normally (return quickly, no
    // response queued, wkc<=0 is expected -- not testing real traffic here, just bounds safety).
    try_slave(&context, 1, "in-range sanity check");
    try_slave(&context, 199, "EC_MAXSLAVE-1, last valid index");

    // The actual boundary test.
    try_slave(&context, 200, "EC_MAXSLAVE, first invalid index");
    try_slave(&context, 65535, "uint16 max");

    fprintf(stderr, "All calls completed without a crash.\n");
    return 0;
}
