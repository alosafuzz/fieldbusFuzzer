/* The libscpi test-tcp example doesn't ignore SIGPIPE, so a client that closes
 * before the server writes a query reply kills the server (harness artifact, not
 * a libscpi bug). Real SCPI servers ignore SIGPIPE; do the same for the wire target. */
#include <signal.h>
__attribute__((constructor)) static void ignore_sigpipe(void) { signal(SIGPIPE, SIG_IGN); }
