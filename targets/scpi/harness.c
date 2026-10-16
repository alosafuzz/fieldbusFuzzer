/*
 * SCPI command-parser coverage-guided harness (fieldbusFuzzer target: scpi)
 *
 * Target: j123b567/scpi-parser (libscpi) — the instrument-side SCPI command
 * parser that sits behind every SCPI-over-LAN transport (raw-socket 5025,
 * VXI-11, HiSLIP). This drives the real byte-intake path SCPI_Input(), which
 * buffers to a terminator then dispatches through SCPI_Parse() -> the command
 * tree -> the parameter readers (SCPI_ParamArbitraryBlock / SCPI_ParamArray* /
 * the SCPI_Expr* numeric+channel-list expression module).
 *
 * The command table / interface / buffers come from examples/common/scpi-def.c
 * (a realistic ~40-command tree incl. TEST:ARBitrary? and TEST:CHANnellist, so
 * the arbitrary-block and expression surfaces are actually reachable). The five
 * I/O callbacks that scpi-def.c's interface points at are normally defined in
 * the example's main.c; we provide no-op stubs here so the harness is pure
 * buffer-in, no sockets, no stdout.
 *
 * Determinism: SCPI_Init() is re-run every iteration, fully resetting the parser
 * state machine, input buffer and error queue (libscpi is allocation-free in
 * this config, so there is no per-iteration heap state to leak).
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "scpi/scpi.h"
#include "scpi-def.h"   /* scpi_commands, scpi_interface, scpi_input_buffer,
                           scpi_error_queue_data, scpi_context, SCPI_IDN*,
                           SCPI_INPUT_BUFFER_LENGTH, SCPI_ERROR_QUEUE_SIZE */

/* ---- interface callback stubs (normally in the example's main.c) ---------- */
size_t SCPI_Write(scpi_t * context, const char * data, size_t len) {
    (void) context; (void) data; return len;
}
scpi_result_t SCPI_Flush(scpi_t * context) { (void) context; return SCPI_RES_OK; }
int SCPI_Error(scpi_t * context, int_fast16_t err) { (void) context; (void) err; return 0; }
scpi_result_t SCPI_Control(scpi_t * context, scpi_ctrl_name_t ctrl, scpi_reg_val_t val) {
    (void) context; (void) ctrl; (void) val; return SCPI_RES_OK;
}
scpi_result_t SCPI_Reset(scpi_t * context) { (void) context; return SCPI_RES_OK; }
scpi_result_t SCPI_SystemCommTcpipControlQ(scpi_t * context) { (void) context; return SCPI_RES_OK; }

/* ---- fuzz entry points ---------------------------------------------------- */
static void scpi_reset(void) {
    SCPI_Init(&scpi_context,
              scpi_commands,
              &scpi_interface,
              scpi_units_def,
              SCPI_IDN1, SCPI_IDN2, SCPI_IDN3, SCPI_IDN4,
              scpi_input_buffer, SCPI_INPUT_BUFFER_LENGTH,
              scpi_error_queue_data, SCPI_ERROR_QUEUE_SIZE);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc; (void) argv;
    scpi_reset();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Cap to INT_MAX; SCPI_Input takes an int length. */
    if (size > 0x7fffffffu) size = 0x7fffffffu;
    scpi_reset();                              /* reset parser state machine + buffer */
    SCPI_Input(&scpi_context, (const char *) data, (int) size);
    /* This build config (SYSTEM_FULL_BLOWN) strndup's device-dependent error
     * strings onto the error queue; a real instrument frees them when the queue
     * is drained. Clear it each iteration so those frees happen — otherwise the
     * next SCPI_Init() orphans them and LeakSanitizer reports a HARNESS artifact,
     * not a real libscpi leak. Clearing here keeps LSan meaningful for genuine leaks. */
    SCPI_ErrorClear(&scpi_context);
    return 0;
}
