/*
 * Custom minimal command table for the libscpi fuzz harness.
 *
 * Replaces examples/common/scpi-def.c. Purpose: drive fuzz input INTO the
 * libscpi parameter readers and the expression module that the stock demo
 * never calls (llvm-cov showed parser.c ~43% / expression.c ~43% functions
 * with the demo), using CORRECTLY-SIZED buffers so there are no scaffolding
 * bugs of the demo's kind (no uninitialized structs, no length/array mismatch).
 *
 * Provides the same global symbols scpi-def.c did (scpi_commands,
 * scpi_interface, scpi_input_buffer, scpi_error_queue_data, scpi_context), so
 * harness.c + scpi-def.h are unchanged. The 5 interface callbacks remain in
 * harness.c.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "scpi/scpi.h"
#include "scpi-def.h"

static const scpi_choice_def_t fuzz_choices[] = {
    {"IMMediate", 1}, {"EXTernal", 2}, {"BUS", 3}, {"INTernal", 4},
    SCPI_CHOICE_LIST_END
};

/* scalar numeric readers: Int32/UInt32/Int64/UInt64/Float/Double */
static scpi_result_t Fuzz_Num(scpi_t * context) {
    int32_t i32; uint32_t u32; int64_t i64; uint64_t u64; float f; double d;
    if (SCPI_ParamInt32(context, &i32, FALSE))  SCPI_ResultInt32(context, i32);
    if (SCPI_ParamUInt32(context, &u32, FALSE)) SCPI_ResultUInt32(context, u32);
    if (SCPI_ParamInt64(context, &i64, FALSE))  SCPI_ResultInt64(context, i64);
    if (SCPI_ParamUInt64(context, &u64, FALSE)) SCPI_ResultUInt64(context, u64);
    if (SCPI_ParamFloat(context, &f, FALSE))    SCPI_ResultFloat(context, f);
    if (SCPI_ParamDouble(context, &d, FALSE))   SCPI_ResultDouble(context, d);
    return SCPI_RES_OK;
}

/* SCPI number with units + special values (MIN/MAX/DEF), then format it back */
static scpi_result_t Fuzz_Number(scpi_t * context) {
    scpi_number_t num;
    char bf[64];
    memset(&num, 0, sizeof(num));
    if (SCPI_ParamNumber(context, scpi_special_numbers_def, &num, FALSE)) {
        SCPI_NumberToStr(context, scpi_special_numbers_def, &num, bf, sizeof(bf));
        SCPI_ResultText(context, bf);
    }
    return SCPI_RES_OK;
}

/* string / text / characters / bool / choice */
static scpi_result_t Fuzz_Str(scpi_t * context) {
    const char * s; size_t len;
    char copy[64]; size_t cl;
    scpi_bool_t b; int32_t choice;
    if (SCPI_ParamCharacters(context, &s, &len, FALSE)) SCPI_ResultCharacters(context, s, len);
    if (SCPI_ParamCopyText(context, copy, sizeof(copy), &cl, FALSE)) SCPI_ResultText(context, copy);
    if (SCPI_ParamBool(context, &b, FALSE)) SCPI_ResultBool(context, b);
    if (SCPI_ParamChoice(context, fuzz_choices, &choice, FALSE)) SCPI_ResultInt32(context, choice);
    return SCPI_RES_OK;
}

/* arbitrary block data: #<ndigits><len><bytes> (the length-lie surface) */
static scpi_result_t Fuzz_Block(scpi_t * context) {
    const char * data; size_t len;
    if (SCPI_ParamArbitraryBlock(context, &data, &len, FALSE)) {
        SCPI_ResultArbitraryBlock(context, data, len);
    }
    return SCPI_RES_OK;
}

/* numeric arrays (ASCII + binary block formats), correctly-sized buffer */
static scpi_result_t Fuzz_ArrInt(scpi_t * context) {
    int32_t arr[16]; size_t o = 0;
    if (SCPI_ParamArrayInt32(context, arr, 16, &o, SCPI_FORMAT_ASCII, FALSE))
        SCPI_ResultArrayInt32(context, arr, o, SCPI_FORMAT_ASCII);
    return SCPI_RES_OK;
}
static scpi_result_t Fuzz_ArrDbl(scpi_t * context) {
    double arr[16]; size_t o = 0;
    if (SCPI_ParamArrayDouble(context, arr, 16, &o, SCPI_FORMAT_ASCII, FALSE))
        SCPI_ResultArrayDouble(context, arr, o, SCPI_FORMAT_ASCII);
    return SCPI_RES_OK;
}
/* binary-format arrays: #<n><len><raw bytes> parsed as binary + endianness-swapped
   (SCPI_FORMAT_NORMAL) — the binary-block array input path + SCPI_Swap16/32/64 */
static scpi_result_t Fuzz_ArrBinI(scpi_t * context) {
    int32_t arr[16]; size_t o = 0;
    if (SCPI_ParamArrayInt32(context, arr, 16, &o, SCPI_FORMAT_NORMAL, FALSE))
        SCPI_ResultArrayInt32(context, arr, o, SCPI_FORMAT_NORMAL);
    return SCPI_RES_OK;
}
static scpi_result_t Fuzz_ArrBinD(scpi_t * context) {
    double arr[16]; size_t o = 0;
    if (SCPI_ParamArrayDouble(context, arr, 16, &o, SCPI_FORMAT_NORMAL, FALSE))
        SCPI_ResultArrayDouble(context, arr, o, SCPI_FORMAT_NORMAL);
    return SCPI_RES_OK;
}

/* numeric-list expression: (1,2:50,80) */
static scpi_result_t Fuzz_NList(scpi_t * context) {
    scpi_parameter_t param;
    if (!SCPI_Parameter(context, &param, TRUE)) return SCPI_RES_ERR;
    int i;
    for (i = 0; i < 64; i++) {
        scpi_bool_t isRange; int32_t from, to;
        scpi_expr_result_t r = SCPI_ExprNumericListEntryInt(context, &param, i, &isRange, &from, &to);
        if (r != SCPI_EXPR_OK) break;
    }
    return SCPI_RES_OK;
}

/* channel-list expression: (@1!2:3!4,5!6) with CORRECTLY-SIZED arrays (length==capacity) */
static scpi_result_t Fuzz_CList(scpi_t * context) {
    scpi_parameter_t param;
    if (!SCPI_Parameter(context, &param, TRUE)) return SCPI_RES_ERR;
    int i;
    for (i = 0; i < 64; i++) {
        scpi_bool_t isRange; int32_t from[8], to[8]; size_t dims;
        scpi_expr_result_t r =
            SCPI_ExprChannelListEntry(context, &param, i, &isRange, from, to, 8, &dims);
        if (r != SCPI_EXPR_OK) break;
    }
    return SCPI_RES_OK;
}

const scpi_command_t scpi_commands[] = {
    /* IEEE 488.2 mandated */
    {.pattern = "*CLS",  .callback = SCPI_CoreCls,},
    {.pattern = "*ESE",  .callback = SCPI_CoreEse,},
    {.pattern = "*ESE?", .callback = SCPI_CoreEseQ,},
    {.pattern = "*ESR?", .callback = SCPI_CoreEsrQ,},
    {.pattern = "*IDN?", .callback = SCPI_CoreIdnQ,},
    {.pattern = "*OPC",  .callback = SCPI_CoreOpc,},
    {.pattern = "*OPC?", .callback = SCPI_CoreOpcQ,},
    {.pattern = "*RST",  .callback = SCPI_CoreRst,},
    {.pattern = "*SRE",  .callback = SCPI_CoreSre,},
    {.pattern = "*SRE?", .callback = SCPI_CoreSreQ,},
    {.pattern = "*STB?", .callback = SCPI_CoreStbQ,},
    {.pattern = "*TST?", .callback = SCPI_CoreTstQ,},
    {.pattern = "*WAI",  .callback = SCPI_CoreWai,},
    /* required error/status */
    {.pattern = "SYSTem:ERRor[:NEXT]?", .callback = SCPI_SystemErrorNextQ,},
    {.pattern = "SYSTem:ERRor:COUNt?",  .callback = SCPI_SystemErrorCountQ,},
    {.pattern = "SYSTem:VERSion?",      .callback = SCPI_SystemVersionQ,},
    {.pattern = "STATus:QUEStionable[:EVENt]?", .callback = SCPI_StatusQuestionableEventQ,},
    {.pattern = "STATus:QUEStionable:ENABle",   .callback = SCPI_StatusQuestionableEnable,},
    {.pattern = "STATus:QUEStionable:ENABle?",  .callback = SCPI_StatusQuestionableEnableQ,},
    {.pattern = "STATus:PRESet",                .callback = SCPI_StatusPreset,},
    /* fuzz surfaces (correctly-buffered) */
    {.pattern = "FUZZ:NUM?",      .callback = Fuzz_Num,},
    {.pattern = "FUZZ:NUMBer?",   .callback = Fuzz_Number,},
    {.pattern = "FUZZ:STRing?",   .callback = Fuzz_Str,},
    {.pattern = "FUZZ:BLOCk?",    .callback = Fuzz_Block,},
    {.pattern = "FUZZ:ARRay:INT?",    .callback = Fuzz_ArrInt,},
    {.pattern = "FUZZ:ARRay:DBL?",    .callback = Fuzz_ArrDbl,},
    {.pattern = "FUZZ:ARRay:IBINary?", .callback = Fuzz_ArrBinI,},
    {.pattern = "FUZZ:ARRay:DBINary?", .callback = Fuzz_ArrBinD,},
    {.pattern = "FUZZ:NLISt?",    .callback = Fuzz_NList,},
    {.pattern = "FUZZ:CLISt?",    .callback = Fuzz_CList,},
    SCPI_CMD_LIST_END
};

scpi_interface_t scpi_interface = {
    .error   = SCPI_Error,
    .write   = SCPI_Write,
    .control = SCPI_Control,
    .flush   = SCPI_Flush,
    .reset   = SCPI_Reset,
};

char scpi_input_buffer[SCPI_INPUT_BUFFER_LENGTH];
scpi_error_t scpi_error_queue_data[SCPI_ERROR_QUEUE_SIZE];
scpi_t scpi_context;

