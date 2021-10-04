//
// Created by athena on 10/3/2021.
//

#if STONESOUP_SNIPPET_DEBUG || \
 (!STONESOUP_SNIPPET_INCLUDES && \
!STONESOUP_SNIPPET_SUPPORT && \
 !STONESOUP_SNIPPET_BODY_STATEMENTS && \
 !STONESOUP_SNIPPET_BODY_DECLARATIONS)
/* Default to debug mode if nothing requested */
#define STONESOUP_SNIPPET_DEBUG 1
#undef STONESOUP_SNIPPET_INCLUDES
#define STONESOUP_SNIPPET_INCLUDES 1
#undef STONESOUP_SNIPPET_SUPPORT
#define STONESOUP_SNIPPET_SUPPORT 1
#undef STONESOUP_SNIPPET_BODY_STATEMENTS
#define STONESOUP_SNIPPET_BODY_STATEMENTS 1
#undef STONESOUP_SNIPPET_BODY_DECLARATIONS
#define STONESOUP_SNIPPET_BODY_DECLARATIONS 1
#endif /* NOTHING DEFINED */
#if STONESOUP_SNIPPET_INCLUDES
/*****************************************************************************
 * Weakness Snippet Dependencies
 *
 * This section should #include any headers for required functions, types,
 * macros, etc. in either the weakness or the supporting functions.
 *****************************************************************************/
#include <stdio.h> /* printf */
#include <stdlib.h> /* malloc */
#include <string.h> /* memset */
/*
* Include tracepoint events.
*/
#if STONESOUP_TRACE
#if STONESOUP_SNIPPET_DEBUG
#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#endif /* STONESOUP_SNIPPET_DEBUG */
#include <stonesoup/stonesoup_trace.h>
#endif /* STONESOUP_TRACE */
#endif /* STONESOUP_SNIPPET_INCLUDES */
#if STONESOUP_SNIPPET_SUPPORT
#if STONESOUP_SNIPPET_DEBUG
/*****************************************************************************
 * Weakness Snippet Support Functions
 *
 * This section should include any additional methods to support the defined
 * weakness snippet in the weakness() function. If any functions should
 * not appear in the injected base program, simply wrap them in the
 * STONESOUP_SNIPPET_DEBUG macro, and they will be stripped by the pre-
 * processor.
 *****************************************************************************/
#include "output-handlers/handler.h"
#endif /* STONESOUP_SNIPPET_DEBUG */
int stonesoup_toupper(int c) {
    if (c >= 97 && c <= 122) {
        return c - 32;
    }
    return c;
}
#endif /* STONESOUP_SNIPPET_SUPPORT */
#if STONESOUP_SNIPPET_BODY_STATEMENTS || STONESOUP_SNIPPET_BODY_DECLARATIONS
#if STONESOUP_SNIPPET_DEBUG
/*****************************************************************************
 * Weakness Snippet
 *
 * This section should include the weakness snippet which will be sourced in
 * to the injection point after all code complexities have been applied. The
 * taint source is mapped to the weakness snippet using the macro:
 * STONESOUP_TAINT_SOURCE. In debug mode, the function declaration is also
 * included.
 *****************************************************************************/
void weakness(char * stonesoup_tainted_buff) {
#define STONESOUP_TAINT_SOURCE stonesoup_tainted_buff
#endif /* STONESOUP_SNIPPET_DEBUG */
#if STONESOUP_SNIPPET_BODY_DECLARATIONS
    int stonesoup_oc_i = 0;
    char stonesoup_stack_buffer_64[64];
#endif /* STONESOUP_SNIPPET_BODY_DECLARATIONS */
#if STONESOUP_SNIPPET_BODY_STATEMENTS
#if STONESOUP_TRACE
    tracepoint(stonesoup_trace, weakness_start, "CWE120", "A", "Buffer Copy without
Checking Size of Input");
#endif /* STONESOUP_TRACE */
    memset(stonesoup_stack_buffer_64,0,64);
#if STONESOUP_TRACE
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_oc_i",
stonesoup_oc_i, &stonesoup_oc_i, "INITIAL-STATE");
 tracepoint(stonesoup_trace, variable_buffer, "stonesoup_stack_buffer_64",
stonesoup_stack_buffer_64, "INITIAL-STATE");
 tracepoint(stonesoup_trace, variable_address, "__builtin_return_address(0)",
__builtin_return_address(0), "INITIAL-STATE");
 tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
#endif /* STONESOUP_TRACE */

    /* STONESOUP: CROSSOVER-POINT (Unchecked buffer copy) */
    strcpy(stonesoup_stack_buffer_64,STONESOUP_TAINT_SOURCE);
#if STONESOUP_TRACE
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_stack_buffer_64",
stonesoup_stack_buffer_64, "CROSSOVER-STATE");
 tracepoint(stonesoup_trace, variable_address, "__builtin_return_address(0)",
__builtin_return_address(0), "CROSSOVER-STATE");
 tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
#endif /* STONESOUP_TRACE */

    for (; stonesoup_oc_i < 64; ++stonesoup_oc_i) {
        stonesoup_stack_buffer_64[stonesoup_oc_i] =
                stonesoup_toupper(stonesoup_stack_buffer_64[stonesoup_oc_i]);
    }

#if STONESOUP_TRACE
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_oc_i",
stonesoup_oc_i, &stonesoup_oc_i, "FINAL-STATE");
 tracepoint(stonesoup_trace, variable_buffer, "stonesoup_stack_buffer_64",
stonesoup_stack_buffer_64, "FINAL-STATE");
#endif /* STONESOUP_TRACE */

    stonesoup_printf("%s\n",stonesoup_stack_buffer_64);
#if STONESOUP_TRACE
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
 tracepoint(stonesoup_trace, weakness_end);
#endif /* STONESOUP_TRACE */
    /* STONESOUP: TRIGGER-POINT (Buffer Overflow: Unchecked stack buffer copy) */
    /* Trigger point occurs on function return. */
#endif /* STONESOUP_SNIPPET_BODY_STATEMENTS */
#if STONESOUP_SNIPPET_DEBUG
}
#endif /* STONESOUP_SNIPPET_DEBUG */
#endif /* STONESOUP_SNIPPET_BODY_STATEMENTS || STONESOUP_SNIPPET_BODY_DECLARATIONS */
#if STONESOUP_SNIPPET_DEBUG
/*****************************************************************************
 * Main
 *
 * This only exists to support direct debugging.
 *****************************************************************************/
int main(int argc,char *argv[])
{
    if (argc < 2) {
        printf("Error: requires a single command-line argument\n");
        exit(1);
    }
    char* tainted_buff = argv[1];

    if (tainted_buff != NULL) {
        stonesoup_setup_printf_context();
        weakness(tainted_buff);
        stonesoup_close_printf_context();
    }
    return 0;
}
