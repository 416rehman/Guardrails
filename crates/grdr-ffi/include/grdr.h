// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#ifndef GRDR_H
#define GRDR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Evaluate either a direct FfiEvalRequest JSON payload (explicit non-empty "packs" array required)
 * or a stateless command envelope with "op" in:
 *   "eval" | "compile_fastpath" | "assess_host" | "interest" | "brand_manifest"
 * Returned UTF-8 C string must be freed with grdr_ffi_free_string().
 */
char* grdr_ffi_eval_json(const uint8_t* input_ptr, size_t input_len);

/*
 * Explicit opt-in accessor returning the signed embedded Essentials PolicyPack JSON.
 * Free the returned pointer with grdr_ffi_free_string().
 */
char* grdr_ffi_essentials_pack_json(void);

/*
 * Free a non-null pointer allocated by grdr_ffi_eval_json or grdr_ffi_essentials_pack_json.
 */
void grdr_ffi_free_string(char* ptr);

#ifdef __cplusplus
}
#endif

#endif
