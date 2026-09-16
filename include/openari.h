/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ncdents, LLC.
 * Experimental ABI 1. UTF-8 JSON output has no trailing NUL.
 * A function success is NOT a trusted-image decision. Read the JSON decision.
 * Query the required size with output=NULL and capacity=0, then supply storage.
 * Buffers and required must be valid, disjoint, and unchanged by other threads.
 * Null input is permitted only when input_len=0. required must never be NULL.
 * All memory is caller-owned. The library retains no pointers and performs no I/O.
 */
#ifndef OPENARI_H
#define OPENARI_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OPENARI_OK 0
#define OPENARI_BUFFER_TOO_SMALL 1
#define OPENARI_INVALID_ARGUMENT 2
#define OPENARI_RESOURCE_LIMIT 3
#define OPENARI_INTERNAL_ERROR 4
uint32_t openari_abi_version(void);
int32_t openari_verify_json_v1(const uint8_t *input, size_t input_len,
    uint8_t *output, size_t output_capacity, size_t *required);
#ifdef __cplusplus
}
#endif
#endif
