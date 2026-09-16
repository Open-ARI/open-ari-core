/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ncdents, LLC. */
#include "openari.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    const uint8_t input[] = {0xff, 0xd8, 0xff};
    size_t required = 0;
    assert(openari_abi_version() == 1);
    assert(openari_verify_json_v1(input, sizeof(input), NULL, 0, &required) == OPENARI_BUFFER_TOO_SMALL);
    uint8_t *buffer = malloc(required + 1);
    assert(buffer != NULL);
    assert(openari_verify_json_v1(input, sizeof(input), buffer, required, &required) == OPENARI_OK);
    buffer[required] = 0;
    assert(strstr((char *)buffer, "\"decision\":\"indeterminate\"") != NULL);
    free(buffer);
    return 0;
}
