#pragma once

#include <stdint.h>
#include <stddef.h>


typedef struct {
    uint32_t state[16];
    uint8_t keystream[64];
    uint32_t block_counter;
    size_t byte_counter;
} chacha20_ctx;


void chacha20_init(chacha20_ctx *ctx, const uint8_t *key, const uint8_t *nonce);


void chacha20_crypt(chacha20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t len);

