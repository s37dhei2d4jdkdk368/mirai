#define _GNU_SOURCE

#include <stdint.h>
#include <string.h>
#include "chacha20.h"


#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}


static void chacha20_block(uint32_t *state, uint8_t *output) {
    uint32_t working_state[16];
    int i;
    
    
    for (i = 0; i < 16; i++) {
        working_state[i] = state[i];
    }
    
    
    for (i = 0; i < 10; i++) {
        
        chacha20_quarter_round(&working_state[0], &working_state[4], &working_state[8], &working_state[12]);
        chacha20_quarter_round(&working_state[1], &working_state[5], &working_state[9], &working_state[13]);
        chacha20_quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        chacha20_quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
        
        
        chacha20_quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        chacha20_quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        chacha20_quarter_round(&working_state[2], &working_state[7], &working_state[8], &working_state[13]);
        chacha20_quarter_round(&working_state[3], &working_state[4], &working_state[9], &working_state[14]);
    }
    
    
    for (i = 0; i < 16; i++) {
        working_state[i] += state[i];
    }
    
    
    for (i = 0; i < 16; i++) {
        output[i * 4 + 0] = (uint8_t)(working_state[i] >> 0);
        output[i * 4 + 1] = (uint8_t)(working_state[i] >> 8);
        output[i * 4 + 2] = (uint8_t)(working_state[i] >> 16);
        output[i * 4 + 3] = (uint8_t)(working_state[i] >> 24);
    }
}


void chacha20_init(chacha20_ctx *ctx, const uint8_t *key, const uint8_t *nonce) {
    
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    
    
    ctx->state[4] = ((uint32_t)key[0]) | ((uint32_t)key[1] << 8) | ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24);
    ctx->state[5] = ((uint32_t)key[4]) | ((uint32_t)key[5] << 8) | ((uint32_t)key[6] << 16) | ((uint32_t)key[7] << 24);
    ctx->state[6] = ((uint32_t)key[8]) | ((uint32_t)key[9] << 8) | ((uint32_t)key[10] << 16) | ((uint32_t)key[11] << 24);
    ctx->state[7] = ((uint32_t)key[12]) | ((uint32_t)key[13] << 8) | ((uint32_t)key[14] << 16) | ((uint32_t)key[15] << 24);
    ctx->state[8] = ((uint32_t)key[16]) | ((uint32_t)key[17] << 8) | ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24);
    ctx->state[9] = ((uint32_t)key[20]) | ((uint32_t)key[21] << 8) | ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24);
    ctx->state[10] = ((uint32_t)key[24]) | ((uint32_t)key[25] << 8) | ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24);
    ctx->state[11] = ((uint32_t)key[28]) | ((uint32_t)key[29] << 8) | ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24);
    
    
    ctx->state[12] = 0;
    
    
    ctx->state[13] = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) | ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    ctx->state[14] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) | ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    ctx->state[15] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9] << 8) | ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24);
    
    ctx->block_counter = 0;
    ctx->byte_counter = 64;  
    memset(ctx->keystream, 0, 64);
}


void chacha20_crypt(chacha20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t len) {
    size_t i;
    
    for (i = 0; i < len; i++) {
        
        if (ctx->byte_counter >= 64) {
            ctx->state[12] = ctx->block_counter;
            chacha20_block(ctx->state, ctx->keystream);
            ctx->block_counter++;
            ctx->byte_counter = 0;
        }
        
        
        output[i] = input[i] ^ ctx->keystream[ctx->byte_counter];
        ctx->byte_counter++;
    }
}

