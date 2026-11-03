/**
 * @file chacha20_64b.c
 * @brief 64バイト固定 ChaCha20 実装の本体
 *
 * @copyright Copyright (c) 2026 Embedead-Inside
 * @license SPDX-License-Identifier: MIT-0
 */

#include "chacha20_64b.h"

/** 32ビット整数の左ローテーション（c は 1..31 の定数で使用） */
static inline uint32_t rotl32(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

/** リトルエンディアンのバイト列から32ビットワードを読み込む（アラインメント・エンディアン非依存） */
static inline uint32_t load32_le(const uint8_t *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

/** 32ビットワードをリトルエンディアンでバッファへXOR（アラインメント・エンディアン非依存） */
static inline void xor32_le(uint8_t *p, uint32_t x) {
    p[0] ^= (uint8_t)x;
    p[1] ^= (uint8_t)(x >> 8);
    p[2] ^= (uint8_t)(x >> 16);
    p[3] ^= (uint8_t)(x >> 24);
}

/** クォーターラウンド（4つの32ビット変数をインプレースで撹拌） */
#define QR(a, b, c, d)                      \
    do {                                    \
        a += b; d ^= a; d = rotl32(d, 16);  \
        c += d; b ^= c; b = rotl32(b, 12);  \
        a += b; d ^= a; d = rotl32(d, 8);   \
        c += d; b ^= c; b = rotl32(b, 7);   \
    } while (0)

/** 1ダブルラウンド（= 列ラウンド + 対角ラウンド、計2ラウンド） */
#define DOUBLE_ROUND                                                           \
    do {                                                                       \
        QR(x0, x4, x8,  x12); QR(x1, x5, x9,  x13);                            \
        QR(x2, x6, x10, x14); QR(x3, x7, x11, x15);                            \
        QR(x0, x5, x10, x15); QR(x1, x6, x11, x12);                            \
        QR(x2, x7, x8,  x13); QR(x3, x4, x9,  x14);                            \
    } while (0)

void chacha20_64b_init(chacha20_64b_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12])
{
    /* 定数 "expand 32-byte k" */
    ctx->state[0] = 0x61707865u;
    ctx->state[1] = 0x3320646eu;
    ctx->state[2] = 0x79622d32u;
    ctx->state[3] = 0x6b206574u;

    for (int i = 0; i < 8; i++) {
        ctx->state[4 + i] = load32_le(key + i * 4);
    }

    ctx->state[12] = 0; /* プレースホルダー（transform で counter に置換） */

    ctx->state[13] = load32_le(nonce + 0);
    ctx->state[14] = load32_le(nonce + 4);
    ctx->state[15] = load32_le(nonce + 8);
}

void chacha20_64b_transform(uint8_t buf[64], const chacha20_64b_ctx_t *ctx, uint32_t counter)
{
    uint32_t x0  = ctx->state[0],  x1  = ctx->state[1],  x2  = ctx->state[2],  x3  = ctx->state[3];
    uint32_t x4  = ctx->state[4],  x5  = ctx->state[5],  x6  = ctx->state[6],  x7  = ctx->state[7];
    uint32_t x8  = ctx->state[8],  x9  = ctx->state[9],  x10 = ctx->state[10], x11 = ctx->state[11];
    uint32_t x12 = counter,        x13 = ctx->state[13], x14 = ctx->state[14], x15 = ctx->state[15];

    /* 20ラウンド = 10ダブルラウンド。
     * 最終加算用の初期値は ctx から再読込できるため、バックアップ用の16変数は持たない
     * （レジスタ圧の低減とスタック使用量の削減が目的）。 */
#ifdef CHACHA20_64B_COMPACT
    for (int i = 0; i < 10; i++) {
        DOUBLE_ROUND;
    }
#else
    DOUBLE_ROUND; DOUBLE_ROUND; DOUBLE_ROUND; DOUBLE_ROUND; DOUBLE_ROUND;
    DOUBLE_ROUND; DOUBLE_ROUND; DOUBLE_ROUND; DOUBLE_ROUND; DOUBLE_ROUND;
#endif

    /* 初期状態を加算してキーストリームを確定し、バッファへLE順でXOR */
    xor32_le(buf +  0, x0  + ctx->state[0]);
    xor32_le(buf +  4, x1  + ctx->state[1]);
    xor32_le(buf +  8, x2  + ctx->state[2]);
    xor32_le(buf + 12, x3  + ctx->state[3]);
    xor32_le(buf + 16, x4  + ctx->state[4]);
    xor32_le(buf + 20, x5  + ctx->state[5]);
    xor32_le(buf + 24, x6  + ctx->state[6]);
    xor32_le(buf + 28, x7  + ctx->state[7]);
    xor32_le(buf + 32, x8  + ctx->state[8]);
    xor32_le(buf + 36, x9  + ctx->state[9]);
    xor32_le(buf + 40, x10 + ctx->state[10]);
    xor32_le(buf + 44, x11 + ctx->state[11]);
    xor32_le(buf + 48, x12 + counter);
    xor32_le(buf + 52, x13 + ctx->state[13]);
    xor32_le(buf + 56, x14 + ctx->state[14]);
    xor32_le(buf + 60, x15 + ctx->state[15]);
}

void chacha20_64b_wipe(chacha20_64b_ctx_t *ctx)
{
    volatile uint32_t *p = ctx->state;
    for (int i = 0; i < 16; i++) {
        p[i] = 0;
    }
}
