/**
 * @file chacha20_64b.c
 * @brief 64バイト固定 ChaCha20 実装の本体
 *
 * @copyright Copyright (c) 2026 Embedead-Inside
 * @license SPDX-License-Identifier: MIT-0
 */

#include "chacha20_64b.h"

/**
 * @brief 32ビット整数の左ローテーション
 */
static inline uint32_t rotl32(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

/**
 * @brief リトルエンディアンのバイト列から32ビットワードを安全に読み込む
 */
static inline uint32_t load32_le(const uint8_t *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

/**
 * @brief クォーターラウンド（四半ラウンド）マクロ
 * 
 * 4つの32ビット変数を直接インプレースで撹拌します。
 */
#define QR(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7);

/**
 * @brief 20ラウンドの完全アンロール・ラウンドマクロ
 */
#define ROUNDS \
    QR(x0, x4,  x8, x12); QR(x1, x5,  x9, x13); QR(x2, x6, x10, x14); QR(x3, x7, x11, x15); \
    QR(x0, x5, x10, x15); QR(x1, x6, x11, x12); QR(x2, x7,  x8, x13); QR(x3, x4,  x9, x14);

/**
 * @brief 暗号コンテキストの初期化（事前計算）
 * 
 * キーとナンスから、ブロック変換で共通となるベース状態を生成します。
 * パケット送信ごとに毎回計算し直す無駄を省くための設計です。
 * 
 * @param ctx   初期化するコンテキスト構造体へのポインタ
 * @param key   32バイト（256ビット）の秘密鍵
 * @param nonce 12バイト（96ビット）のナンス（初期ベクトル）
 */
void chacha20_64b_init(chacha20_64b_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12])
{
    // 定数 "expand 32-byte k"
    ctx->state[0]  = 0x61707865;
    ctx->state[1]  = 0x3320646e;
    ctx->state[2]  = 0x79622d32;
    ctx->state[3]  = 0x6b206574;

    // 秘密鍵 (32バイト = 8ワード)
    for (int i = 0; i < 8; i++) {
        ctx->state[4 + i] = load32_le(key + i * 4);
    }

    // カウンターのプレースホルダー（通常は変換時に上書きされるため0）
    ctx->state[12] = 0;

    // ナンス (12バイト = 3ワード)
    ctx->state[13] = load32_le(nonce + 0);
    ctx->state[14] = load32_le(nonce + 4);
    ctx->state[15] = load32_le(nonce + 8);
}

/**
 * @brief 64バイトデータのインプレース暗号化・復号
 * 
 * バッファ（64バイト固定）をその場で直接書き換えます（インプレース処理）。
 * 同じ関数を再度呼び出すことで復号（デコード）が完了します。
 * 
 * @param buf     対象の64バイトバッファ（入力および出力兼用）
 * @param ctx     初期化済みのコンテキスト構造体
 * @param counter ブロックごとのカウンター（パケット内のブロック番号: 0, 1, 2...）
 */
void chacha20_64b_transform(uint8_t buf[64], const chacha20_64b_ctx_t *ctx, uint32_t counter)
{
    // コンテキストから状態を展開し、このブロック専用のカウンターをセット
    uint32_t x0  = ctx->state[0],  x1  = ctx->state[1],  x2  = ctx->state[2],  x3  = ctx->state[3];
    uint32_t x4  = ctx->state[4],  x5  = ctx->state[5],  x6  = ctx->state[6],  x7  = ctx->state[7];
    uint32_t x8  = ctx->state[8],  x9  = ctx->state[9],  x10 = ctx->state[10], x11 = ctx->state[11];
    uint32_t x12 = counter;         // カウンター
    uint32_t x13 = ctx->state[13], x14 = ctx->state[14], x15 = ctx->state[15];

    // 加算用の初期値（バックアップ）
    uint32_t b0 = x0, b1 = x1, b2 = x2,   b3 = x3;
    uint32_t b4 = x4, b5 = x5, b6 = x6,   b7 = x7;
    uint32_t b8 = x8, b9 = x9, b10 = x10, b11 = x11;
    uint32_t b12 = x12, b13 = x13, b14 = x14, b15 = x15;

    // 20ラウンド（10回のダブルラウンドを完全アンロール）
    ROUNDS ROUNDS ROUNDS ROUNDS ROUNDS ROUNDS ROUNDS ROUNDS ROUNDS ROUNDS

    // 初期状態を加算してキーストリームを確定
    x0 += b0; x1 += b1; x2 += b2;   x3 += b3;
    x4 += b4; x5 += b5; x6 += b6;   x7 += b7;
    x8 += b8; x9 += b9; x10 += b10; x11 += b11;
    x12 += b12; x13 += b13; x14 += b14; x15 += b15;

    // バッファ上のデータとキーストリームをその場で直接XOR（インプレース処理）
    uint32_t *d = (uint32_t *)buf;
    d[0]  ^= x0;  d[1]  ^= x1;  d[2]  ^= x2;  d[3]  ^= x3;
    d[4]  ^= x4;  d[5]  ^= x5;  d[6]  ^= x6;  d[7]  ^= x7;
    d[8]  ^= x8;  d[9]  ^= x9;  d[10] ^= x10; d[11] ^= x11;
    d[12] ^= x12; d[13] ^= x13; d[14] ^= x14; d[15] ^= x15;
}
