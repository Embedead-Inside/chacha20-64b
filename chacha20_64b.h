/**
 * @file chacha20_64b.h
 * @brief ベアメタル・組込み環境向け 64バイト固定 ChaCha20 暗号化/復号ライブラリ
 *
 * @copyright Copyright (c) 2026 Embedead-Inside
 * @license SPDX-License-Identifier: MIT-0
 */

#ifndef CHACHA20_64B_H
#define CHACHA20_64B_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ChaCha20のベース状態（事前計算用）
 */
typedef struct {
    uint32_t state[16];
} chacha20_64b_ctx_t;

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
void chacha20_64b_init(chacha20_64b_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12]);

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
void chacha20_64b_transform(uint8_t buf[64], const chacha20_64b_ctx_t *ctx, uint32_t counter);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_64B_H */
