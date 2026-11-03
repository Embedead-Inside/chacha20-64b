/**
 * @file chacha20_64b.h
 * @brief 64バイト固定 ChaCha20 (RFC 8439) のAPI宣言
 *
 * @copyright Copyright (c) 2026 Embedead-Inside
 * @license SPDX-License-Identifier: MIT-0
 *
 * @par ビルドオプション
 *  - 既定: ダブルラウンドを完全アンロール（速度優先・コードサイズ大）
 *  - -DCHACHA20_64B_COMPACT: ダブルラウンドをループ化（サイズ優先）
 *  どちらが速い/小さいかはターゲットと最適化レベルで変わるため、実測して選択してください。
 *
 * @warning (key, nonce) の組を絶対に再利用しないでください。
 *          同じ組で別のデータを暗号化すると、平文同士のXORが漏洩します。
 * @warning ChaCha20 単体は認証を行いません（改ざん検知不可）。
 *          必要なら Poly1305 等のMACと組み合わせてください。
 * @warning 本実装は第三者による監査を受けていません。
 */
#ifndef CHACHA20_64B_H
#define CHACHA20_64B_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** ブロック変換で共通となるベース状態（鍵素材を含む） */
typedef struct {
    uint32_t state[16]; /**< state[12] は未使用（変換時にカウンタで置換） */
} chacha20_64b_ctx_t;

/**
 * @brief キーとナンスからコンテキストを初期化する
 * @param ctx   初期化対象
 * @param key   32バイトの秘密鍵
 * @param nonce 12バイトのナンス（(key, nonce) 再利用禁止）
 */
void chacha20_64b_init(chacha20_64b_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12]);

/**
 * @brief 64バイトバッファをその場で暗号化/復号する
 *
 * RFC 8439 に準拠（リトルエンディアン固定、バッファのアラインメント不問）。
 * 暗号化と復号は同一の呼び出しです。
 *
 * @param buf     64バイトのバッファ（入出力兼用）
 * @param ctx     初期化済みコンテキスト
 * @param counter 32ビットブロックカウンタ。2^32ブロック（256GiB）で折り返すため、
 *                同一 (key, nonce) で折り返すほど処理しないこと。
 */
void chacha20_64b_transform(uint8_t buf[64], const chacha20_64b_ctx_t *ctx, uint32_t counter);

/**
 * @brief コンテキスト内の鍵素材をゼロクリアする（最適化で消されない）
 *
 * 注意: transform 内のレジスタ/スタック上の一時値まではクリアできません。
 */
void chacha20_64b_wipe(chacha20_64b_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_64B_H */
