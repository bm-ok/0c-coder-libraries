/*
 * okpqc.h — OnlyKey post-quantum PGP keys (composite ML-KEM-768 + ML-DSA-65).
 *
 * One RSA slot (1-4) holds one imported composite PQC PGP key as a 160-byte seed blob:
 *   [0:32]  Ed25519 secret   (sign, ecc half)
 *   [32:64] ML-DSA-65 seed    (sign, pqc half)      FIPS 204 32-byte seed
 *   [64:96] X25519 secret     (decrypt, ecc half)
 *   [96:160] ML-KEM-768 seed  (decrypt, pqc half)   FIPS 203 64-byte seed (d||z)
 *
 * The device expands the PQC seeds at use time (deterministic keygen) and performs the
 * requested half. Nothing but the seeds is stored; the public key lives on the host.
 *
 * Primitives:
 *   ML-KEM-768: mlkem-native   (already vendored) — crypto_kem_keypair_derand / crypto_kem_dec
 *   ML-DSA-65 : mldsa-native   with MLD_CONFIG_REDUCE_RAM (~17 KB sign; 69 KB without -> won't fit 64 KB)
 *   Ed25519 / X25519: the firmware's existing primitives.
 *
 * Target: NXP MK20DX256 (Cortex-M4, 256 KB flash / 64 KB RAM). UNTESTED — by inspection.
 */
#ifndef OKPQC_H
#define OKPQC_H
#include <stdint.h>

/* slot key type (per-slot EEPROM nibble) */
#define KEYTYPE_PQC_PGP     7
#define PQC_PGP_BLOB_LEN    160

/* blob offsets */
#define PQC_OFF_ED25519     0
#define PQC_OFF_MLDSA_SEED  32
#define PQC_OFF_X25519      64
#define PQC_OFF_MLKEM_SEED  96

/* seed lengths */
#define MLDSA65_SEED_LEN    32
#define MLKEM768_SEED_LEN   64

/* component selector (buffer[6]): which half of the composite to run */
#define PQC_HALF_ECC        0    /* Ed25519 / X25519 */
#define PQC_HALF_PQC        1    /* ML-DSA-65 / ML-KEM-768 */
/* Sign-path selector that returns the derived ML-DSA-65 public key rather than
 * a signature, so a host can confirm which key a slot actually holds.
 * okcrypto_getpubkey() has no KEYTYPE_PQC_PGP branch, so this is the only way
 * to see it. */
#define PQC_HALF_PQC_PUBKEY 2
/* Returns the 32 raw ML-DSA seed bytes the device has stored, so a host can
 * tell a wrong-seed fault from a wrong-derivation one. DEBUG-only: this is
 * private key material and must never ship in a production build. */
#define PQC_HALF_PQC_SEED   3

/* sizes (FIPS 203 / 204) */
#define MLKEM_CT_SIZE       1088
#define MLKEM_SS_SIZE       32
#define MLKEM_DK_SIZE       2400
#define MLKEM_PK_SIZE       1184
#define MLDSA_SK_SIZE       4032
#define MLDSA_PK_SIZE       1952
#define MLDSA_SIG_SIZE      3309
#define ED25519_SIG_SIZE    64
#define X25519_SS_SIZE      32

#ifdef __cplusplus
extern "C" {
#endif
/* Called from okcrypto_sign / okcrypto_decrypt when the slot type is KEYTYPE_PQC_PGP.
 * okcore_flashget_RSA() must have loaded the 160-byte blob into rsa_private_key[] and set type=7. */
void okpqc_sign    (uint8_t *buffer);   /* OKSIGN:    selector -> Ed25519 sig(64) | ML-DSA sig(3309) */
void okpqc_decrypt (uint8_t *buffer);   /* OKDECRYPT: selector -> X25519 ss(32)  | ML-KEM ss(32)     */
#ifdef __cplusplus
}
#endif
#endif /* OKPQC_H */
