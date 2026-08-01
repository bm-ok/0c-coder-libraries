/*
 * okpqc.cpp — OnlyKey composite PQC PGP key operations (ML-KEM-768 + ML-DSA-65).
 * See okpqc.h for the 160-byte slot layout. Mirrors the two-phase CRYPTO_AUTH flow of
 * okcrypto_mlkem_decaps. Target: NXP MK20DX256 (Cortex-M4, 64 KB RAM).
 *
 * Libraries (vendored at repo root, compiled via their monolithic .c):
 *   ML-KEM-768: mlkem_native   (crypto_kem_keypair_derand / crypto_kem_dec)
 *   ML-DSA-65 : mldsa_native   built with MLD_CONFIG_PARAMETER_SET=65 + MLD_CONFIG_REDUCE_RAM
 *               (~17 KB sign; 69 KB without -> exceeds 64 KB RAM)
 *   Ed25519 / Curve25519: Arduino Crypto library (already used by the firmware).
 *
 * UNTESTED on hardware; the crypto core (keygen-from-seed + op) is verified on host.
 */
#include "Arduino.h"
#include "okpqc.h"
#include <string.h>
#include <Ed25519.h>
#include "Curve25519.h"
#include <RNG.h>

/* Arduino compiles each .cpp as its own translation unit, and DEBUG is
 * #define'd in onlykey.h / OnlyKey.ino - neither of which is included here.
 * Every #ifdef DEBUG block in this file was therefore compiling to nothing,
 * giving zero serial visibility into okpqc_sign()/okpqc_decrypt() while
 * looking identical to instrumentation elsewhere that works.
 *
 * NOTE: this forces DEBUG on for this file regardless of build type, so a
 * production (non-DEBUG) build would still compile this file's serial
 * output. Fine for the DEBUG builds this harness drives - it is the only
 * build with the SEREMU channel at all - but it should become a proper
 * conditional include before anything ships. */
#ifndef DEBUG
#define DEBUG
#endif

/* ---- vendored PQC primitives (declared here to avoid pulling the big headers) ---- */
extern "C" int PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(uint8_t *pk, uint8_t *dk, const uint8_t *coins /*64B seed*/);
extern "C" int PQCP_MLKEM_NATIVE_MLKEM768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *dk);
extern "C" int PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
extern "C" int PQCP_MLDSA_NATIVE_MLDSA65_signature(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);

/* ---- firmware RNG bridge required by mldsa_native config ----
 * RNG is the Arduino Crypto library global (RNG.h), as used elsewhere in the firmware.
 * (onlykey_mlkem_randombytes is already defined in okcrypto.cpp for mlkem_native's config.) */
extern "C" int onlykey_mldsa_randombytes(uint8_t *out, size_t outlen) { RNG.rand(out, (size_t)outlen); return 0; }

/* ---- firmware globals/APIs (okcore.cpp / okcrypto.cpp) ---- */
extern uint8_t  rsa_private_key[];       /* 160-byte blob after okcore_flashget_RSA */
extern uint8_t *large_buffer;            /* request in (digest / ct) */
extern uint8_t *large_resp_buffer;
extern int      large_buffer_offset;
extern uint8_t  CRYPTO_AUTH;
extern uint8_t  pending_operation;
extern int      outputmode;
// The real definition (okcore.cpp:260) is `uint8_t packet_buffer_details[5]`.
// Declaring it uint32_t here made every indexed access in this file use a
// 4-byte stride, so the indices did not address the bytes they name:
//   [0] -> byte 0   (correct only by coincidence)
//   [1] -> byte 4   (wanted byte 1: the SLOT passed to the decrypt below)
//   [2] -> bytes 8-11, i.e. entirely past the end of a 5-byte array
// One mismatch, two visible failures, both confirmed on hardware: the
// decrypt ran with the wrong slot and produced garbage, so large_buffer[0]
// was not the component selector and okpqc_sign() took the ML-DSA branch for
// a request that asked for the Ed25519 half; and `outputmode` was restored
// from out-of-bounds memory, so it was never WEBAUTHN and the response went
// out over raw HID instead of into the WebAuthn-retrievable buffer.
extern uint8_t packet_buffer_details[];
extern uint8_t  profilekey[];
extern uint8_t  ctap_buffer[];           /* large scratch (>= MLDSA_SIG_SIZE 3309) */

extern "C" {
  void process_packets(uint8_t *buffer, uint8_t type, uint8_t contype);
  void okcore_aes_gcm_decrypt(uint8_t *state, uint8_t slot, uint8_t features, uint8_t *key, int len);
  void send_transport_response(uint8_t *data, int len, bool enc, bool storeread);
  void hidprint(const char *s);
  void byteprint(uint8_t *bytes, int size);
  void fadeoff(int);
}

#ifndef OKDECRYPT_ERR_USER_ACTION_PENDING
#define OKDECRYPT_ERR_USER_ACTION_PENDING 0xF9
#endif
#ifndef CTAP2_ERR_OPERATION_PENDING
#define CTAP2_ERR_OPERATION_PENDING 0xF2
#endif
#ifndef CTAP2_ERR_DATA_READY
#define CTAP2_ERR_DATA_READY 0xF1
#endif
#ifndef LARGE_BUFFER_SIZE
#define LARGE_BUFFER_SIZE 1024
#endif

/* Ed25519 sign over the 32-byte secret in the blob (derive pub, then sign). */
static int okpqc_ed25519_sign(uint8_t sig[64], const uint8_t *m, size_t mlen, const uint8_t sk[32])
{
    uint8_t priv[32], pub[32];
    memcpy(priv, sk, 32);
    Ed25519::derivePublicKey(pub, priv);
    Ed25519::sign(sig, priv, pub, m, mlen);
    memset(priv, 0, sizeof priv);
    return 0;
}

/* X25519 shared secret = scalar * point (Curve25519::eval clamps + mults). */
static int okpqc_x25519_shared(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t s[32], p[32];
    memcpy(s, scalar, 32); memcpy(p, point, 32);
    // Curve25519::eval() does not clamp: it is a low-level curve evaluation
    // that expects an already-clamped scalar. The library's own dh1() clamps
    // explicitly before calling it, because it only ever handles freshly
    // generated ephemerals. This function instead loads a stored scalar out
    // of the composite blob, which was never clamped - yielding a different
    // point than every RFC 7748-conformant implementation (openpgp.js and
    // @noble both clamp internally, as the spec requires), so the shared
    // secret never matched and composite decrypt failed AES key-wrap
    // integrity even though the on-device math "succeeded".
    s[0] &= 0xF8;
    s[31] = (s[31] & 0x7F) | 0x40;
    bool ok = Curve25519::eval(out, s, p);
    memset(s, 0, sizeof s);
    return ok ? 0 : -1;
}

/* One scratch for the expanded secret key: ML-DSA sk(4032) covers ML-KEM dk(2400);
 * never used simultaneously. In .bss so it isn't on the deep call stack. */
static uint8_t pqc_expanded_sk[MLDSA_SK_SIZE];


/* ============================== SIGN ============================== */
void okpqc_sign(uint8_t *buffer)
{
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
        return;
    }
    if (CRYPTO_AUTH != 4) return;

    okcore_aes_gcm_decrypt(large_buffer, (uint8_t)packet_buffer_details[0],
                           (uint8_t)packet_buffer_details[1], profilekey, large_buffer_offset);
    pending_operation = CTAP2_ERR_OPERATION_PENDING;
    outputmode = (int)packet_buffer_details[2];

    /* wire: large_buffer[0] = component selector, large_buffer[1..] = message digest */
    uint8_t  sel = large_buffer[0];
    uint8_t *msg = large_buffer + 1;
    size_t   msglen = (large_buffer_offset > 0) ? (size_t)(large_buffer_offset - 1) : 0;

    /* Selector 2: return the ML-DSA-65 public key this device derives from the
     * stored seed, instead of a signature.
     *
     * The host cannot otherwise see it - okcrypto_getpubkey() has no
     * KEYTYPE_PQC_PGP branch - and without it "the signature does not verify"
     * cannot be split into "wrong key material" versus "wrong message
     * representative". Reading it over the DEBUG channel was tried first and
     * does not work: ML-DSA keygen floods the serial trace and the prints are
     * dropped (QUIRKS.md). This uses the same proven chunked response path the
     * signature itself uses.
     *
     * Costs nothing at rest and is genuinely useful beyond debugging - it lets
     * a host confirm which key a slot actually holds. */
    if (sel == PQC_HALF_PQC_PUBKEY) {
        uint8_t pk[MLDSA_PK_SIZE];
        int rc = PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(pk, pqc_expanded_sk,
                                                            rsa_private_key + PQC_OFF_MLDSA_SEED);
        memset(pqc_expanded_sk, 0, sizeof pqc_expanded_sk);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { pending_operation = 0; hidprint("Error ML-DSA keygen"); return; }
        pending_operation = CTAP2_ERR_DATA_READY;
        /* Send only rho, the first 32 bytes. The whole 1952-byte key cannot be
         * returned: store_FIDO_response() drops anything >= LARGE_RESP_BUFFER_SIZE
         * (1024) and does so SILENTLY, so the readback staged nothing and every
         * poll answered "Error incorrect challenge was entered" - its
         * nothing-is-staged message - which reads as a rejected challenge.
         * rho = H(xi || k || l)[0:32] is enough to compare derivations: it
         * differs whenever the seed or the expansion differs. */
        send_transport_response(pk, 32, false, true);
        fadeoff(85);
        return;
    }

    /* DEBUG-ONLY. Hands back the stored ML-DSA seed itself.
     *
     * The device derives an ML-DSA public key that matches neither the host's
     * derivation from the same blob nor ANY 32-byte window of that blob, while
     * the Ed25519 half of the same blob verifies and both decrypt halves round
     * trip. That combination leaves exactly two possibilities - the seed the
     * device stored is not the seed the host sent, or keypair_internal()
     * disagrees with FIPS 204 - and nothing observable from outside separates
     * them. This does.
     *
     * Guarded so it cannot reach a production build: it exports private key
     * material by design. */
#ifdef DEBUG
    if (sel == PQC_HALF_PQC_SEED) {
        pending_operation = CTAP2_ERR_DATA_READY;
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        send_transport_response(rsa_private_key + PQC_OFF_MLDSA_SEED, 32, false, true);
        fadeoff(85);
        return;
    }
#endif

    if (sel == PQC_HALF_ECC) {                           /* Ed25519 */
        uint8_t sig[ED25519_SIG_SIZE];
        okpqc_ed25519_sign(sig, msg, msglen, rsa_private_key + PQC_OFF_ED25519);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(sig, ED25519_SIG_SIZE, false, true);
        memset(sig, 0, sizeof sig);
    } else {                                             /* ML-DSA-65 */
        uint8_t pk[MLDSA_PK_SIZE];
        uint8_t *sig = ctap_buffer;                      /* >= 3309 B scratch */
        size_t siglen = 0;
        int rc = PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(pk, pqc_expanded_sk,
                                                            rsa_private_key + PQC_OFF_MLDSA_SEED);
        /* openpgp.js ml_dsa.js signs [0x00,0x00]||digest with empty ML-DSA context; sending the
         * RAW digest and signing with ctx="" yields the same FIPS 204 message representative.
         * Verify against openpgp.js on hardware. */
        if (rc == 0) rc = PQCP_MLDSA_NATIVE_MLDSA65_signature(sig, &siglen, msg, msglen,
                                    (const uint8_t*)0, 0, pqc_expanded_sk);
        memset(pqc_expanded_sk, 0, sizeof pqc_expanded_sk);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0 || siglen != MLDSA_SIG_SIZE) { pending_operation = 0; hidprint("Error ML-DSA sign"); return; }
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(sig, MLDSA_SIG_SIZE, false, true);   /* 3309 B, fragmented by transport */
        memset(sig, 0, MLDSA_SIG_SIZE);
    }
    fadeoff(85);
}

/* ============================= DECRYPT ============================ */
void okpqc_decrypt(uint8_t *buffer)
{
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
        return;
    }
    if (CRYPTO_AUTH != 4) return;

    okcore_aes_gcm_decrypt(large_buffer, (uint8_t)packet_buffer_details[0],
                           (uint8_t)packet_buffer_details[1], profilekey, large_buffer_offset);
    pending_operation = CTAP2_ERR_OPERATION_PENDING;
    outputmode = (int)packet_buffer_details[2];

    /* component inferred from input size: 32 B ephemeral point -> X25519, 1088 B ct -> ML-KEM */
    if (large_buffer_offset == X25519_SS_SIZE) {         /* X25519 on the 32-byte ephemeral point */
        uint8_t ss[X25519_SS_SIZE];
        int rc = okpqc_x25519_shared(ss, rsa_private_key + PQC_OFF_X25519, large_buffer);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { pending_operation = 0; hidprint("Error X25519"); return; }
        memcpy(large_resp_buffer, ss, X25519_SS_SIZE); memset(ss, 0, sizeof ss);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(large_resp_buffer, X25519_SS_SIZE, false, true);
    } else if (large_buffer_offset == MLKEM_CT_SIZE) {   /* ML-KEM-768 decapsulate 1088-B ct */
        uint8_t pk[MLKEM_PK_SIZE], ss[MLKEM_SS_SIZE];
        /* seed used DIRECTLY as coins (d||z) — no SHAKE(32->64); this is an imported key */
        int rc = PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(pk, pqc_expanded_sk, rsa_private_key + PQC_OFF_MLKEM_SEED);
        if (rc == 0) rc = PQCP_MLKEM_NATIVE_MLKEM768_dec(ss, large_buffer, pqc_expanded_sk);
        memset(pqc_expanded_sk, 0, MLKEM_DK_SIZE);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { memset(ss, 0, sizeof ss); pending_operation = 0; hidprint("Error ML-KEM decaps"); return; }
        memcpy(large_resp_buffer, ss, MLKEM_SS_SIZE); memset(ss, 0, sizeof ss);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(large_resp_buffer, MLKEM_SS_SIZE, false, true);
    } else {
        hidprint("Error PQC decrypt: bad input size");
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        pending_operation = 0;
    }
    fadeoff(85);
}
