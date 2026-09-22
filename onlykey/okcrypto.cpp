/* 
 * Copyright (c) 2015-2022, CryptoTrust LLC.
 * All rights reserved.
 * 
 * Author : Tim Steiner <t@crp.to>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "CryptoTrust" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    admin@crp.to.
 *
 * 5. Products derived from this software may not be called "OnlyKey"
 *    nor may "OnlyKey" or "CryptoTrust" appear in their names without
 *    specific prior written permission. For written permission, please
 *    contact admin@crp.to.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 7. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for this software and any
 *    accompanying software that uses this software. The source code
 *    must either be included in the distribution or be available for
 *    no more than the cost of distribution plus a nominal fee, and must
 *    be freely redistributable under reasonable conditions. For a
 *    binary file, complete source code means the source code for all
 *    modules it contains.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS
 * ARE GRANTED BY THIS LICENSE. IF SOFTWARE RECIPIENT INSTITUTES PATENT
 * LITIGATION AGAINST ANY ENTITY (INCLUDING A CROSS-CLAIM OR COUNTERCLAIM
 * IN A LAWSUIT) ALLEGING THAT THIS SOFTWARE (INCLUDING COMBINATIONS OF THE
 * SOFTWARE WITH OTHER SOFTWARE OR HARDWARE) INFRINGES SUCH SOFTWARE
 * RECIPIENT'S PATENT(S), THEN SUCH SOFTWARE RECIPIENT'S RIGHTS GRANTED BY
 * THIS LICENSE SHALL TERMINATE AS OF THE DATE SUCH LITIGATION IS FILED. IF
 * ANY PROVISION OF THIS AGREEMENT IS INVALID OR UNENFORCEABLE UNDER
 * APPLICABLE LAW, IT SHALL NOT AFFECT THE VALIDITY OR ENFORCEABILITY OF THE
 * REMAINDER OF THE TERMS OF THIS AGREEMENT, AND WITHOUT FURTHER ACTION
 * BY THE PARTIES HERETO, SUCH PROVISION SHALL BE REFORMED TO THE MINIMUM
 * EXTENT NECESSARY TO MAKE SUCH PROVISION VALID AND ENFORCEABLE. ALL
 * SOFTWARE RECIPIENT'S RIGHTS UNDER THIS AGREEMENT SHALL TERMINATE IF IT
 * FAILS TO COMPLY WITH ANY OF THE MATERIAL TERMS OR CONDITIONS OF THIS
 * AGREEMENT AND DOES NOT CURE SUCH FAILURE IN A REASONABLE PERIOD OF
 * TIME AFTER BECOMING AWARE OF SUCH NONCOMPLIANCE. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR  PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <cstring>
#include "Arduino.h"
#include "onlykey.h"
#ifdef STD_VERSION
#include <SoftTimer.h>
#include "T3MacLib.h"
#include <RNG.h>
#include <AES.h>
#include <CBC.h>
#include <GCM.h>
#include <ChaCha.h>
#include <Crypto.h>
#include "sha1.h"
#include "sha512.h"
#include "yubikey.h"
#include "device.h"
#include "okcrypto.h"

/*************************************/
//ML-KEM-768 (FIPS 203) support
/*************************************/
extern "C" {
#include "mlkem_native.h"
}

// Access SHA3-256 and SHAKE256 from mlkem-native (already compiled in)
extern "C" {
    void PQCP_MLKEM_NATIVE_MLKEM768_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
    void PQCP_MLKEM_NATIVE_MLKEM768_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
}
#define xwing_sha3_256  PQCP_MLKEM_NATIVE_MLKEM768_sha3_256
#define xwing_shake256  PQCP_MLKEM_NATIVE_MLKEM768_shake256

// X-Wing label: "\./", "/^\" = hex 5c 2e 2f 2f 5e 5c
static const uint8_t XWingLabel[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

// X-Wing Combiner (draft-connolly-cfrg-xwing-kem-09 Section 5.3)
// SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
static void xwing_combiner(uint8_t ss[32],
    const uint8_t ss_M[32], const uint8_t ss_X[32],
    const uint8_t ct_X[32], const uint8_t pk_X[32])
{
    uint8_t buf[134]; // 32+32+32+32+6
    memcpy(buf,       ss_M, 32);
    memcpy(buf + 32,  ss_X, 32);
    memcpy(buf + 64,  ct_X, 32);
    memcpy(buf + 96,  pk_X, 32);
    memcpy(buf + 128, XWingLabel, 6);
    xwing_sha3_256(ss, buf, 134);
    memset(buf, 0, sizeof(buf));
}

// Bridge OnlyKey RNG to mlkem-native expected signature
extern "C" int onlykey_mlkem_randombytes(uint8_t *out, size_t outlen) {
    RNG.rand(out, (unsigned)outlen);
    return 0;
}

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "memory_buffer_alloc.h"
#endif

/*************************************/
//RSA assignments
/*************************************/
uint8_t rsa_publicN[MAX_RSA_KEY_SIZE];
uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
/*************************************/
//ECC Authentication assignments
/*************************************/
uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE*2)+1];
uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
/*************************************/
//HMACSHA1 assignments
/*************************************/
extern uint8_t keyboard_buffer[KEYBOARD_BUFFER_SIZE];
/*************************************/

extern uint8_t Challenge_button1;
extern uint8_t Challenge_button2;
extern uint8_t Challenge_button3;
extern uint8_t CRYPTO_AUTH;
uint8_t type;
extern int large_buffer_offset;
extern uint8_t resp_buffer[64];
extern uint8_t* large_buffer;
extern uint8_t recv_buffer[64];
extern int large_buffer_len;
extern uint8_t profilekey[32];
extern uint8_t packet_buffer_details[5];
extern uint8_t* large_resp_buffer;
extern int outputmode;   /* defined as int in okcore.cpp - the uint8_t
                          * declaration here was UB that only worked by
                          * little-endian luck. */
extern uint8_t pending_operation;
extern uint8_t transit_key[32];

void okcrypto_sign (uint8_t *buffer) {
	uECC_set_rng(&RNG2);
	uint8_t features = 0;
	#ifdef DEBUG
	Serial.println();
	Serial.println("OKSIGN MESSAGE RECEIVED");
	#endif
	if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
		features = okcore_flashget_RSA ((int)buffer[5]);
		if (type == 0) {
			hidprint("Error no key set in this slot");
			fadeoff(0);
			return;
		}
		#ifdef DEBUG
		Serial.print(features, BIN);
		#endif
		if ((type & 0x0F) == KEYTYPE_PQC_PGP) { okpqc_sign(buffer); return; }
		if (is_bit_set(features, 6)) {
			okcrypto_rsasign(buffer);
		} else {
			#ifdef DEBUG
			Serial.print("Error key not set as signature key");
			#endif
			hidprint("Error key not set as signature key");
			fadeoff(0);
		}
		return;
	}
	else if (buffer[5] > 200 && buffer[5] < 205) { // SSH/GPG Derive Key
		okcrypto_ecdsa_eddsa(buffer);
	} else {
		if (buffer[5] > 100 && buffer[5] < 117) { // Keys 117 - 132 reserved
			features = okcore_flashget_ECC ((int)buffer[5]);
		}
		if (type == 0) {
			hidprint("Error no key set in this slot");
			fadeoff(0);
			return;
		}
		#ifdef DEBUG
		Serial.print(features, BIN);
		#endif
		if (is_bit_set(features, 6)) {
			okcrypto_ecdsa_eddsa(buffer);
		} else {
			#ifdef DEBUG
			Serial.print("Error key not set as signature key");
			#endif
			hidprint("Error key not set as signature key");
			fadeoff(0);
			return;
		}
	}
}

// ---- Derived (label-based) X-Wing over HID and FIDO2 --------------------
//
// Nothing is stored: the keypair is reproduced on demand from
// (slot-128 web-and-agent derivation key, 32-byte label tag). There is NO origin
// in the derivation, and that is deliberate: the CLI (raw HID, no origin at all)
// and every web origin must reach the same key for a label, so a file encrypted
// in the browser decrypts with the age plugin and vice versa. Both hash the label
// the same way (SHA256(utf8(label))).
//
// This used to hash a pinned string, "onlyagent.app", into the HKDF info and
// call it origin binding. It was never origin binding - it was the same constant
// for every caller - and it tied the key to a site that is not a production
// origin. v3 drops it; the info string alone is the domain separation. Web-
// derived ECC keys (okcrypto_hkdf) are different: those ARE bound to the
// browser's rpId, and stay that way.
//
// Construction, in two clearly separated layers:
//
//   1. HKDF (RFC 5869, HMAC-SHA256) turns the device secret, the label and the
//      origin into ONE 32-byte X-Wing seed. This is the only place HKDF
//      appears and the only OnlyKey-specific step.
//   2. That seed goes through the X-Wing spec's own key generation -
//      xwing_shake256(expanded, 96, seed, 32), ML-KEM d||z = expanded[0:64],
//      sk_X = expanded[64:96] - the SAME call and layout the stored-slot path
//      uses (okcrypto_xwing_keygen / _decaps / _getpubkey). A derived keypair
//      is therefore a real draft-connolly-cfrg-xwing-kem keypair.
//
// This replaces a construction in which mlkem_seed was SHA256(sk_X || tag) -
// the ML-KEM half a CHILD of the X25519 half - so an adversary who recovered
// sk_X from the published pk_X obtained the ML-KEM seed, sk_M and the whole
// shared secret, and the hybrid degraded to X25519-only security against
// exactly the adversary ML-KEM exists to stop. The halves are now sibling
// slices of one SHAKE-256 stream over a secret seed: neither reveals the other,
// in either direction.
//
// No private key material is returned to the host on either call now:
//
//   derive getpubkey : out = [ pk_M(1184) | pk_X(32) ] = XWING_PK_SIZE, public
//   derive decaps    : out = [ ss(32) ]                = X-Wing shared secret
//
// The RPID staging is gone too: okcrypto_hkdf() reads its info string out of
// ctap_buffer+4, so this code used to write a fixed origin string there before
// deriving - and a FIDO2 path that did NOT stage it derived a different sk_X
// than the CLI for the same label (ok_extension.cpp:280 documents that hunt).
// okcrypto_hkdf_expand() takes info as an argument, so the shared mutable
// buffer is out of the derivation entirely.

/* HKDF-Expand, RFC 5869 section 2.3, with an explicit info string.
 * okcrypto_hkdf() hardwires info to SHA256(RPID) read from ctap_buffer and is
 * deliberately left untouched: the P-256 / Curve25519 / NACL web-and-agent
 * keytypes share it, and any change there moves keys that already exist. */
void okcrypto_hkdf_expand (const uint8_t *prk, const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t L) {
	SHA256 hash;
	uint8_t T[32];
	size_t done = 0, Tlen = 0;
	uint8_t counter = 1;
	while (done < L) {
		hash.resetHMAC(prk, 32);
		if (Tlen) hash.update(T, Tlen);       /* T(0) is empty, RFC 5869 */
		hash.update(info, info_len);
		hash.update(&counter, 1);
		hash.finalizeHMAC(prk, 32, T, 32);
		Tlen = 32;
		size_t n = (L - done < 32) ? (L - done) : 32;
		memcpy(out + done, T, n);
		done += n;
		counter++;
	}
	memset(T, 0, sizeof(T));
}

/* (slot-128 key, label) -> one 32-byte X-Wing seed.
 * 32 and not 64 on purpose: X-Wing's decapsulation key IS 32 bytes; the 64-byte
 * quantity is ML-KEM's own d||z, which the spec expansion produces FROM it. */
void okcrypto_xwing_derive_seed (const uint8_t *label32, uint8_t *seed_out) {
	/* v3: the info string is the whole domain separation. v2 prefixed it with
	 * SHA256("onlyagent.app"), a constant every caller shared - see the block
	 * comment above. Changing it moved every derived X-Wing recipient, which was
	 * free to do only because derived X-Wing had never shipped. */
	static const char INFO[] = "onlykey/xwing/seed/v3";

	uint8_t salt[33] = {0};                        /* [flag 0][label32] */
	memcpy(salt + 1, label32, 32);

	okcore_flashget_ECC(RESERVED_KEY_WEB_AGENT_DERIVATION);   /* IKM -> ecc_private_key */

	SHA256 h;                                      /* HKDF-Extract, RFC 5869 2.2 */
	uint8_t prk[32];
	h.resetHMAC(salt, sizeof(salt));
	h.update(ecc_private_key, 32);
	h.finalizeHMAC(salt, sizeof(salt), prk, 32);

	okcrypto_hkdf_expand(prk, (const uint8_t *)INFO, sizeof(INFO) - 1, seed_out, 32);

	#ifdef DEBUG
	Serial.println();
	Serial.println("X-Wing PRK");
	byteprint(prk, 32);
	Serial.println("X-Wing derived seed");
	byteprint(seed_out, 32);
	#endif

	memset(prk, 0, sizeof(prk));
	memset(salt, 0, sizeof(salt));
	memset(ecc_private_key, 0, sizeof(ecc_private_key));
}

/* ML-KEM scratch for the two DERIVED X-Wing entry points.
 *
 * The stored-slot functions (okcrypto_xwing_getpubkey()/_decaps()) scratch at
 * the BASE of ctap_buffer, which is safe for them: they are only ever reached
 * from okcore.cpp's raw-HID dispatch, where no CTAP request is in flight.
 *
 * The derived pair is different - it is also reached from inside
 * ok_extension.cpp, in the middle of servicing a CTAPHID getAssertion whose
 * request bytes ARE ctap_buffer. Scratching at the base wrote 3584 bytes over
 * that live request and then zeroed them, so the assertion the browser got back
 * was built on a wiped buffer. Symptom: the derive call rejected with
 * NotAllowedError while a plain OKCONNECT over the identical path succeeded.
 *
 * The first attempt at a fix moved the scratch to the TAIL of ctap_buffer, and
 * that was worse. large_buffer IS the tail - ctap_buffer[5465,6585) - and it is
 * where okcrypto_decrypt() stages the ciphertext it hands to
 * okcrypto_xwing_derive_decaps() as `ct`. pk_M landed at [5401,6585), covering
 * the whole of it, so crypto_kem_keypair_derand() overwrote the ciphertext
 * before crypto_kem_dec() read it. ML-KEM's implicit rejection meant the
 * decapsulation still reported success and returned a deterministic value with
 * nothing to do with the sender's ciphertext: every derived-key file would have
 * failed to decrypt, with no error anywhere. Found by review, not on hardware -
 * the hardware pass ran on the build before the move.
 *
 * So the scratch goes BETWEEN the two: above whatever an inbound CTAP request
 * occupies, entirely below large_buffer. Both edges are asserted, because the
 * whole history of this constant is one edge being fixed by breaking the other.
 */
#define XWING_DERIVE_SCRATCH_SIZE  (MLKEM_SK_SIZE + MLKEM_PK_SIZE)   /* 3584 */
#define XWING_DERIVE_SCRATCH_OFF   (CTAPHID_BUFFER_SIZE - LARGE_BUFFER_SIZE - XWING_DERIVE_SCRATCH_SIZE)
static_assert(XWING_DERIVE_SCRATCH_OFF >= 1024,
	"ctap_buffer scratch would collide with an in-flight CTAP request");
static_assert(XWING_DERIVE_SCRATCH_OFF + XWING_DERIVE_SCRATCH_SIZE
	              <= CTAPHID_BUFFER_SIZE - LARGE_BUFFER_SIZE,
	"ctap_buffer scratch would overlap large_buffer - the staged ciphertext");

/* Derived recipient. out must be XWING_PK_SIZE (1216) bytes.
 * Same expansion and layout as okcrypto_xwing_getpubkey(). */
void okcrypto_xwing_derive_getpubkey (const uint8_t *label32, uint8_t *out) {
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	uint8_t seed[32];
	uint8_t expanded[96];

	okcrypto_xwing_derive_seed(label32, seed);
	xwing_shake256(expanded, 96, seed, XWING_SEED_SIZE);

	uint8_t *scratch = ctap_buffer + XWING_DERIVE_SCRATCH_OFF;
	uint8_t *sk_M = scratch;
	uint8_t *pk_M = scratch + MLKEM_SK_SIZE;
	/* crypto_kem_keypair_derand() is declared warn_unused_result and its return
	 * was being dropped. It cannot fail on a well-formed buffer today, so this
	 * changes nothing on the success path - but a silent failure here hands the
	 * host a public key made of whatever was in scratch, and "the key is wrong
	 * and nothing said so" is the failure mode that cost nine bugs on the
	 * derived X-Wing path. Say it out loud instead. */
	if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) != 0) {
		memset(seed, 0, sizeof(seed));
		memset(expanded, 0, sizeof(expanded));
		memset(scratch, 0, XWING_DERIVE_SCRATCH_SIZE);
		memset(out, 0, XWING_PK_SIZE);
		hidprint("Error ML-KEM keygen");
		return;
	}

	memcpy(out, pk_M, MLKEM_PK_SIZE);
	crypto_scalarmult_base(out + MLKEM_PK_SIZE, expanded + 64);   /* pk_X */

	memset(seed, 0, sizeof(seed));
	memset(expanded, 0, sizeof(expanded));
	memset(scratch, 0, XWING_DERIVE_SCRATCH_SIZE);
}

/* Derived decapsulation. ct is XWING_CT_SIZE (1120) = ct_M(1088) || ct_X(32);
 * out is the 32-byte X-Wing shared secret. Mirrors okcrypto_xwing_decaps()'s
 * body. ct_M now never leaves the host-to-device direction and the seed never
 * leaves the device at all. Returns 0 on success. */
int okcrypto_xwing_derive_decaps (const uint8_t *label32, const uint8_t *ct, uint8_t *out) {
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	uint8_t seed[32];
	uint8_t expanded[96];
	uint8_t ss_M[32], ss_X[32], pk_X[32];
	uint8_t *scratch = ctap_buffer + XWING_DERIVE_SCRATCH_OFF;   /* see note above */
	uint8_t *sk_M = scratch;
	uint8_t *pk_M = scratch + MLKEM_SK_SIZE;
	int rc = -1;

	okcrypto_xwing_derive_seed(label32, seed);
	xwing_shake256(expanded, 96, seed, XWING_SEED_SIZE);

	if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) == 0) {
		crypto_scalarmult_base(pk_X, expanded + 64);
		if (crypto_kem_dec(ss_M, ct, sk_M) == 0) {
			crypto_scalarmult(ss_X, expanded + 64, ct + MLKEM_CT_SIZE);  /* ct_X */
			xwing_combiner(out, ss_M, ss_X, ct + MLKEM_CT_SIZE, pk_X);
			rc = 0;
		}
	}

	memset(seed, 0, sizeof(seed));
	memset(expanded, 0, sizeof(expanded));
	memset(ss_M, 0, sizeof(ss_M));
	memset(ss_X, 0, sizeof(ss_X));
	memset(pk_X, 0, sizeof(pk_X));
	memset(scratch, 0, XWING_DERIVE_SCRATCH_SIZE);
	return rc;
}

void okcrypto_getpubkey (uint8_t *buffer) {
	#ifdef DEBUG
	Serial.println();
	Serial.println("OKGETPUBKEY MESSAGE RECEIVED");
	#endif
	if (buffer[5] < 5 && !buffer[6]) { //Slot 101-132 are for ECC, 1-4 are for RSA
		if (okcore_flashget_RSA ((int)buffer[5])) {
			/* okcrypto_getrsapubkey() sends (type * 128) bytes out of
			 * rsa_publicN[MAX_RSA_KEY_SIZE=512]. For a composite PQC PGP slot
			 * type is 7, so it sent 896 bytes: 384 past the array, straight to
			 * the host, and send_transport_response() then memset()s the same
			 * 896 bytes - 384 of them past the end. okcore_flashget_RSA() never
			 * populates rsa_publicN for this type (it decrypts the 160-byte seed
			 * blob into rsa_private_key and returns), so there was no public key
			 * there to send in the first place. A composite key's public halves
			 * come from okpqc_getpubkey(), not from an RSA modulus. */
			if ((type & 0x0F) == KEYTYPE_PQC_PGP) {
				hidprint("Error use OKGETPUBKEY PQC for composite keys");
			} else {
				okcrypto_getrsapubkey(buffer);
			}
		}
	} else if (buffer[5] < 117) { //128-132 are reserved
		if (okcore_flashget_ECC ((int)buffer[5])) {
			if (type == KEYTYPE_MLKEM768) okcrypto_mlkem_getpubkey(buffer);
			else if (type == KEYTYPE_XWING) okcrypto_xwing_getpubkey(buffer);
			else okcrypto_geteccpubkey(buffer);
		}
	} else if (buffer[5] == RESERVED_KEY_DERIVATION && buffer[6] <= KEYTYPE_CURVE25519) { // Generate key using provided data, return public
	okcrypto_derive_key(buffer[6], buffer+7, 0);
	send_transport_response(ecc_public_key, 64, false, false);
	} else if (buffer[5] == RESERVED_KEY_WEB_AGENT_DERIVATION && (buffer[6] & 0x0F) == KEYTYPE_XWING) {
		// Derived X-Wing recipient: buffer[7..39] = 32-byte label tag.
		// Returns the full public recipient [ pk_M(1184) | pk_X(32) ] - the same
		// XWING_PK_SIZE payload okcrypto_xwing_getpubkey() returns for a stored
		// slot. It used to return [ pk_X(32) | mlkem_seed(32) ]: 32 bytes of
		// PRIVATE key material handed out in answer to a request for a PUBLIC
		// key. ML-KEM has no short public key, and the only 32-byte value that
		// reproduces pk_M also reproduces sk_M, so there was no encoding fix -
		// the public key itself has to be the thing that is sent.
		//
		// 1216 bytes fits both transports: raw HID chunks at 64
		// (send_transport_response), and WebAuthn stages into large_resp_buffer
		// (LARGE_RESP_BUFFER_SIZE) for chunked retrieval by send_stored_response() - the path
		// already carrying a 3309-byte ML-DSA-65 signature.
		okcrypto_xwing_derive_getpubkey(buffer + 7, large_resp_buffer);
		send_transport_response(large_resp_buffer, XWING_PK_SIZE, true, true);
	}
}

/* Reassembly state for the derived X-Wing decapsulation request that arrives
 * over OKDECRYPT in multiple HID reports. File scope, not function statics,
 * because the request is reassembled across one call sequence, held across the
 * user-confirmation wait, and consumed by a later re-entry from
 * okcore_run_pending_op() - and because wipetasks() has to be able to drop it.
 *
 * derive_pending distinguishes "confirmed a request we actually staged" from a
 * re-entry with CRYPTO_AUTH == 4 left over from some other operation; without
 * it, a stale large_buffer would be decapsulated as if it were a request. */
static uint8_t derive_label[32];
static int     derive_offset  = 0;
static uint8_t derive_pending = 0;

void okcrypto_derive_reset (void) {
	derive_offset  = 0;
	derive_pending = 0;
	memset(derive_label, 0, sizeof(derive_label));
	memset(large_buffer, 0, LARGE_BUFFER_SIZE);
}

void okcrypto_decrypt (uint8_t *buffer){
	uECC_set_rng(&RNG2);
	uint8_t features = 0;
	#ifdef DEBUG
	Serial.println();
	Serial.println("OKDECRYPT MESSAGE RECEIVED");
	#endif
	if (buffer[5] == RESERVED_KEY_WEB_AGENT_DERIVATION) {
		// Derived X-Wing decaps over HID (split custody): label(32)+ct_X(32)
		// =64B exceeds one 57-byte HID report, so the host
		// (derive_decaps(), onlykey_hid.py) sends it via
		// send_large_message2()'s standard multi-packet framing, which puts
		// the CONTINUATION marker in buffer[6] (0xFF = more chunks coming,
		// else = this many bytes is the final chunk) - not a keytype
		// selector. This used to also require
		// `(buffer[6] & 0x0F) == KEYTYPE_XWING`, which only ever matched
		// okcrypto_getpubkey()'s single-packet OKGETPUBKEY sibling (built
		// with a *different* host method, _send_and_receive(), that really
		// does put key_type in buffer[6] since it never chunks). For this
		// multi-packet OKDECRYPT case chunk 1 has buffer[6]=0xFF (masked:
		// 0x0F, not KEYTYPE_XWING's 6) and chunk 2 has buffer[6]=7 (the
		// remaining byte count; masked: 7, not 6) - so the check never
		// matched either chunk, and both silently fell through to the
		// general slot-dispatch logic below, using a stale `type` value and
		// running the wrong decap function on garbage data. Confirmed live
		// (onlykey-testing TC-17): derive_decaps() always completed with no
		// error, but with a shared secret that never matched the sender's -
		// exactly this, not a byte-level issue. (The previous single-packet
		// version here also read `buffer + 7 + 32` = up to `buffer[70]`,
		// past `recv_buffer[64]`'s end - a real out-of-bounds read, but
		// dead code given the above, never actually reached; moot now that
		// this reassembles into its own right-sized buffer below instead of
		// reading straight out of the raw per-report buffer.)
		// RESERVED_KEY_WEB_AGENT_DERIVATION (128) is unique within OKDECRYPT's
		// dispatch, so buffer[5] alone is enough to recognize every chunk of
		// this request.
		//
		// WIRE CHANGE (rev 3): the payload is now
		//     [ label32(32) | ct(1120) ] = 32 + XWING_CT_SIZE = 1152 bytes
		// where ct = ct_M(1088) || ct_X(32) - the WHOLE X-Wing ciphertext - and
		// the reply is the 32-byte X-Wing shared secret. Previously the host
		// sent label32 || ct_X (64 B) and got back ss_X || mlkem_seed, then
		// finished the ML-KEM half itself from the seed. ct_M never reached the
		// device and the seed always reached the host; this reverses both, so
		// the derived path custodies its whole key exactly as the stored path
		// does.
		//
		// Reassembly keeps the label in its own 32 bytes and streams the
		// ciphertext into large_buffer (LARGE_BUFFER_SIZE == XWING_CT_SIZE ==
		// 1120, an exact fit), so no buffer constant changes and the added RAM
		// cost is 32 bytes.
		//
		// USER PRESENCE: this path used to answer the moment the last chunk
		// landed, with no button gate at all - the FIDO2 route in
		// ok_extension.cpp had its own, raw HID had none. It now goes through
		// the same confirmation machinery as every other decrypt: the final
		// chunk primes the challenge (okcore_prime_user_confirmation) and
		// returns, and okcore_run_pending_op() re-enters here with
		// CRYPTO_AUTH == 4 once the user has confirmed. The reassembled
		// request is what the challenge code is computed over, so the code
		// shown on the device is bound to the exact label and ciphertext being
		// decapsulated - and matches what the FIDO2 path shows for the same
		// request.
		//
		// The staged request is NOT encrypted into large_buffer the way
		// done_process_packets() encrypts packet_buffer, because neither half
		// of it is secret: ct is the sender's public ciphertext and the label
		// tag is public derivation input. What matters is that they cannot be
		// swapped between priming and confirmation, which the challenge hash
		// covers.
		if (CRYPTO_AUTH == 4) {
			// Confirmed. derive_label/large_buffer still hold the request.
			if (derive_pending != 1) {
				hidprint("Error no derived decaps request pending");
				fadeoff(0);
				return;
			}
			derive_pending = 0;
			uint8_t ss[XWING_SS_SIZE];
			if (okcrypto_xwing_derive_decaps(derive_label, large_buffer, ss) != 0) {
				hidprint("Error X-Wing derived decaps failed");
				fadeoff(0);
			} else {
				send_transport_response(ss, XWING_SS_SIZE, true, true);
			}
			memset(ss, 0, sizeof(ss));
			memset(derive_label, 0, sizeof(derive_label));
			memset(large_buffer, 0, LARGE_BUFFER_SIZE);
			// Release the LED/button state primed by the OKDECRYPT dispatcher's
			// fadeon(128); without this isfade stayed set, the LED faded
			// turquoise forever and every button press (config mode included)
			// was ignored until the key was re-plugged. Seen on hardware
			// 2026-09-03.
			fadeoff(85);
			return;
		} else if (CRYPTO_AUTH) {
			return; // confirmation in progress, ignore stray traffic
		}

		const int derive_total = 32 + XWING_CT_SIZE;
		int n = (buffer[6] == 0xFF) ? 57 : buffer[6];

		/* buffer is recv_buffer[64], so a report carries at most 57 payload
		 * bytes. buffer[6] is a length from the wire and only 0xFF was special-
		 * cased, so 58..254 passed straight through and the copy below read
		 * buffer[7 + i] well past the 64-byte packet into neighbouring globals,
		 * folding them into the ciphertext. (`n < 0` below never fired - n comes
		 * from a uint8_t.)
		 *
		 * This has to be checked BEFORE the padding tolerance underneath, which
		 * exists to forgive a tail a few bytes longer than the payload: an
		 * out-of-range length must be refused, not quietly clamped into range. */
		if (buffer[6] != 0xFF && buffer[6] > 57) {
			okcrypto_derive_reset();
			hidprint("Error derived decaps chunk size");
			fadeoff(0);
			return;
		}

		// The FINAL report's length is the keyhandle's data length, and
		// encode_ctaphid_request_as_keyhandle() zero-pads every keyhandle up to
		// 16 bytes of data because is_extension_request() needs that much to
		// match. A genuine tail shorter than 16 therefore arrives claiming 16,
		// and the host has no way to say otherwise.
		//
		// [label32 | ct1120] is 1152 bytes and 1152 = 20*57 + 12, so this tail
		// is ALWAYS 12 bytes and always claims 16. No host-side chunk size
		// avoids it: ok_extension.cpp re-chunks into 57-byte reports and counts
		// every non-final one as a full 57, so every host chunk but the last
		// must be a multiple of 57 - which fixes the final remainder at
		// 1152 mod 57 regardless of how the payload is split.
		//
		// Measured on hardware 2026-09-15: 21 reports arrived, derive_offset
		// reached 1156 against a 1152 expectation, and a correct ciphertext was
		// dropped with "Error derived decaps payload size" over four bytes of
		// transport padding.
		//
		// So trust derive_total over the padded length, for the last report
		// only and only when the overshoot is small enough to BE padding.
		// Anything larger is still a desynchronised request and still dropped:
		// this must not become the silent truncation TC-17 was.
		if (buffer[6] != 0xFF && derive_offset + n > derive_total
		    && derive_offset + n - derive_total < 16) {
			n = derive_total - derive_offset;
		}

		if (n < 0 || derive_offset + n > derive_total) {
			// Overlong or desynchronised: drop the whole request rather than
			// decapsulate against a half-filled buffer. Silent truncation here
			// is exactly what TC-17 looked like from the host side.
			okcrypto_derive_reset();
			hidprint("Error derived decaps payload size");
			fadeoff(0);
			return;
		}
		for (int i = 0; i < n; i++) {
			int pos = derive_offset + i;
			if (pos < 32) derive_label[pos] = buffer[7 + i];
			else          large_buffer[pos - 32] = buffer[7 + i];
		}
		derive_offset += n;
		if (buffer[6] == 0xFF) return;            /* more chunks coming */

		if (derive_offset != derive_total) {
			okcrypto_derive_reset();
			hidprint("Error derived decaps payload size");
			fadeoff(0);
			return;
		}
		derive_offset = 0;
		derive_pending = 1;

		// Prime the confirmation over the whole reassembled request. Two
		// updates rather than one concatenated buffer: there is no 1152-byte
		// scratch space to build it in, and the hash is the same either way.
		{
			SHA256_CTX ch;
			uint8_t chmsg[32];
			sha256_init(&ch);
			sha256_update(&ch, derive_label, 32);
			sha256_update(&ch, large_buffer, XWING_CT_SIZE);
			sha256_final(&ch, chmsg);
			okcore_prime_user_confirmation(OKDECRYPT, RESERVED_KEY_WEB_AGENT_DERIVATION,
			                               chmsg, sizeof(chmsg));
			memset(chmsg, 0, sizeof(chmsg));
		}
		pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
		// Actually SIGNAL that input is wanted.
		//
		// okcore_prime_user_confirmation() sets isfade and CRYPTO_AUTH but never
		// starts FadeinTask, so on its own the LED does not pulse - it just
		// holds whatever solid colour was last set. Every other confirmation
		// reaches the user through done_process_packets(), which ends with
		// fadeon(NEO_Color); this path returned straight to the caller instead
		// and so was the only confirmation on the device with no visible
		// prompt at all.
		//
		// Reported from hardware 2026-09-15: "solid yellow then green" across
		// three attempts, and correctly read as NOT a request for input - a
		// waiting OnlyKey pulses. The operation was in fact waiting, and timed
		// out after 20 s having never asked for anything.
		//
		// NEO_Color is defined in okcore.cpp and not declared in any header;
		// ok_extension.cpp externs it locally for the same reason.
		extern uint8_t NEO_Color;
		fadeon(NEO_Color);
		return;
	}
	if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
		features = okcore_flashget_RSA (buffer[5]);
		if (type == 0) {
			hidprint("Error no key set in this slot");
			fadeoff(0);
			return;
		}
		if ((type & 0x0F) == KEYTYPE_PQC_PGP) { okpqc_decrypt(buffer); return; }
		if (is_bit_set(features, 5)) {
			okcrypto_rsadecrypt(buffer);
		} else {
			#ifdef DEBUG
			Serial.print("Error key not set as decryption key");
			#endif
			hidprint("Error key not set as decryption key");
			fadeoff(0);
			return;
		}
	} else if (buffer[5] > 200 && buffer[5] < 205) { // SSH/GPG Derive Key
		okcrypto_ecdh(buffer);
	} else {
		if (buffer[5] > 100 && buffer[5] < 117) { // Keys 117 - 132 reserved
			// okcore_flashget_ECC() does a flash read + AES-GCM decrypt to
			// populate ecc_private_key - expensive, and this dispatcher runs
			// once per incoming HID report. For MLKEM/XWING, the multi-packet
			// ciphertext send (~20 reports for X-Wing) only actually needs
			// ecc_private_key once CRYPTO_AUTH==4 (okcrypto_xwing_decaps()/
			// okcrypto_mlkem_decaps() don't touch it before then - earlier
			// reports just accumulate via process_packets()). Paying that
			// cost on every one of ~20 reports was slow enough to cause real
			// receive-side USB packet loss under the burst (confirmed live:
			// only ~10 of ~20 chunks were arriving). type still needs
			// refreshing every time for correct dispatch below, just not the
			// expensive part - okeeprom_eeget_ecckey() is the cheap lookup
			// okcore_flashget_ECC() itself starts with.
			if ((type == KEYTYPE_MLKEM768 || type == KEYTYPE_XWING) && CRYPTO_AUTH && CRYPTO_AUTH != 4) {
				okeeprom_eeget_ecckey(&type, buffer[5]);
				type = type & 0x0F;
			} else {
				features = okcore_flashget_ECC ((int)buffer[5]);
			}
		}
		if (type == 0) {
			hidprint("Error no key set in this slot");
			fadeoff(0);
			return;
		}
		if (type == KEYTYPE_MLKEM768) {
			okcrypto_mlkem_decaps(buffer);
		} else if (type == KEYTYPE_XWING) {
			okcrypto_xwing_decaps(buffer);
		} else if (is_bit_set(features, 5)) {
			okcrypto_ecdh(buffer);
		} else {
			#ifdef DEBUG
			Serial.print("Error key not set as decryption key");
			#endif
			hidprint("Error key not set as decryption key");
			fadeoff(0);
			return;
		}
	}
}

void okcrypto_generate_random_key (uint8_t *buffer) {
	uECC_set_rng(&RNG2);
	#ifdef DEBUG
	Serial.println();
	Serial.println("GENERATE KEY MESSAGE RECEIVED");
	#endif
	if (buffer[5] > 100) { //Slot 101-132 are for ECC, 1-4 are for RSA
		if ((buffer[6] & 0x0F) == KEYTYPE_MLKEM768) {
			okcrypto_mlkem_keygen(buffer);
			return;
		} else if ((buffer[6] & 0x0F) == KEYTYPE_XWING) {
			okcrypto_xwing_keygen(buffer);
			return;
		} else if ((buffer[6] & 0x0F) == 1) {
			crypto_box_keypair(ecc_public_key, buffer+7); //Curve25519
		} else if ((buffer[6] & 0x0F) == 2) {
			const struct uECC_Curve_t * curve = uECC_secp256r1(); //P-256
			uECC_make_key(ecc_public_key, buffer+7, curve);
		} else if ((buffer[6] & 0x0F) == 3) {
			const struct uECC_Curve_t * curve = uECC_secp256k1();
			uECC_make_key(ecc_public_key, buffer+7, curve);
		} else if ((buffer[6] & 0x0F) == KEYTYPE_CURVE25519) {
			/* THIS BRANCH WAS MISSING, and its absence was silent. The CLI's
			 * genkey accepts 'c' and CLI_KEY_LETTERS maps it to
			 * KEYTYPE_CURVE25519 (4), so the all-FFs trigger arrived here,
			 * matched nothing, and fell through - leaving ecc_priv_flash() to
			 * store the thirty-two 0xFF trigger bytes AS THE PRIVATE KEY. Every
			 * device that ran it got the same key, and its public half is a
			 * published constant. Measured on the emulator: two generations in
			 * a row answered 210142ed5157ad3d1b58074fa3e9f077710a6a9d..., and
			 * the other three types answered differently every time.
			 *
			 * Thirty-two random bytes is the whole keygen here. Unlike P-256
			 * and secp256k1 - where uECC_make_key() exists because a random 32
			 * bytes can land at or above the group order - every 32-bit string
			 * is a valid X25519 scalar, and okcrypto_compute_pubkey() clamps on
			 * the way out. The byte-swap that same function applies for this
			 * type (the GnuPG ordering) does not matter to random bytes either.
			 *
			 * ecc_public_key is not computed because nothing reads it: the line
			 * below wipes it, and OKGETPUBKEY recomputes from the stored scalar
			 * after a flashget. */
			RNG2(buffer + 7, 32);
		}
		memset(ecc_public_key, 0, sizeof(ecc_public_key));
	}
	return;
}

void okcrypto_getrsapubkey (uint8_t *buffer) {
	#ifdef DEBUG
	byteprint(rsa_publicN, (type*128));
	#endif
	send_transport_response(rsa_publicN, (type*128), true, true);
}

void okcrypto_rsasign (uint8_t *buffer) {
	uint8_t rsa_signature[(type*128)];
	uint8_t rsa_signaturetemp[64];
    if(!CRYPTO_AUTH) {
		process_packets (buffer, 0, 0);
		pending_operation=OKSIGN_ERR_USER_ACTION_PENDING;
	}
	else if (CRYPTO_AUTH == 4) {
		if (large_buffer_offset != 28 && large_buffer_offset != 32 && large_buffer_offset != 48 && large_buffer_offset != 64) {
			hidprint("Error with RSA data to sign invalid size");
			#ifdef DEBUG
			Serial.println("Error with RSA data to sign invalid size");
			Serial.println(large_buffer_offset);
			#endif
			fadeoff(1);
			large_buffer_offset = 0;
			memset(large_buffer, 0, LARGE_BUFFER_SIZE); //wipe buffer
			return;
		}
		okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
		#ifdef DEBUG
		Serial.println();
		Serial.printf("RSA data to sign size=%d", large_buffer_offset);
		Serial.println();
		byteprint(large_buffer, large_buffer_offset);
		#endif
  		pending_operation=CTAP2_ERR_OPERATION_PENDING;
  		memcpy(rsa_signaturetemp, large_buffer, large_buffer_offset);
  		memset(large_buffer, 0, LARGE_BUFFER_SIZE);
  		if (rsa_sign (large_buffer_offset, rsa_signaturetemp, rsa_signature) == 0) {
			pending_operation=CTAP2_ERR_DATA_READY;
			#ifdef DEBUG
			Serial.print("Signature = ");
			byteprint(rsa_signature, sizeof(rsa_signature));
			#endif
			outputmode=packet_buffer_details[2]; // Outputmode set at start of operation
			if (outputmode == WEBAUTHN) {
				send_transport_response(rsa_signature, (type*128), true, true);
			}
			else {
				send_transport_response(rsa_signature, (type*128), false, false);
				wipetasks();
			}
		} else {
			pending_operation=0;
			hidprint("Error with RSA signing");
		}
		fadeoff(85);
		memset(rsa_signature, 0, sizeof(rsa_signature));
		if (outputmode != WEBAUTHN) memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
   		return;
	} else {
		#ifdef DEBUG
   		Serial.println("Waiting for challenge buttons to be pressed");
		#endif
		pending_operation=CTAP2_ERR_USER_ACTION_PENDING;
	}
}

void okcrypto_rsadecrypt (uint8_t *buffer) {
	unsigned int plaintext_len = 0;
    if(!CRYPTO_AUTH) {
		process_packets (buffer, 0, 0);
		pending_operation=OKDECRYPT_ERR_USER_ACTION_PENDING;
	}
	else if (CRYPTO_AUTH == 4) {
		if (large_buffer_offset != (type*128)) {
			hidprint("Error with RSA data to decrypt invalid size");
			#ifdef DEBUG
    		Serial.println("Error with RSA data to decrypt invalid size");
			Serial.println(large_buffer_offset);
			#endif
			fadeoff(1);
			large_buffer_offset = 0;
			memset(large_buffer, 0, LARGE_BUFFER_SIZE); //wipe buffer
			return;
		}
		okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
		#ifdef DEBUG
   		Serial.println();
    	Serial.printf("RSA ciphertext blob size=%d", large_buffer_offset);
		Serial.println();
		byteprint(large_buffer, large_buffer_offset);
		#endif
		// decrypt ciphertext in large_buffer to temp_buffer
  		pending_operation=CTAP2_ERR_OPERATION_PENDING;
  		uint8_t rsa_decrypttemp[(type*128)];
  		memcpy(rsa_decrypttemp, large_buffer, large_buffer_offset);
  		memset(large_buffer, 0, LARGE_BUFFER_SIZE);
		if (rsa_decrypt (&plaintext_len, rsa_decrypttemp, large_resp_buffer) == 0) {
			pending_operation=CTAP2_ERR_DATA_READY;
			#ifdef DEBUG
			Serial.println();
			Serial.print("Plaintext len = ");
			Serial.println(plaintext_len);
			Serial.print("Plaintext = ");
			byteprint(large_resp_buffer, plaintext_len);
			Serial.println();
			#endif
			outputmode=packet_buffer_details[2]; // Outputmode set at start of operation
			if (outputmode == WEBAUTHN) {
				send_transport_response(large_resp_buffer, plaintext_len,  true, true);
			}
			else {
				send_transport_response(large_resp_buffer, plaintext_len,  false, false);
				wipetasks();
			}
		} else {
			pending_operation=0;
			hidprint("Error with RSA decryption");
		}
		fadeoff(85);
		if (outputmode != WEBAUTHN) memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
		return;
	} else {
		#ifdef DEBUG
    	Serial.println("Waiting for challenge buttons to be pressed");
		#endif
		pending_operation=CTAP2_ERR_USER_ACTION_PENDING;
	}
}

void okcrypto_geteccpubkey (uint8_t *buffer) {
	uint8_t pubkeylen = 64;
	okcore_flashget_ECC (buffer[5]);
	if (type==KEYTYPE_NACL && buffer[6]==KEYTYPE_CURVE25519) {
		type = KEYTYPE_CURVE25519;
		okcrypto_compute_pubkey();
	} 
	#ifdef DEBUG
    Serial.println("okcrypto_geteccpubkey MESSAGE RECEIVED");
	byteprint(ecc_public_key, sizeof(ecc_public_key));
	#endif
	if (type==KEYTYPE_CURVE25519 || type==KEYTYPE_ED25519) pubkeylen = 32;
	send_transport_response(ecc_public_key, pubkeylen, true, true);
	memset(ecc_public_key, 0, MAX_ECC_KEY_SIZE*2); //wipe buffer
	memset(ecc_private_key, 0, MAX_ECC_KEY_SIZE); //wipe buffer
}

void okcrypto_derive_key (uint8_t ktype, uint8_t *data, uint8_t slot) {
	if (!slot) { //SHA256 KDF used for SSH and challenge-response
		okcore_flashget_ECC (RESERVED_KEY_DERIVATION); //Default Key stored in ECC slot 32
		memset(ecc_public_key, 0, sizeof(ecc_public_key));
		SHA256_CTX ekey;
		sha256_init(&ekey);
		sha256_update(&ekey, ecc_private_key, 32); //Add default key to ekey
		sha256_update(&ekey, data, 32); //Add provided data to ekey
		sha256_final(&ekey, ecc_private_key); //Create hash and store
		#ifdef DEBUG
		Serial.println();
		Serial.println("Agent derivation private key");
		byteprint(ecc_private_key,32);
		#endif
  	} else if (slot==RESERVED_KEY_WEB_AGENT_DERIVATION) { //HMAC SHA256 KDF used for web requests
	  	okcore_flashget_ECC (slot); 
		#ifdef DEBUG
		Serial.println();
		Serial.println("Web and agent derivation key");
		byteprint(ecc_private_key,32);
		Serial.println("Other data");
		byteprint(data,33);
		#endif
		// HKDF Reference: RFC5869 - https://tools.ietf.org/html/rfc5869
		okcrypto_hkdf(data, ecc_private_key, ecc_private_key, 32);
		#ifdef DEBUG
		Serial.println();
		Serial.println("HKDF Key");
		byteprint(ecc_private_key,32);
		#endif
  	}
	type=ktype;
	okcrypto_compute_pubkey();
}

void okcrypto_ecdsa_eddsa(uint8_t *buffer)
{
	uint8_t ecc_signature[64];
	uint8_t hash[64];
	#ifdef DEBUG
    Serial.println();
    Serial.println("OKECDSA_EDDSA SIGN MESSAGE RECEIVED");
	#endif
    if (!CRYPTO_AUTH) {
		process_packets (buffer, 0, 0);
		pending_operation=OKSIGN_ERR_USER_ACTION_PENDING;	
	}
	else if (CRYPTO_AUTH == 4) {
		//if (outputmode == RAW_USB && !derived_key_challenge_mode && !stored_key_challenge_mod) {

		//}
		okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
		#ifdef DEBUG
		Serial.println();
		Serial.print("ECC blob size of ");
		Serial.println(large_buffer_offset);
		byteprint(large_buffer, large_buffer_offset);
		#endif
		uint8_t tmp[32 + 32 + 64];
		SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
		if (buffer[5] > 200) {
			/* 201/202/203 (SSH/GPG) and 211/212/213 (web-and-agent domain) are
			 * the whole set. okcrypto_sign() routes 201..204 here, so 204 -
			 * which names no key type - fell through this chain with `type` and
			 * ecc_private_key left over from whatever ran last, and then signed
			 * with them, or (for a stale type outside 1..3) returned the
			 * uninitialised ecc_signature[64] as if it were a signature.
			 * Reject it rather than letting stale state decide. */
			if (buffer[5] != 201 && buffer[5] != 202 && buffer[5] != 203 &&
			    buffer[5] != 211 && buffer[5] != 212 && buffer[5] != 213) {
				hidprint("Error invalid derived key slot");
				fadeoff(0);
				return;
			}
			if (buffer[5] == 201) {
				//Used by SSH, old version used 132, new version uses 201 for type 1
				okcrypto_derive_key(1, large_buffer+(large_buffer_offset-32), 0);
			}
			else if (buffer[5] == 202) {
				okcrypto_derive_key(2, large_buffer+(large_buffer_offset-32), 0);
			}
			else if (buffer[5] == 203) {
				okcrypto_derive_key(3, large_buffer+(large_buffer_offset-32), 0);
			} else if (buffer[5] == 211) {
				okcrypto_derive_key(1, large_buffer+(large_buffer_offset-32), RESERVED_KEY_WEB_AGENT_DERIVATION);
			}
			else if (buffer[5] == 212) {
				okcrypto_derive_key(2, large_buffer+(large_buffer_offset-32), RESERVED_KEY_WEB_AGENT_DERIVATION);
			}
			else if (buffer[5] == 213) {
				okcrypto_derive_key(3, large_buffer+(large_buffer_offset-32), RESERVED_KEY_WEB_AGENT_DERIVATION);
			}
			large_buffer_offset = large_buffer_offset - 32;
		}
		else if (buffer[5] >= 101 && buffer[5] <= 116) {
			// Not using derived key, using stored key
			okcore_flashget_ECC (buffer[5]); //Default Key stored in ECC slot 32
		} else {
			return;
		}

		if (large_buffer_offset == 32 || large_buffer_offset == 64) { // Hash and sign data if larger than 32 bytes, if 32 bytes sign data
			memcpy(hash, large_buffer, large_buffer_offset);
		} else {
			SHA256_CTX msghash;
			sha256_init(&msghash);
			sha256_update(&msghash, large_buffer, large_buffer_offset);
			sha256_final(&msghash, hash); //Create hash and store
			if (type!=0x01) large_buffer_offset = 32;
		} 

		#ifdef DEBUG
      	Serial.println("Signature Hash ");
	  	byteprint(hash, large_buffer_offset);
	  	Serial.print("Type");
	  	Serial.println(type);
		Serial.println("Private ");
	  	byteprint(ecc_private_key, sizeof(ecc_private_key));
		#endif
		pending_operation=CTAP2_ERR_OPERATION_PENDING;			
		/* The chain below has no else: a `type` outside 1..3 signed nothing and
		 * the uninitialised ecc_signature[64] went to the host as the result -
		 * 64 bytes of whatever that stack frame last held. Fail instead. */
		if (type != 0x01 && type != 0x02 && type != 0x03) {
			hidprint("Error key not set as signature key");
			fadeoff(0);
			return;
		}
		if (type==0x01) Ed25519::sign(ecc_signature, ecc_private_key, ecc_public_key, large_buffer, large_buffer_offset);
		else if (type==0x02) {
			const struct uECC_Curve_t * curve = uECC_secp256r1(); //P-256
			if (!uECC_sign_deterministic(ecc_private_key,
						hash,
						large_buffer_offset,
						&ectx.uECC,
						ecc_signature,
						curve)) {
							#ifdef DEBUG
      						Serial.println("Signature Failed ");
							#endif
      		}
		}
		else if (type==0x03) {
			const struct uECC_Curve_t * curve = uECC_secp256k1();
			if (!uECC_sign_deterministic(ecc_private_key,
						hash,
						large_buffer_offset,
						&ectx.uECC,
						ecc_signature,
						curve)) {
							#ifdef DEBUG
      						Serial.println("Signature Failed ");
							#endif
      		}
		} 
		#ifdef DEBUG
		Serial.print("Signature=");
		byteprint(ecc_signature, 64);
		#endif
		pending_operation=CTAP2_ERR_DATA_READY;
		outputmode=packet_buffer_details[2]; // Outputmode set at start of operation
		if (outputmode == WEBAUTHN) {
			send_transport_response (ecc_signature, 64, true, true);
		}
		else {
			send_transport_response (ecc_signature, 64, true, true);
			wipetasks();
		}
  		// Stop the fade in
  		fadeoff(85);
    	memset(large_buffer, 0, LARGE_BUFFER_SIZE);
		memset(ecc_public_key, 0, sizeof(ecc_public_key)); //wipe buffer
		memset(ecc_private_key, 0, sizeof(ecc_private_key)); //wipe buffer
    	return;
	} else {
		#ifdef DEBUG
    	Serial.println("Waiting for challenge buttons to be pressed");
		#endif
		pending_operation=CTAP2_ERR_USER_ACTION_PENDING;
	}
}

void okcrypto_ecdh(uint8_t *buffer) {
	uint8_t temp[65] = {0};
	uint8_t resplen = 64;
	#ifdef DEBUG
    Serial.println();
    Serial.println("OKECDH MESSAGE RECEIVED");
	#endif
    if(!CRYPTO_AUTH) {
		process_packets (buffer, 0, 0);
		pending_operation=OKDECRYPT_ERR_USER_ACTION_PENDING;		
	}
	else if (CRYPTO_AUTH == 4) {	
		okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
		#ifdef DEBUG
		Serial.println();
		Serial.print("ECC blob size of ");
		Serial.println(large_buffer_offset);
		byteprint(large_buffer, large_buffer_offset);
		#endif
		if (buffer[5] > 201) {
			if (buffer[5] == 202) {
				okcrypto_derive_key(2, large_buffer+(large_buffer_offset-32), 0);
			}
			else if (buffer[5] == 203) {
				okcrypto_derive_key(3, large_buffer+(large_buffer_offset-32), 0);
			} 
			else if (buffer[5] == 204) {
				okcrypto_derive_key(4, large_buffer+(large_buffer_offset-32), 0); 
			} else if (buffer[5] == 212) {
				okcrypto_derive_key(2, large_buffer+(large_buffer_offset-32), RESERVED_KEY_WEB_AGENT_DERIVATION);
			}
			else if (buffer[5] == 213) {
				okcrypto_derive_key(3, large_buffer+(large_buffer_offset-32), RESERVED_KEY_WEB_AGENT_DERIVATION);
			} 
			else if (buffer[5] == 214) {
				okcrypto_derive_key(4, large_buffer+(large_buffer_offset-32), RESERVED_KEY_WEB_AGENT_DERIVATION); 
			} 
			large_buffer_offset = large_buffer_offset - 32; //Remove derivation data hash
		}
		else if (buffer[5] >= 101 && buffer[5] <= 116) {
			// Not using derived key, using stored key
			okcore_flashget_ECC (buffer[5]); 
		} else {
			return;
		}

		if (type==2 || type==3) type+=100; // Different shared secret method required, multiply points and return x and y
		if (type==1) {
			type=4; // Use Curve25519 scalar multiply
			resplen = 32;
			okcrypto_compute_pubkey();
		}
		if (large_buffer_offset == 33 || large_buffer_offset == 65) { // Remove public key first byte 0x04 or 0x40 for Trezor agent
			large_buffer_offset--;
			memcpy(ecc_public_key, large_buffer+1, large_buffer_offset);
		} else if (large_buffer_offset == 32 || large_buffer_offset == 64) {
			memcpy(ecc_public_key, large_buffer, large_buffer_offset);
		}

		pending_operation=CTAP2_ERR_USER_ACTION_PENDING;
		// Use ecc_private_key and provided pubkey to generate shared secret
		if (large_buffer_offset == 64 || large_buffer_offset == 32) { // Public key sizes
			if (okcrypto_shared_secret (ecc_public_key, temp)) { 
				//Error
			}
		}
					
		#ifdef DEBUG
      	Serial.println("Input public");
	  	byteprint(ecc_public_key, large_buffer_offset);
      	Serial.println("Private");
	  	byteprint(ecc_private_key, sizeof(ecc_private_key));
	  	Serial.print("Type");
	  	Serial.println(type);
		Serial.print("Shared Secret =");
		byteprint(temp, large_buffer_offset);
		#endif
		pending_operation=CTAP2_ERR_DATA_READY;
		outputmode=packet_buffer_details[2]; // Outputmode set at start of operation
		if (outputmode == WEBAUTHN) {
			send_transport_response (temp, resplen, true, true);
		}
		else {
			send_transport_response (temp, resplen, true, true);
			wipetasks();
		}
  		// Stop the fade in
  		fadeoff(85);
    	memset(large_buffer, 0, LARGE_BUFFER_SIZE);
		memset(ecc_public_key, 0, sizeof(ecc_public_key)); //wipe buffer
		memset(ecc_private_key, 0, sizeof(ecc_private_key)); //wipe buffer
    	return;
	} else {
		#ifdef DEBUG
    	Serial.println("Waiting for challenge buttons to be pressed");
		#endif
	}
}

void okcrypto_hmacsha1 () {
	uint8_t temp[32];
	uint8_t inputlen;
	uint8_t slot = keyboard_buffer[64];
	uint16_t crc;
	extern uint8_t setBuffer[9];
	uint8_t *ptr;
	#ifdef DEBUG
	Serial.println();
	Serial.println("GENERATE HMACSHA1 MESSAGE RECEIVED");
	Serial.print("SLOT = ");
	Serial.println(slot);
	#endif
    if (CRYPTO_AUTH == 4) {
		if(!check_crc(keyboard_buffer)) {
			memset(setBuffer, 0, 9);
			memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
			return;
		}
		outputmode=RAW_USB;
		if (slot == 0x38) { //HMAC Slot 2 selected, 0x08 for slot 2, 0x00 for slot 1
			okcore_flashget_ECC (RESERVED_KEY_HMACSHA1_2); //ECC slot 129 reserved for HMAC Slot 2 key
		} else if (slot == 0x30){ //HMAC Slot 2 selected, 0x00 for slot 1
			okcore_flashget_ECC (RESERVED_KEY_HMACSHA1_1); //ECC slot 130 reserved for HMAC Slot 1 key
		} else if (slot >= 1 &&  slot <= 24) { 
			okcore_flashget_hmac(ecc_private_key, slot); 
		} 
		if (type == 0) { //Generate a key using the default key in slot 132 if there is no key set in slot
			// Derive key from SHA256 hash of default key and added data temp
			for(int i=0; i<32; i++) {
				temp[i] = i + slot;
			}
			okcrypto_derive_key(0, temp, 0);
		}
		outputmode=KEYBOARD_USB;
		// Variable buffer size
		// Any challenge less than 16 bytes in size is treated as 16 bytes, this means response will be different than Yubikey response
		if (keyboard_buffer[57] == 0x20 && keyboard_buffer[58] == 0x20 && keyboard_buffer[59] == 0x20 && keyboard_buffer[60] == 0x20 && keyboard_buffer[61] == 0x20 && keyboard_buffer[62] == 0x20 && keyboard_buffer[63] == 0x20) {
			inputlen = 32; //KeepassXC uses 0x20 for empty buffer
		} else {
			int i;
			for (i = 63; i >= 15; i--) {
				if (keyboard_buffer[i] != 0) { //YubiKey personalization tool uses 0 for empty buffer
					break;
				}	
			}
			inputlen = i+1;
		}
		#ifdef DEBUG
		Serial.print("HMACSHA1 Input = ");
	    byteprint(keyboard_buffer, 70);
		Serial.print("Input Length");
	    Serial.println(inputlen);
		#endif
		//Load HMAC Key
		Sha1.initHmac(ecc_private_key, 20);
		//Generate HMACSHA1
		Sha1.write(keyboard_buffer, inputlen);
		ptr=keyboard_buffer;
		ptr = Sha1.resultHmac();
		memcpy(temp, ptr, 20);
		memset(ecc_private_key, 0, 32);
		#ifdef DEBUG
		Serial.print("HMAC for CRC Input = ");
	    byteprint(temp, 20);
		#endif
		//Generate CRC of Output
		crc = yubikey_crc16 (temp, 20);
		memcpy(keyboard_buffer, temp, 7);
		keyboard_buffer[7] = 0xC0; //Part 1 of HMAC
		memcpy(keyboard_buffer+8, temp+7, 7);
		keyboard_buffer[15] = 0xC1; //Part 2 of HMAC
		memcpy(keyboard_buffer+16, temp+14, 6);
		keyboard_buffer[23] = 0xC2; //Part 3 of HMAC
		memset(keyboard_buffer +24, 0, KEYBOARD_BUFFER_SIZE-24);
    	// CRC Bytes expected are CRC-16/X-25 but yubikey_crc16 generates CRC-16/MCRF4XX,
    	// Weird that firmware uses a different CRC-16 than https://github.com/Yubico/yubikey-personalization/blob/master/ykcore/
		// We can XOR CRC-16/MCRF4XX output to convert to CRC-16/X-25
		crc ^= 0xFFFF;
		keyboard_buffer[22] = crc & 0xFF;
		keyboard_buffer[24] = crc >> 8;
		keyboard_buffer[31] = 0xC3; //Part 4 contains part of CRC and mystery byte keyboard_buffer[28]
		keyboard_buffer[28] = 0x4B;
		#ifdef DEBUG
		Serial.print("HMACSHA1 Output = ");
	    byteprint(keyboard_buffer, KEYBOARD_BUFFER_SIZE);
		Serial.print("CRC = ");
		Serial.println(crc);
		#endif
    	return;
	} else {
		#ifdef DEBUG
    	Serial.println("Waiting for challenge buttons to be pressed");
		#endif
	}
}

int okcrypto_shared_secret (uint8_t *pub, uint8_t *secret) {
	const struct uECC_Curve_t * curve;
	switch (type) {
	case KEYTYPE_NACL:
		if (crypto_box_beforenm(secret, pub, ecc_private_key)) return 1;
		else return 0;
	case KEYTYPE_P256R1:
		curve = uECC_secp256r1();
		if (uECC_shared_secret(pub, ecc_private_key, secret, curve)) {
			return 0;
		}
		else return 1;
	case KEYTYPE_P256K1:
		curve = uECC_secp256k1();
		if (uECC_shared_secret(pub, ecc_private_key, secret, curve)) {
			return 0;
		}
		else return 1;
	case KEYTYPE_CURVE25519:
		Curve25519::eval(secret, ecc_private_key, pub);
		return 0;
	case KEYTYPE_ECDH_P256R:
		curve = uECC_secp256r1();
		if (uECC_shared_secret2(pub, ecc_private_key, secret, curve)) {
		return 0;
		}
	case KEYTYPE_ECDH_P256K:
		curve = uECC_secp256k1();
		if (uECC_shared_secret2(pub, ecc_private_key, secret, curve)) {
		return 0;
		}

	case KEYTYPE_MLKEM768:
		// ML-KEM uses KEM (encaps/decaps), not DH shared secret
		// Use okcrypto_mlkem_decaps() instead
		hidprint("Error use ML-KEM decaps for this key type");
		return 1;

	case KEYTYPE_XWING:
		// Hybrid uses combined KEM, not DH shared secret
		// Use okcrypto_xwing_decaps() instead
		hidprint("Error use X-Wing decaps for this key type");
		return 1;

	default:
		hidprint("Error ECC type incorrect");
		return 1;
	}
}

mbedtls_md_context_t sha512_ctx;

void crypto_sha512_init() {
	mbedtls_md_type_t md_type = MBEDTLS_MD_SHA512;
	mbedtls_md_init (&sha512_ctx);
	mbedtls_md_setup(&sha512_ctx, mbedtls_md_info_from_type(md_type), 0); // 0 = not using HMAC
}

void crypto_sha512_update(const uint8_t * data, size_t len) {
	mbedtls_md_update (&sha512_ctx, data, len);
}

void crypto_sha512_final(uint8_t * hash) {
	mbedtls_md_finish (&sha512_ctx, hash);
	mbedtls_md_free (&sha512_ctx);
}

/* ---- FIDO2 transit encryption, v2 --------------------------------------
 *
 * The transit key is a fresh ECDH secret per OKCONNECT, which is why a fixed
 * IV looked defensible. It is not: many messages ride each key. Every chunk of
 * a multi-part request is a separate GCM operation on the host side, and every
 * response is another - all under one key and, until now, one all-zero IV. Same
 * key and same IV means the same keystream, so any two messages in a session
 * XOR to the XOR of their plaintexts.
 *
 * That was directly exploitable rather than merely untidy. A plain OKCONNECT
 * answers with the status string "UNLOCKEDv<version>" in the clear (opt3 is 0
 * on that request, so store_FIDO_response() does not encrypt it), and the very
 * next OKCONNECT - the derive one - encrypts that same string at a known
 * offset under the session key. XOR the two and the leading keystream for the
 * session falls out; every other message starts at keystream offset zero, so
 * the head of each one follows, and a derived X-Wing shared secret is only 32
 * bytes. `tagLength: 0` on the host meant there was no authentication either,
 * so the same keystream let an attacker flip bits undetected.
 *
 * GCM's requirement is that (key, IV) never repeats - NOT that a key encrypt
 * only one message. A counter gives that directly, without restructuring the
 * chunking:
 *
 *     IV = [dir(1)][counter big-endian(4)][zero(7)]
 *
 * The direction byte matters. With one shared counter, or two counters both
 * starting at zero, the first request and the first response collide on the
 * same IV under the same key - the original bug, just rarer. dir 0 is
 * device->host and dir 1 is host->device, so the two directions can never meet.
 *
 * THE COUNTER TRAVELS ON THE WIRE, in the clear, ahead of the ciphertext:
 *
 *     [counter big-endian(4)][ciphertext(n)][tag(16)]
 *
 * so neither side has to track what the other has sent. That is not a
 * refinement, it is the only version of this that survives contact with this
 * transport:
 *
 *   - Windows 10 1903 delivers every FIDO2 request twice. The duplicate is
 *     recognised and dropped further down (opt3 <= last_request_opt3), but the
 *     decrypt happens first, so a receiver-side counter would advance twice for
 *     one host-side increment and every message after it would fail its tag.
 *   - A derive request is itself an OKCONNECT and replaces the transit key
 *     mid-session. The host has already had one bug from holding a stale
 *     sharedsec across exactly that rekey; a stale counter would be the same
 *     bug with a worse failure mode.
 *
 * The counter is not covered by any AAD and does not need to be: GCM derives
 * its whole tag computation from the IV, so a flipped counter fails the tag.
 *
 * Counters still restart whenever the transit key does - okcrypto_transit_reset()
 * is called wherever the key is established - so a session never gets near
 * 2^32 messages and the value stays small enough to read in a trace.
 *
 * Compatibility: this is a clean break, gated on the firmware version. The
 * plain OKCONNECT response is unencrypted, so a host reads the version out of
 * it before any of this applies and picks the scheme from there. Old firmware
 * with a new host keeps working. A NEW firmware with an OLD host does not -
 * the old host sends no counter and no tag, and every request fails to
 * authenticate.
 */
static uint32_t transit_ctr_out = 0;   /* device -> host */

void okcrypto_transit_reset (void) {
	transit_ctr_out = 0;
}

static void okcrypto_transit_iv (uint8_t *iv, uint8_t dir, uint32_t ctr) {
	memset(iv, 0, 12);
	iv[0] = dir;
	iv[1] = (uint8_t)(ctr >> 24);
	iv[2] = (uint8_t)(ctr >> 16);
	iv[3] = (uint8_t)(ctr >> 8);
	iv[4] = (uint8_t)(ctr);
}

/* Seal a frame in place.
 *
 * `frame` points at the 4-byte counter field, which this writes; the plaintext
 * must already be sitting at frame + OKCRYPTO_TRANSIT_CTR_LEN and be `len`
 * bytes long. The caller owns len + OKCRYPTO_TRANSIT_OVERHEAD bytes at
 * `frame`. Returns the framed length. */
int okcrypto_transit_seal (uint8_t *frame, int len) {
	#ifdef STD_VERSION
	uint8_t iv[12];
	uint32_t ctr = transit_ctr_out++;
	uint8_t *ct = frame + OKCRYPTO_TRANSIT_CTR_LEN;
	GCM<AES256> gcm;
	frame[0] = (uint8_t)(ctr >> 24);
	frame[1] = (uint8_t)(ctr >> 16);
	frame[2] = (uint8_t)(ctr >> 8);
	frame[3] = (uint8_t)(ctr);
	okcrypto_transit_iv(iv, OKCRYPTO_TRANSIT_DIR_OUT, ctr);
	gcm.clear();
	gcm.setKey(transit_key, 32);
	gcm.setIV(iv, 12);
	gcm.encrypt(ct, ct, len);
	gcm.computeTag(ct + len, OKCRYPTO_TRANSIT_TAG_LEN);
	#ifdef DEBUG
	Serial.print("transit seal ctr=");
	Serial.print(ctr);
	Serial.print(" len=");
	Serial.println(len);
	#endif
	return len + OKCRYPTO_TRANSIT_OVERHEAD;
	#else
	return len;
	#endif
}

/* Open a frame in place.
 *
 * `frame` is [counter(4)][ciphertext(n)][tag(16)] and `len` is the whole of
 * that. On success the plaintext is moved down to frame[0] - so callers keep
 * indexing from the start of their buffer as they always have - and its length
 * is returned. On failure returns -1 and the buffer is wiped.
 *
 * A failure means these bytes were not produced by something holding the
 * transit key. There is no partial acceptance: the caller discards the whole
 * request rather than acting on any of it. */
int okcrypto_transit_open (uint8_t *frame, int len) {
	#ifdef STD_VERSION
	uint8_t iv[12];
	uint8_t tag[OKCRYPTO_TRANSIT_TAG_LEN];
	uint8_t *ct = frame + OKCRYPTO_TRANSIT_CTR_LEN;
	uint32_t ctr;
	GCM<AES256> gcm;
	int ptlen = len - OKCRYPTO_TRANSIT_OVERHEAD;
	if (ptlen < 0) {
		memset(frame, 0, len > 0 ? len : 0);
		return -1;
	}
	ctr = ((uint32_t)frame[0] << 24) | ((uint32_t)frame[1] << 16) |
	      ((uint32_t)frame[2] << 8)  |  (uint32_t)frame[3];
	memcpy(tag, ct + ptlen, OKCRYPTO_TRANSIT_TAG_LEN);
	okcrypto_transit_iv(iv, OKCRYPTO_TRANSIT_DIR_IN, ctr);
	gcm.clear();
	gcm.setKey(transit_key, 32);
	gcm.setIV(iv, 12);
	gcm.decrypt(ct, ct, ptlen);
	if (!gcm.checkTag(tag, OKCRYPTO_TRANSIT_TAG_LEN)) {
		/* Wipe rather than leave a plausible-looking plaintext behind. */
		memset(frame, 0, len);
		return -1;
	}
	memmove(frame, ct, ptlen);
	memset(frame + ptlen, 0, len - ptlen);
	#ifdef DEBUG
	Serial.print("transit open ctr=");
	Serial.print(ctr);
	Serial.print(" len=");
	Serial.println(ptlen);
	#endif
	return ptlen;
	#else
	return len;
	#endif
}

/* okcrypto_aes_crypto_box() lived here. It was AES-GCM under the transit key
 * with a hardcoded all-zero IV and the tag check commented out - a raw
 * keystream XOR, reused for every message of a session in both directions. It
 * is gone rather than deprecated: leaving a working same-IV primitive next to
 * the sealed one is an invitation to call the wrong one. Use
 * okcrypto_transit_seal() and okcrypto_transit_open() above. */

int rsa_sign (int mlen, const uint8_t *msg, uint8_t *out)
{
	//mbedtls_rsa_self_test(1);
	mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
	int ret = 0;
	static mbedtls_rsa_context rsa;
    uint8_t rsa_ciphertext[(type*128)];
	mbedtls_mpi P1, Q1, H;
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

	mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);
	rsa.len = (type*128);
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa.E, 0x10001) );

	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.P, &rsa_private_key[0], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.Q, &rsa_private_key[((type*128) / 2)], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&rsa.N, &rsa.P, &rsa.Q) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa.P, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa.Q, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.D , &rsa.E, &H) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DP, &rsa.D, &P1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DQ, &rsa.D, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.QP, &rsa.Q, &rsa.P) );

	#ifdef DEBUG
	Serial.printf( "\nRSA len = " );
	Serial.println(rsa.len);
	#endif
	ret = mbedtls_rsa_check_privkey( &rsa );
	cleanup:
	mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);

   	if( ret != 0 ) {
		#ifdef DEBUG
	  	Serial.printf("Error with key check =%d", ret);
	  	#endif
		hidprint("Error invalid key, key check failed");
		return -1;
	}
  	if (ret == 0) {
    	#ifdef DEBUG
    	Serial.print("RSA sign messege length = ");
	  	Serial.println(mlen);
	  	#endif
	  	if (mlen > ((type*128)-11)) mlen = ((type*128)-11);

		switch (mlen) {
		case 64:
			md_type = MBEDTLS_MD_SHA512;
		break;

		case 48:
			md_type = MBEDTLS_MD_SHA384;
		break;

		case 32:
			md_type = MBEDTLS_MD_SHA256;
		break;

		case 28:
			md_type = MBEDTLS_MD_SHA224;
		break;

		//case 20:
		//	md_type = MBEDTLS_MD_RIPEMD160;
		//break;

		default:
		break;

		}

      	ret = mbedtls_rsa_rsassa_pkcs1_v15_sign (&rsa, mbedtls_rand, NULL, MBEDTLS_RSA_PRIVATE, md_type, mlen, msg, rsa_ciphertext);
      	#ifdef DEBUG
      		Serial.print("Hash Value = ");
	 		byteprint((uint8_t *)msg, mlen);
	  	#endif
	  	memcpy (out, rsa_ciphertext, (type*128));
		/*int ret2 = mbedtls_rsa_rsassa_pkcs1_v15_verify ( &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE, mlen, msg, rsa_ciphertext );
		#ifdef DEBUG
		Serial.print("Hash Value = ");
		byteprint((uint8_t *)msg, mlen);
		#endif
		if( ret2 != 0 ) {
			#ifdef DEBUG
			Serial.print("Signature Verification Failed ");
			Serial.println(ret2);
			#endif
			return -1;
		}*/
    }
  	mbedtls_rsa_free (&rsa);
  	if (ret == 0) {
		#ifdef DEBUG
		Serial.println("completed successfully");
		#endif
		return 0;
    }
  	else {
		#ifdef DEBUG
		Serial.print("MBEDTLS_ERR_RSA_XXX error code ");
    	Serial.println(ret);
		#endif
		hidprint("invalid data, or data does not match key");
    	return -1;
    }
}

int rsa_decrypt (unsigned int *olen, const uint8_t *in, uint8_t *out) {
	mbedtls_mpi P1, Q1, H;
	int ret = 0;
	static mbedtls_rsa_context rsa;
	#ifdef DEBUG
	Serial.printf ("\nRSA decrypt:");
	Serial.println ((uint32_t)&ret);
	#endif

	mbedtls_rsa_init (&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);
	rsa.len = (type*128);
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa.E, 0x10001) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.P, &rsa_private_key[0], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.Q, &rsa_private_key[((type*128) / 2)], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&rsa.N, &rsa.P, &rsa.Q) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa.P, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa.Q, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.D , &rsa.E, &H) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DP, &rsa.D, &P1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DQ, &rsa.D, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.QP, &rsa.Q, &rsa.P) );
	#ifdef DEBUG
	Serial.println (rsa.len);
	#endif
	cleanup:
	mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);

	#ifdef DEBUG
	Serial.printf( "\nRSA len = " );
	Serial.println(rsa.len);
	#endif
	ret = mbedtls_rsa_check_privkey( &rsa );
	if (ret != 0) {
		#ifdef DEBUG
		Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
		Serial.println (ret);
		#endif
		hidprint("Error invalid key, key check failed");
	}
	if (ret == 0) {
		#ifdef DEBUG
		Serial.print ("RSA decrypt ");
		#endif
		ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt (&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, olen, in, out, 512);
	}
	mbedtls_rsa_free (&rsa);
	if (ret == 0) {
		#ifdef DEBUG
		Serial.println ("completed successfully");
		Serial.print (*olen);
		#endif
		return 0;
	} else {
		#ifdef DEBUG
		Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
		Serial.println (ret);
		#endif
		hidprint("Error invalid data, or data does not match key");
		return -1;
	}
}

void rsa_getpub (uint8_t type) {
	mbedtls_mpi P, Q, N;
	int ret = 0;
	#ifdef DEBUG
	Serial.print ("RSA generate public N:");
	#endif
	mbedtls_mpi_init (&P);  mbedtls_mpi_init (&Q);  mbedtls_mpi_init (&N);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&P, &rsa_private_key[0], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&Q, &rsa_private_key[((type*128) / 2)], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&N, &P, &Q) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary (&N, &rsa_publicN[0], (type*128) ));
	cleanup:
	mbedtls_mpi_free (&P);  mbedtls_mpi_free (&Q);  mbedtls_mpi_free (&N);

	if (ret == 0) {
		#ifdef DEBUG
		Serial.print ("Storing RSA public ");
		byteprint(rsa_publicN, (type*128));
		#endif
	} else {
		hidprint("Error generating RSA public N");
		#ifdef DEBUG
		Serial.print ("Error generating RSA public");
		byteprint(rsa_publicN, (type*128));
		#endif
	}
}

int rsa_encrypt (int len, const uint8_t *in, uint8_t *out) {
	mbedtls_mpi P1, Q1, H;
	int ret = 0;
	static mbedtls_rsa_context rsa;
	#ifdef DEBUG
	Serial.printf ("\nRSA encrypt:");
	Serial.println ((uint32_t)&ret);
	#endif

	mbedtls_rsa_init (&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);
	rsa.len = (type*128);
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa.E, 0x10001) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.P, &rsa_private_key[0], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.Q, &rsa_private_key[((type*128) / 2)], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&rsa.N, &rsa.P, &rsa.Q) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa.P, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa.Q, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.D , &rsa.E, &H) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DP, &rsa.D, &P1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DQ, &rsa.D, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.QP, &rsa.Q, &rsa.P) );
	#ifdef DEBUG
	Serial.println (rsa.len);
	#endif
	cleanup:
	mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);

	#ifdef DEBUG
	Serial.printf( "\nRSA len = " );
	Serial.println(rsa.len);
	#endif
  	ret = mbedtls_rsa_check_pubkey( &rsa );
	if (ret != 0) {
	  #ifdef DEBUG
      Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
	  Serial.println (ret);
	  #endif
	  return ret;
	}
  	if (ret == 0) {
	  ret = mbedtls_rsa_rsaes_pkcs1_v15_encrypt	( &rsa, mbedtls_rand, NULL, MBEDTLS_RSA_PUBLIC, len, in, out );
    }
  	mbedtls_rsa_free (&rsa);
  	if (ret == 0) {
	  #ifdef DEBUG
      Serial.print ("completed successfully");
	  #endif
      return 0;
    } else {
	  #ifdef DEBUG
      Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
	  Serial.println (ret);
	  #endif
      return ret;
    }
}

bool is_bit_set(unsigned char byte, int index) {
  return (byte >> index) & 1;
}

int mbedtls_rand( void *rng_state, unsigned char *output, size_t len ) {
	if( rng_state != NULL )
        rng_state = NULL;
    RNG2( output, len );
    return( 0 );
}


void okcrypto_hkdf(const void *salt, const void *inputKey, void *outputKey, const size_t L) {
	SHA256 hash;
	uint8_t PRK[hash.hashSize()];
	void *s;
	// 33, not 32: the salt this function is called with is the 33-byte
	// additional_data ([flag][32-byte tag]), and the salt == NULL branch below
	// zero-fills and then HMAC-keys 33 bytes from here. At 32 that wrote one
	// byte past the end of this buffer and read one byte past it as key
	// material. Unreachable today - okcrypto_derive_key(), the only caller,
	// always passes a non-NULL 33-byte salt - but the trap was live for the
	// next caller. Sized off the salt length rather than the hash length on
	// purpose; they are not the same quantity.
	uint8_t tmp[33];
	int N = L / hash.hashSize();
	int i = 0;
	uint8_t rpid[255] ={0};
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	uint8_t *ptr = ctap_buffer+4;
	while (*ptr != 0x02 && i < (int)sizeof(rpid)) {
		rpid[i] = *ptr;
		i++;
		ptr++;
	}

	#ifdef DEBUG
	Serial.print ("RPID");
	byteprint(rpid,i);
	#endif

	SHA256_CTX context;
	sha256_init(&context);
	sha256_update(&context, rpid, i);
	sha256_final(&context, rpid);

	#ifdef DEBUG
	Serial.print ("RPID hash");
	byteprint(rpid,32);
	#endif

	if (salt == NULL) {
		s = tmp;
		memset(s, 0, sizeof(tmp));
	} else {
		s = (void *) salt;
	}

	#ifdef DEBUG
	Serial.print ("salt");
	byteprint((uint8_t*)s,33);
	#endif


	hash.resetHMAC(s, 33);
	hash.update(inputKey, 32);
	hash.finalizeHMAC(s, 33, PRK, hash.hashSize());

	// Use rpid as tsalt
	size_t saltLen = hash.hashSize() + 32 + 1;
	uint8_t tsalt[saltLen];
	tsalt[saltLen - 1] = 1;
	memcpy(tsalt + hash.hashSize(), rpid, 32);

	// Calculate T(1)
	hash.resetHMAC (PRK, hash.hashSize());
	hash.update(tsalt + hash.hashSize(), 32 + 1);
	hash.finalizeHMAC (PRK, hash.hashSize(), outputKey, hash.hashSize());

	tsalt[saltLen - 1] += 1;
	memcpy(tsalt, outputKey, hash.hashSize());

	// Calculate T(2) ... T(N)
	for (i = 1; i < N; i++) {
		hash.resetHMAC(PRK, hash.hashSize());
		hash.update(tsalt, saltLen);
		hash.finalizeHMAC(PRK,
					hash.hashSize(),
					((uint8_t *) outputKey) + (i * hash.hashSize()),
					hash.hashSize());

		tsalt[saltLen - 1] += 1;
		memcpy(tsalt,
			((uint8_t *) outputKey) + (i * hash.hashSize()),
			hash.hashSize());
	}

	// Process remaining octets if there are any.
	if (L % hash.hashSize()) {
		uint8_t rslt[hash.hashSize()];
		int remain = L - N * hash.hashSize();
		hash.resetHMAC(PRK, hash.hashSize());
		hash.update(tsalt, saltLen);
		hash.finalizeHMAC(PRK, hash.hashSize(), rslt, hash.hashSize());

		memcpy(((uint8_t *) outputKey) + (N * hash.hashSize()),
			rslt,
			remain);
	}
		hash.clear();

}


void okcrypto_aes_gcm_encrypt(uint8_t *state, uint8_t slot, uint8_t value, const uint8_t *key, int len)
{
	#ifdef STD_VERSION
	GCM<AES256> gcm;
	uint8_t iv2[12];
	uint8_t aeskey[32];
	uint8_t data[2];
	uint8_t function1 = 1;
	uint8_t function2 = 2;
	data[0] = slot;
	data[1] = value;

	okcore_flashget_noncehash((uint8_t*)iv2, 12);

	#ifdef DEBUG
	Serial.print("INPUT KEY ");
	byteprint((uint8_t *)key, 32);
	#endif

	#ifdef DEBUG
	Serial.println("SLOT");
	Serial.println(slot);
	#endif

	#ifdef DEBUG
	Serial.print("VALUE");
	Serial.print(value);
	#endif

	SHA256_CTX iv;
	sha256_init(&iv);
	sha256_update(&iv, iv2, 12);		   //add nonce
	sha256_update(&iv, data, 2);		   //add data
	sha256_update(&iv, (uint8_t *)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&iv, aeskey);			   //Create hash and store in aeskey temporarily
	memcpy(iv2, aeskey, 12);
	#ifdef DEBUG
	Serial.print("IV ");
	byteprint(iv2, 12);
	#endif

	SHA256_CTX key2;
	sha256_init(&key2);
	sha256_update(&key2, key, 16);			 //add profilekey
	sha256_update(&key2, data, 2);			 //add slot
	sha256_update(&key2, (uint8_t *)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&key2, aeskey);			 //Create hash and store in aeskey

	#ifdef DEBUG
	Serial.print("AES KEY ");
	byteprint(aeskey, 32);
	Serial.print("DECRYPTED STATE");
	byteprint(state, len);
	#endif

	#ifdef FACTORYKEYS
	// Even/Odd IV different encryption algorithms
	if (iv2[0] % 2 == 0) {
		function1 = 2;
		function2 = 1;
	}
	okcrypto_split_sundae(state, iv2, len, function1, true);
	#endif

	gcm.clear();
	gcm.setKey(aeskey, 32);
	gcm.setIV(iv2, 12);
	gcm.encrypt(state, state, len);
	
	#ifdef FACTORYKEYS
	okcrypto_split_sundae(state, iv2, len, function2, true);
	#endif

	#ifdef DEBUG
	Serial.print("ENCRYPTED STATE");
	byteprint(state, len);
	#endif
	//gcm.computeTag(tag, sizeof(tag));
	#endif
}

void okcrypto_aes_gcm_decrypt(uint8_t *state, uint8_t slot, uint8_t value, const uint8_t *key, int len)
{
	#ifdef STD_VERSION
	GCM<AES256> gcm;
	uint8_t iv2[12];
	uint8_t aeskey[32];
	uint8_t data[2];
	uint8_t function3 = 4;
	uint8_t function4 = 3;
	data[0] = slot;
	data[1] = value;

	okcore_flashget_noncehash((uint8_t*)iv2, 12);

	#ifdef DEBUG
	Serial.print("INPUT KEY ");
	byteprint((uint8_t *)key, 32);
	#endif

	#ifdef DEBUG
	Serial.println("SLOT");
	Serial.println(slot);
	#endif

	#ifdef DEBUG
	Serial.print("VALUE");
	Serial.print(value);
	#endif

	SHA256_CTX iv;
	sha256_init(&iv);
	sha256_update(&iv, iv2, 12);		   //add nonce
	sha256_update(&iv, data, 2);		   //add data
	sha256_update(&iv, (uint8_t *)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&iv, aeskey);			   //Create hash and store in aeskey temporarily
	memcpy(iv2, aeskey, 12);

	#ifdef DEBUG
	Serial.print("IV ");
	byteprint(iv2, 12);
	#endif

	SHA256_CTX key2;
	sha256_init(&key2);
	sha256_update(&key2, key, 16);			 //add profilekey
	sha256_update(&key2, data, 2);			 //add data
	sha256_update(&key2, (uint8_t *)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&key2, aeskey);			 //Create hash and store in aeskey

	#ifdef DEBUG
	Serial.print("AES KEY ");
	byteprint(aeskey, 32);
	Serial.print("ENCRYPTED STATE");
	byteprint(state, len);
	#endif

	#ifdef FACTORYKEYS
	// Even/Odd IV different encryption algorithms
	if (iv2[0] % 2 == 0) {
		function3 = 3;
		function4 = 4;
	}
	okcrypto_split_sundae(state, iv2, len, function3, true);
	#endif

	gcm.clear();
	gcm.setKey(aeskey, 32);
	gcm.setIV(iv2, 12);
	gcm.decrypt(state, state, len);

	#ifdef FACTORYKEYS
	okcrypto_split_sundae(state, iv2, len, function4, true);
	#endif

	#ifdef DEBUG
	Serial.print("DECRYPTED STATE");
	byteprint(state, len);
	#endif
	//if (!gcm.checkTag(tag, sizeof(tag))) {
	//	return 1;
	//}
	#endif
}

void okcrypto_aes_gcm_encrypt2(uint8_t *state, uint8_t *iv1, const uint8_t *key, int len, bool s)
{
	#ifdef STD_VERSION
	GCM<AES256> gcm;
	//uint8_t tag[16];
	uint8_t function1 = 1;
	uint8_t function2 = 2;
	#ifdef DEBUG
	Serial.print("DECRYPTED STATE");
	byteprint(state, len);
	#endif

	#ifdef FACTORYKEYS
	// Even/Odd IV different encryption algorithms
	if (iv1[0] % 2 == 0) {
		function1 = 2;
		function2 = 1;
	}
	okcrypto_split_sundae(state, iv1, len, function1, s);
	#endif

	gcm.clear();
	gcm.setKey(key, 32);
	gcm.setIV(iv1, 12);
	gcm.encrypt(state, state, len);

	#ifdef FACTORYKEYS
	okcrypto_split_sundae(state, iv1, len, function2, s);
	#endif

	#ifdef DEBUG
	Serial.print("ENCRYPTED STATE");
	byteprint(state, len);
	#endif
	//gcm.computeTag(tag, sizeof(tag));
	#endif
}

void okcrypto_aes_gcm_decrypt2(uint8_t *state, uint8_t *iv1, const uint8_t *key, int len, bool s)
{
	#ifdef STD_VERSION
	GCM<AES256> gcm;
	//uint8_t tag[16];
	uint8_t function3 = 4;
	uint8_t function4 = 3;
	#ifdef DEBUG
	Serial.print("ENCRYPTED STATE");
	byteprint(state, len);
	#endif

	#ifdef FACTORYKEYS
	// Even/Odd IV different encryption algorithm sequence
	if (iv1[0] % 2 == 0) {
		function3 = 3;
		function4 = 4;
	}
	okcrypto_split_sundae(state, iv1, len, function3, s);
	#endif

	gcm.clear();
	gcm.setKey(key, 32);
	gcm.setIV(iv1, 12);
	gcm.decrypt(state, state, len);

	#ifdef FACTORYKEYS
	okcrypto_split_sundae(state, iv1, len, function4, s);
	#endif

	#ifdef DEBUG
	Serial.print("DECRYPTED STATE");
	byteprint(state, len);
	#endif
	//if (!gcm.checkTag(tag, sizeof(tag))) {
	//	return 1;
	//}
	#endif
}

void okcrypto_aes_cbc_encrypt(uint8_t *state, uint8_t *iv, const uint8_t *key, int len)
{
	#ifdef STD_VERSION
	CBC<AES256> cbc;
	#ifdef DEBUG
	Serial.print("DECRYPTED STATE");
	byteprint(state, len);
	#endif
	cbc.clear();
	cbc.setKey(key, 32);
	cbc.setIV(iv, 16);
	cbc.encrypt(state, state, len);
	#ifdef DEBUG
	Serial.print("ENCRYPTED STATE");
	byteprint(state, len);
	#endif
	#endif
}

void okcrypto_aes_cbc_decrypt(uint8_t *state, uint8_t *iv, const uint8_t *key, int len)
{
	#ifdef STD_VERSION
	CBC<AES256> cbc;
	#ifdef DEBUG
	Serial.print("ENCRYPTED STATE");
	byteprint(state, len);
	#endif
	cbc.clear();
	cbc.setKey(key, 32);
	cbc.setIV(iv, 16);
	cbc.decrypt(state, state, len);
	#ifdef DEBUG
	Serial.print("DECRYPTED STATE");
	byteprint(state, len);
	#endif
	#endif
}

/*
void newhope_test ()
{
	//unsigned long ran;
	char rand[32];
	csprng SRNG,CRNG;
	RAND_clean(&SRNG);
	RAND_clean(&CRNG);
	char s[1792],sb[1824],uc[2176],keyA[32],keyB[32];

	octet S= {0,sizeof(s),s};
	octet SB= {0,sizeof(sb),sb};
	octet UC= {0,sizeof(uc),uc};
	octet KEYA={0,sizeof(keyA),keyA};
	octet KEYB={0,sizeof(keyB),keyB};
	RNG2((uint8_t*)rand, 32);
	RAND_seed(&SRNG, rand);
	RNG2((uint8_t*)rand, 32);
	RAND_seed(&CRNG, rand);

	// NewHope Simple key exchange

	NHS_SERVER_1(&SRNG,&SB,&S);
	NHS_CLIENT(&CRNG,&SB,&UC,&KEYB);
	NHS_SERVER_2(&S,&UC,&KEYA);
#ifdef DEBUG
	Serial.println("NewHope Simple Implemetation from open source AMCL crypto library (https://github.com/MIRACL/amcl)");
	Serial.println("Ref. Alkim, Ducas, Popplemann and Schwabe (https://eprint.iacr.org/2016/1157)");
	Serial.printf("Alice shared secret= 0x");
	byteprint((uint8_t*)KEYA.val, KEYA.len);
	Serial.printf("Bob's shared secret= 0x");
	byteprint((uint8_t*)KEYB.val, KEYB.len);
#endif
	return;
} */

void okcrypto_split_sundae(uint8_t *state, uint8_t *iv, int len, uint8_t function, bool s) {
	// Just like an ice cream sundae, this function mixes the best crypto algorithms 
	// together in variable order with multiple variable keys and in order to mitigate 
	// side channel attacks against a single algorithm or key. State is split so that 
	// each crypto function only has access to part of the state. Order of algorithms 
	// vary depending on IV. Keys vary depending on the IV and shift 0-12 bytes.
	//
	// Here is how it works 
	// 
	// Each function only has access to half (or less) of the input/output
	//
	// 1 has access to first 1/3 bytes
	// 2 has access to last 1/3 bytes
	// 3 has access to middle 1/3 bytes
	//
	// AES-256 GCM has access to all bytes
	//
	// 1 has access to last 1/2 bytes
	// 2 has access to first 1/2 bytes
	//
	// Each byte is double or triple encrypted using different algorithms
	// The middle algorithm is a FIPS 140-2 compliant algorithm for FIPS compliance
	//
	// Encrypt usage:
	// okcrypto_split_sundae(<plaintext>, <plaintext len>, <iv>, <encrypt outer>)
	// return ciphertext
	// middle encryption is completed in calling function
	// okcrypto_split_sundae(<ciphertext>, <ciphertext len>, <iv>, <encrypt inner>)
	// return ciphertext
	//
	// Decrypt usage:
	// okcrypto_split_sundae(<ciphertext>, <ciphertext len>, <iv>, <decrypt inner>)
	// return ciphertext
	// middle decryption is completed in calling function
	// okcrypto_split_sundae(<ciphertext>, <ciphertext len>, <iv>, <decrypt outer>)
	// return plaintext
	
	// crypto_stream_xsalsa20 requires 24 NONCEBYTES, a difererent nonce is required for each message
	// "...crypto_stream_xor with a different nonce for each message, the ciphertexts are indistinguishable 
	// from uniform random strings of the same length" https://nacl.cr.yp.to/stream.html

	if ((*certified_hw != 1 && *certified_hw != 3) || s==false) return;

	uint8_t iv2[24] = {0}; 
	memcpy(iv2,iv,12);
	uint8_t tempkey[32];

	if (function==1) { 
		// chocolate_syrup[32] (ChaCha 256)
		// has access to last 1/3 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(chocolate_syrup+(((iv2[0]+iv2[1]) % 4)*4)), 32);
		ChaCha chacha;
		uint8_t counter[8] = {0};
		chacha.clear();
		chacha.setKey(tempkey, 32);
		chacha.setIV(iv2, 8);
		chacha.setCounter(counter, 8);
		chacha.encrypt(state+(len-(len/3)), state+(len-(len/3)), len/3);
    	// whipped_cream[32]  (NACL crypto_stream_salsa20)
		// has access to first 1/3 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(whipped_cream+(((iv2[0]+iv2[1]) % 4)*4)), 32);
		crypto_stream_salsa20_xor(state,state,(len/3),iv2,tempkey); 
    	// cherry_on_top[32] (NACL crypto_stream_xsalsa20)
		// has access to middle 1/3 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(cherry_on_top+(((iv2[0]+iv2[1]) % 4)*4)), 32);
		crypto_stream_xsalsa20_xor(state+(len/3),state+(len/3),len/3,iv2,tempkey); 

	} else if (function==2) { 
		// banana[32] (ChaCha)
		// has access to first 1/2 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(banana+(((iv2[0]+iv2[1]) % 4)*4)), 32);
		ChaCha chacha;
		uint8_t counter[8] = {0};
		chacha.clear();
		chacha.setKey(tempkey, 32);
		chacha.setIV(iv2, 8);
		chacha.setCounter(counter, 8);
		chacha.encrypt(state, state, len/2);
    	// ice_cream[32] (NACL crypto_stream_salsa20)
		// has access to last 1/2 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(ice_cream+(((iv2[0]+iv2[1]) % 4)*4)), 32);
		crypto_stream_salsa20_xor(state+(len-(len/2)),state+(len-(len/2)),(len/2),iv2,tempkey); 

	} else if (function==3) { 
		// cherry_on_top[32] - (NACL crypto_stream_xsalsa20)
		// has access to middle 1/3 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(cherry_on_top+(((iv2[0]+iv2[1]) % 4)*4)), 32);			
		crypto_stream_xsalsa20_xor(state+(len/3),state+(len/3),len/3,iv2,tempkey); 	
		// whipped_cream[32] (NACL crypto_stream_salsa20)
		// has access to first 1/3 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(whipped_cream+(((iv2[0]+iv2[1]) % 4)*4)), 32);	
		crypto_stream_salsa20_xor(state,state,(len/3),iv2,tempkey); 
		// chocolate_syrup[32] (ChaCha 256)
		// has access to last 1/3 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(chocolate_syrup+(((iv2[0]+iv2[1]) % 4)*4)), 32);
		ChaCha chacha;
		uint8_t counter[8] = {0}; 
		chacha.clear();
		chacha.setKey(tempkey, 32);
		chacha.setIV(iv2, 8);
		chacha.setCounter(counter, 8);
		chacha.decrypt(state+(len-(len/3)), state+(len-(len/3)), len/3);

	} else if (function==4) { 
		// ice_cream[32](NACL crypto_stream_salsa20)
		// has access to last 1/2 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(ice_cream+(((iv2[0]+iv2[1]) % 4)*4)), 32);
		crypto_stream_salsa20_xor(state+(len-(len/2)),state+(len-(len/2)),(len/2),iv2,tempkey); 
		// banana[32] (ChaCha 256)
		// has access to first 1/2 bytes
		memcpy((uint8_t *)tempkey, (uint8_t *)(banana+(((iv2[0]+iv2[1]) % 4)*4)), 32);
		ChaCha chacha;
		uint8_t counter[8] = {0};
		chacha.clear();
		chacha.setKey(tempkey, 32);
		chacha.setIV(iv2, 8);
		chacha.setCounter(counter, 8);
		chacha.decrypt(state, state, len/2);
	}
}

/*************************************/
//ML-KEM-768 operations
//Seed stored as 32-byte ECC key with KEYTYPE_MLKEM768
/*************************************/

void okcrypto_mlkem_keygen (uint8_t *buffer) {
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	#ifdef DEBUG
	Serial.println();
	Serial.println("MLKEM KEYGEN MESSAGE RECEIVED");
	#endif
	/* NO CONFIRMATION GATE HERE, and the reason is where this can be reached
	 * from. A keygen only ever arrives through OKSETPRIV, which okcore.cpp
	 * dispatches on `configmode == true || !initcheck` - config mode, or first
	 * use. Both are presence proofs already: config mode is entered by a long
	 * press on the device and cannot be left without a reinsert, and first use
	 * is the provisioning the user is physically performing. A 3-button
	 * challenge on top of either is unanswerable anyway, because the
	 * config-mode LED owns the indicator.
	 *
	 * This used to carry `if (!CRYPTO_AUTH && !configmode) { pending; return; }`
	 * by analogy with the decaps functions. The analogy does not hold: decaps
	 * IS reachable from a normal unlocked device, so its gate is real, and this
	 * one could only ever fire during first-use provisioning - where it would
	 * have stalled setup waiting for a challenge. ECC keygen has never had one.
	 */

	// Generate 32-byte seed, store via existing ECC slot infrastructure
	// buffer[5] = slot (set by caller), buffer[6] = type, buffer[7..38] = key data
	uint8_t seed[32];
	RNG2(buffer + 7, 32);
	memcpy(seed, buffer + 7, 32); // ecc_priv_flash() below encrypts buffer+7 in place (gcm.encrypt(state,state,len)) - keep the plaintext for the expansion below
	buffer[6] = (KEYTYPE_MLKEM768 & 0x0F) | 0x20; // type with decrypt feature (bit 5)
	ecc_priv_flash(buffer, false, true); // quiet: the public key below IS the response

	// Expand seed to 64-byte coins: SHAKE256(seed, 64)
	uint8_t coins[64];
	xwing_shake256(coins, 64, seed, 32);
	memset(seed, 0, sizeof(seed));

	// Deterministic keygen
	uint8_t *sk = ctap_buffer;
	uint8_t *pk = ctap_buffer + MLKEM_SK_SIZE;
	if (crypto_kem_keypair_derand(pk, sk, coins) != 0) {
		hidprint("Error ML-KEM keygen failed");
		fadeoff(0);
		memset(coins, 0, 64);
		memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
		return;
	}
	#ifdef DEBUG
	Serial.println("ML-KEM keypair generated");
	Serial.print("PK first 16 bytes: ");
	byteprint(pk, 16);
	#endif

	pending_operation=CTAP2_ERR_DATA_READY;
	send_transport_response(pk, MLKEM_PK_SIZE, true, true);

	memset(coins, 0, 64);
	memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
	fadeoff(85);
}

void okcrypto_mlkem_decaps (uint8_t *buffer) {
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	uint8_t ss[MLKEM_SS_SIZE];
	#ifdef DEBUG
	Serial.println();
	Serial.println("MLKEM DECAPS MESSAGE RECEIVED");
	#endif
	if (!CRYPTO_AUTH) {
		process_packets(buffer, 0, 0);
		pending_operation=OKDECRYPT_ERR_USER_ACTION_PENDING;
	}
	else if (CRYPTO_AUTH == 4) {
		okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
		if (large_buffer_offset != MLKEM_CT_SIZE) {
			hidprint("Error ML-KEM CT wrong size");
			fadeoff(0);
			memset(large_buffer, 0, LARGE_BUFFER_SIZE);
			return;
		}

		// Seed already loaded into ecc_private_key by okcore_flashget_ECC in dispatch
		uint8_t coins[64];
		xwing_shake256(coins, 64, ecc_private_key, 32);

		uint8_t *sk = ctap_buffer;
		uint8_t *pk = ctap_buffer + MLKEM_SK_SIZE;
		if (crypto_kem_keypair_derand(pk, sk, coins) != 0) {
			hidprint("Error ML-KEM key expansion failed");
			memset(coins, 0, 64);
			memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
			memset(large_buffer, 0, LARGE_BUFFER_SIZE);
			fadeoff(0);
			return;
		}
		memset(coins, 0, 64);

		if (crypto_kem_dec(ss, large_buffer, sk) != 0) {
			hidprint("Error ML-KEM decaps failed");
			memset(ss, 0, sizeof(ss));
			memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
			memset(large_buffer, 0, LARGE_BUFFER_SIZE);
			fadeoff(0);
			return;
		}
		#ifdef DEBUG
		Serial.print("Shared secret: ");
		byteprint(ss, MLKEM_SS_SIZE);
		#endif

		pending_operation=CTAP2_ERR_DATA_READY;
		outputmode=packet_buffer_details[2];
		send_transport_response(ss, MLKEM_SS_SIZE, true, true);
		if (outputmode != WEBAUTHN) {
			wipetasks();
		}

		memset(ss, 0, sizeof(ss));
		memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
		memset(large_buffer, 0, LARGE_BUFFER_SIZE);
		fadeoff(85);
	} else {
		#ifdef DEBUG
		Serial.println("Waiting for challenge buttons to be pressed");
		#endif
	}
}

void okcrypto_mlkem_getpubkey (uint8_t *buffer) {
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	#ifdef DEBUG
	Serial.println();
	Serial.println("MLKEM GETPUBKEY MESSAGE RECEIVED");
	#endif

	// Seed already loaded into ecc_private_key by okcore_flashget_ECC in dispatch
	uint8_t coins[64];
	xwing_shake256(coins, 64, ecc_private_key, 32);

	uint8_t *sk = ctap_buffer;
	uint8_t *pk = ctap_buffer + MLKEM_SK_SIZE;
	/* crypto_kem_keypair_derand() is declared warn_unused_result and its return
	 * was being dropped. It cannot fail on a well-formed buffer today, so this
	 * changes nothing on the success path - but a silent failure here hands the
	 * host a public key made of whatever was in scratch, and "the key is wrong
	 * and nothing said so" is the failure mode that cost nine bugs on the
	 * derived X-Wing path. Say it out loud instead. */
	if (crypto_kem_keypair_derand(pk, sk, coins) != 0) {
		memset(coins, 0, 64);
		memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
		hidprint("Error ML-KEM keygen");
		return;
	}
	memset(coins, 0, 64);

	send_transport_response(pk, MLKEM_PK_SIZE, true, true);
	memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
}

/*************************************/
//X-Wing KEM operations (draft-connolly-cfrg-xwing-kem-09)
//Compatible with age v1.3.0 mlkem768x25519 recipient type
//Seed stored as 32-byte ECC key with KEYTYPE_XWING
//PK: pk_M(1184) || pk_X(32) = 1216 bytes
//CT: ct_M(1088) || ct_X(32) = 1120 bytes
//SS: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel) = 32 bytes
/*************************************/

void okcrypto_xwing_keygen (uint8_t *buffer) {
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	#ifdef DEBUG
	Serial.println();
	Serial.println("XWING KEYGEN MESSAGE RECEIVED");
	#endif
	/* NO CONFIRMATION GATE HERE, and the reason is where this can be reached
	 * from. A keygen only ever arrives through OKSETPRIV, which okcore.cpp
	 * dispatches on `configmode == true || !initcheck` - config mode, or first
	 * use. Both are presence proofs already: config mode is entered by a long
	 * press on the device and cannot be left without a reinsert, and first use
	 * is the provisioning the user is physically performing. A 3-button
	 * challenge on top of either is unanswerable anyway, because the
	 * config-mode LED owns the indicator.
	 *
	 * This used to carry `if (!CRYPTO_AUTH && !configmode) { pending; return; }`
	 * by analogy with the decaps functions. The analogy does not hold: decaps
	 * IS reachable from a normal unlocked device, so its gate is real, and this
	 * one could only ever fire during first-use provisioning - where it would
	 * have stalled setup waiting for a challenge. ECC keygen has never had one.
	 */

	// Generate 32-byte seed, store via existing ECC slot infrastructure
	uint8_t seed[XWING_SEED_SIZE];
	RNG2(buffer + 7, XWING_SEED_SIZE);
	memcpy(seed, buffer + 7, XWING_SEED_SIZE); // ecc_priv_flash() below encrypts buffer+7 in place (gcm.encrypt(state,state,len)) - keep the plaintext for the expansion below
	buffer[6] = (KEYTYPE_XWING & 0x0F) | 0x20; // type with decrypt feature (bit 5)
	ecc_priv_flash(buffer, false, true); // quiet: the public key below IS the response

	// Expand seed: SHAKE256(seed, 96)
	uint8_t expanded[96];
	xwing_shake256(expanded, 96, seed, XWING_SEED_SIZE);
	memset(seed, 0, sizeof(seed));

	// ML-KEM-768 deterministic keygen from expanded[0:64]
	uint8_t *sk_M = ctap_buffer;
	uint8_t *pk_M = ctap_buffer + MLKEM_SK_SIZE;
	if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) != 0) {
		hidprint("Error X-Wing ML-KEM keygen failed");
		fadeoff(0);
		memset(expanded, 0, 96);
		memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
		return;
	}

	// X25519: pk_X = X25519(expanded[64:96], BASE)
	uint8_t pk_X[32];
	crypto_scalarmult_base(pk_X, expanded + 64);

	// Build PK: pk_M(1184) || pk_X(32)
	memcpy(pk_M + MLKEM_PK_SIZE, pk_X, 32);

	#ifdef DEBUG
	Serial.println("X-Wing keypair generated");
	Serial.print("PK_M first 16: ");
	byteprint(pk_M, 16);
	Serial.print("PK_X: ");
	byteprint(pk_X, 32);
	#endif

	pending_operation=CTAP2_ERR_DATA_READY;
	send_transport_response(pk_M, XWING_PK_SIZE, true, true);

	memset(expanded, 0, 96);
	memset(pk_X, 0, 32);
	memset(ctap_buffer, 0, MLKEM_SK_SIZE + XWING_PK_SIZE);
	fadeoff(85);
}

void okcrypto_xwing_decaps (uint8_t *buffer) {
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	uint8_t ss_M[32];
	uint8_t ss_X[32];
	uint8_t ss[XWING_SS_SIZE];
	#ifdef DEBUG
	Serial.println();
	Serial.println("XWING DECAPS MESSAGE RECEIVED");
	#endif
	if (!CRYPTO_AUTH) {
		process_packets(buffer, 0, 0);
		pending_operation=OKDECRYPT_ERR_USER_ACTION_PENDING;
	}
	else if (CRYPTO_AUTH == 4) {
		okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
		if (large_buffer_offset != XWING_CT_SIZE) {
			hidprint("Error X-Wing CT wrong size");
			fadeoff(0);
			memset(large_buffer, 0, LARGE_BUFFER_SIZE);
			return;
		}

		uint8_t *ct_M = large_buffer;
		uint8_t *ct_X = large_buffer + MLKEM_CT_SIZE;

		// Seed already loaded into ecc_private_key by okcore_flashget_ECC in dispatch
		uint8_t expanded[96];
		xwing_shake256(expanded, 96, ecc_private_key, XWING_SEED_SIZE);

		// Reconstruct ML-KEM keypair from expanded[0:64]
		uint8_t *sk_M = ctap_buffer;
		uint8_t *pk_M = ctap_buffer + MLKEM_SK_SIZE;
		if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) != 0) {
			hidprint("Error X-Wing key expansion failed");
			memset(expanded, 0, 96);
			memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
			memset(large_buffer, 0, LARGE_BUFFER_SIZE);
			fadeoff(0);
			return;
		}

		// X25519 keys from expanded[64:96]
		uint8_t *sk_X = expanded + 64;
		uint8_t pk_X[32];
		crypto_scalarmult_base(pk_X, sk_X);

		// ML-KEM-768 decapsulation
		if (crypto_kem_dec(ss_M, ct_M, sk_M) != 0) {
			hidprint("Error X-Wing ML-KEM decaps failed");
			memset(ss_M, 0, 32);
			memset(expanded, 0, 96);
			memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
			memset(large_buffer, 0, LARGE_BUFFER_SIZE);
			fadeoff(0);
			return;
		}

		// X25519 ECDH: ss_X = X25519(sk_X, ct_X)
		crypto_scalarmult(ss_X, sk_X, ct_X);

		// X-Wing Combiner
		xwing_combiner(ss, ss_M, ss_X, ct_X, pk_X);

		#ifdef DEBUG
		Serial.print("ss_M: "); byteprint(ss_M, 32);
		Serial.print("ss_X: "); byteprint(ss_X, 32);
		Serial.print("X-Wing SS: "); byteprint(ss, XWING_SS_SIZE);
		#endif

		pending_operation=CTAP2_ERR_DATA_READY;
		outputmode=packet_buffer_details[2];
		send_transport_response(ss, XWING_SS_SIZE, true, true);
		if (outputmode != WEBAUTHN) {
			wipetasks();
		}

		memset(ss_M, 0, 32);
		memset(ss_X, 0, 32);
		memset(ss, 0, XWING_SS_SIZE);
		memset(expanded, 0, 96);
		memset(pk_X, 0, 32);
		memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
		memset(large_buffer, 0, LARGE_BUFFER_SIZE);
		fadeoff(85);
	} else {
		#ifdef DEBUG
		Serial.println("Waiting for challenge buttons to be pressed");
		#endif
	}
}

void okcrypto_xwing_getpubkey (uint8_t *buffer) {
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
	#ifdef DEBUG
	Serial.println();
	Serial.println("XWING GETPUBKEY MESSAGE RECEIVED");
	#endif

	// Seed already loaded into ecc_private_key by okcore_flashget_ECC in dispatch
	uint8_t expanded[96];
	xwing_shake256(expanded, 96, ecc_private_key, XWING_SEED_SIZE);

	uint8_t *sk_M = ctap_buffer;
	uint8_t *pk_M = ctap_buffer + MLKEM_SK_SIZE;
	/* crypto_kem_keypair_derand() is declared warn_unused_result and its return
	 * was being dropped. It cannot fail on a well-formed buffer today, so this
	 * changes nothing on the success path - but a silent failure here hands the
	 * host a public key made of whatever was in scratch, and "the key is wrong
	 * and nothing said so" is the failure mode that cost nine bugs on the
	 * derived X-Wing path. Say it out loud instead. */
	if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) != 0) {
		memset(expanded, 0, 96);
		memset(ctap_buffer, 0, MLKEM_SK_SIZE + XWING_PK_SIZE);
		hidprint("Error ML-KEM keygen");
		return;
	}

	uint8_t pk_X[32];
	crypto_scalarmult_base(pk_X, expanded + 64);

	memcpy(pk_M + MLKEM_PK_SIZE, pk_X, 32);

	send_transport_response(pk_M, XWING_PK_SIZE, true, true);

	memset(expanded, 0, 96);
	memset(pk_X, 0, 32);
	memset(ctap_buffer, 0, MLKEM_SK_SIZE + XWING_PK_SIZE);
}

void okcrypto_compute_pubkey() {
	memset(ecc_public_key, 0, sizeof(ecc_public_key));

	// PQ key types store seeds, not traditional ECC keys — pubkey is
	// derived on demand via SHAKE256 expansion, not from ecc_private_key
	if (type == KEYTYPE_MLKEM768 || type == KEYTYPE_XWING) return;

	if (type == KEYTYPE_ED25519) {
		Ed25519::derivePublicKey(ecc_public_key, ecc_private_key);
	}
	else if (type == KEYTYPE_P256R1)
	{
		const struct uECC_Curve_t *curve = uECC_secp256r1();
		uECC_compute_public_key(ecc_private_key, ecc_public_key, curve);
	}
	else if (type == KEYTYPE_P256K1)
	{
		const struct uECC_Curve_t *curve = uECC_secp256k1();
		uECC_compute_public_key(ecc_private_key, ecc_public_key, curve);
	}
	else if (type == KEYTYPE_CURVE25519)
	{
		swap_buffer (0, 31, ecc_private_key);
		Curve25519::eval(ecc_public_key, ecc_private_key, 0);
	}
	#ifdef DEBUG
	Serial.println("Computed Public");
	byteprint(ecc_public_key, sizeof(ecc_public_key));
	#endif
}

void swap_buffer (uint8_t start, uint8_t end, uint8_t * buffer) {
	// Swap buffer
	// http://gnupg.10057.n7.nabble.com/Correct-method-to-generate-a-Curve25519-keypair-td56013.html
	uint8_t tmp;
	while (start < end) {
		tmp = buffer[start];
		buffer[start] = buffer[end];
		buffer[end] = tmp;
		start++; 
		end--; 
	}
}

#endif
