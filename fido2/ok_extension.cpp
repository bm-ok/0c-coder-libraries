/* Tim Steiner
 * Copyright (c) 2015-2018, CryptoTrust LLC.
 * All rights reserved.
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
 *    the OnlyKey Project (http://www.crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "OnlyKey Project" must not be used to
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
 *    the OnlyKey Project (http://www.crp.to/ok)"
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

#include "device.h"
#include "onlykey.h"
#ifdef STD_VERSION
#include "log.h"
#include "wallet.h"
//#include APP_CONFIG
#include "util.h"
#include "storage.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "crypto.h"
#include "u2f.h"
#include "extensions.h"
#include "ok_extension.h"

// Functions for use with derived key (RESERVED_KEY_WEB_AGENT_DERIVATION)
#define DERIVE_PUBLIC_KEY 1
#define DERIVE_SHAREDSEC 2
// 3 and 4 were DERIVE_PUBLIC_KEY_REQ_PRESS / DERIVE_SHAREDSEC_REQ_PRESS.
// Removed, and the numbers are left burned rather than reused: an old client
// still sending them must fail loudly, not be silently reinterpreted.
//
// They stopped meaning what their names said. Presence is now decided by what
// is asked for (public key: never a touch; shared secret: always one), so the
// only thing the suffix still selected was a SECOND KEY DOMAIN, via
// additional_data[0] = 1 in the HKDF salt - two different keys per label,
// picked by an opcode whose name was about touches. Nothing wants that: it
// doubles the key space for no stated purpose and it is a trap for anyone
// reading the callers, as vault.js proves - it fetched its public key in one
// domain and did its ECDH in the other, believing it was only choosing whether
// a touch was required.
#define DERIVE_OPCODE_MAX DERIVE_SHAREDSEC
// Option to encrypt response for end-to-end data in-transit encryption
#define NO_ENCRYPT_RESP 0
#define ENCRYPT_RESP 1

extern uint8_t* large_resp_buffer;
extern int large_resp_buffer_offset;
extern int large_resp_buffer_cursor;
extern uint8_t large_resp_buffer_last_opt3;
// Max bytes of large_resp_buffer served per WebAuthn round trip.
//
// The destination is ctap.cpp's sigder[514]: extend_fido2() puts a status byte
// at sigder[0] and the payload from sigder+1, and ctap_end_get_assertion()
// requires sigder_sz (= payload + 1) to be strictly less than sizeof(sigder).
// So the largest payload that survives is 512, not 513 - at 513 the size test
// fails and the response silently drops to the 72-byte default.
//
// 512 is also exactly an RSA-4096 signature, which keeps the classic PGP path
// single-shot. That matters because that path cannot reassemble: onlykey-pgp.js's
// doPinTimer() resolves on the first poll returning an array. Only responses
// genuinely larger than one assertion (ML-DSA-65's 3309 bytes) chunk, and only
// callers that accumulate should ask for them.
#define MAX_LARGE_RESP_CHUNK 512
extern uint8_t profilemode;
extern uint8_t isfade;
extern uint8_t NEO_Color;
extern uint8_t type;
extern uint8_t CRYPTO_AUTH;
extern int outputmode;
extern uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE*2)+1];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
extern uint8_t recv_buffer[64];
extern uint8_t pending_operation;
extern int packet_buffer_offset;
extern uint8_t packet_buffer_details[5];

// ---- Web and agent derived key user input (web_agent_derive_mode, OKSETSLOT 30) ----
// The setting decides how the user authorises a shared-secret derive: 0 = the
// 3-digit challenge code, 1 = button press (default), 2 = none. The key never
// depends on it. A REQ_PRESS request variant can only RAISE the requirement to
// a press (a page asking for presence gets it; a hostile page cannot lower the
// setting). Challenge code = SHA-256 over the request bytes the device hashes -
// the 32-byte label hash then the 32/64-byte ct_X / input public key - bytes
// 0/15/31 mod 6 (mod 3 on a DUO) plus one; the web app computes and shows it.
// Public-key derives are never gated.
static int web_agent_derive_gate(uint8_t floor_mode, const uint8_t *data, int len)
{
	extern uint8_t onlykeyhw;
	uint8_t need = okcore_web_agent_derive_mode();
	// floor_mode is the weakest confirmation this CALL SITE will accept,
	// independent of the user setting. It replaces the old REQ_PRESS opcode
	// variants, which let the REQUEST raise the requirement: those opcodes are
	// gone (one label, one key), and a per-request knob was the wrong shape
	// anyway - a page asking politely for a prompt is not a security control.
	//
	// Every call site currently passes USER_INPUT_NONE, i.e. the user setting
	// decides outright. The parameter stays because a future operation may
	// genuinely need a floor, and because a call site that wants one should
	// have to say so rather than inherit it.
	if (need == USER_INPUT_NONE && floor_mode != USER_INPUT_NONE) need = floor_mode;
	if (need == USER_INPUT_NONE) return 0;
	int but;
	device_set_status(CTAPHID_STATUS_UPNEEDED);
	if (need == USER_INPUT_PRESS) {
		but = ctap_user_presence_test(CTAP2_UP_DELAY_MS);
	} else {
		uint8_t h[32];
		SHA256_CTX c;
		sha256_init(&c);
		sha256_update(&c, (uint8_t *)data, len);
		sha256_final(&c, h);
		uint8_t m = (onlykeyhw == OK_HW_DUO) ? 3 : 6;
		but = ctap_challenge_test(CTAP2_UP_DELAY_MS, (h[0] % m) + 1, (h[15] % m) + 1, (h[31] % m) + 1);
		memset(h, 0, 32);
	}
	if (but == -2) { pending_operation = 0; return CTAP2_ERR_OPERATION_DENIED; }
	if (but > 1) return CTAP2_ERR_PROCESSING;
	if (but < 0) return CTAP2_ERR_KEEPALIVE_CANCEL;
	if (but == 0) { pending_operation = 0; return CTAP2_ERR_ACTION_TIMEOUT; }
	return 0;
}
uint8_t transit_key[32];

// Duplicate-packet suppression high-water mark for inbound OKDECRYPT/OKSIGN
// requests (the Windows 10 1903 double-fire guard).
//
// This used to be kept in packet_buffer_details[3] - which okcore.cpp's
// process_packets() overwrites with TWO RANDOM BYTES the moment a message
// completes:
//
//     RNG2(packet_buffer_details + 3, 2);   // response channel id
//
// Two unrelated meanings on one byte, and the random one wins. The next
// multi-chunk request then arrives against a random 0-255 threshold, so its
// early chunks fail `opt3 <= last` and are dropped SILENTLY - no error, no
// print. The device accumulates only the chunks that happened to exceed the
// random byte, hashes that short buffer, and asks for challenge digits
// computed over bytes the host never sent.
//
// Measured 2026-08-01: a 1088-byte ML-KEM-768 ciphertext sent as five
// 228-byte chunks arrived as its final 176-byte chunk ALONE (1088 - 4*228),
// confirmed by the "Received Message" byteprint, and every confirmation
// failed with "Error incorrect challenge was entered".
//
// This affects the classic RSA path identically - any payload needing more
// than one keyhandle. It goes unnoticed there because wipetasks() zeroes the
// byte on a 5s timer, and a human operating the web app usually takes longer
// than that between operations; a scripted caller does not.
static uint8_t last_request_opt3 = 0;


/* Bytes of `keyh` consumed by the OnlyKey request header before the payload:
 * cmd, opt1, opt2, opt3, then the 4-byte wallet tag and 2 more. */
#define OK_KEYHANDLE_HEADER_LEN 10

int16_t bridge_to_onlykey(uint8_t * _appid, uint8_t * keyh, int handle_len, uint8_t * output) {
    int8_t ret = 0;
	uint8_t client_handle[256];

	/* handle_len is the length of an attacker-supplied WebAuthn credential id,
	 * and it arrives here BEFORE any origin or unlock check - the webcryptcheck()
	 * gate is 20 lines below. Unchecked, `handle_len -= 10` on a shorter id went
	 * negative and the memcpy below took it as a size_t: an unbounded write into
	 * a 256-byte stack frame, on a part with no MMU and no stack canary, from any
	 * web page with no PIN and no trusted origin.
	 *
	 * It was reachable because the size gate and the size USED were different
	 * numbers. ctap_get_assertion()/ctap_filter_invalid_credentials() decide a
	 * custom credential is an extension request by calling is_extension_request()
	 * with the CONSTANT sizeof(CredentialId) (68), which trivially clears its
	 * `len < WALLET_MIN_LENGTH` guard, while what gets passed here as handle_len
	 * is the real getAssertionState.customCredIdSize. A 9-byte id sails through
	 * the first and underflows the second. (customCredIdSize is a uint8_t, so a
	 * 256-byte id truncating to 0 underflows the same way.)
	 *
	 * Check the length actually being used, at the point it is used, rather than
	 * relying on a caller's separate opinion of it. The U2F sibling path already
	 * gates on the real key-handle length; this is the FIDO2 path catching up. */
	if (handle_len < OK_KEYHANDLE_HEADER_LEN || handle_len > (int)sizeof(client_handle)) {
		#ifdef DEBUG
		Serial.print("Rejecting keyhandle of length ");
		Serial.println(handle_len, DEC);
		#endif
		return 0;
	}
	handle_len-=OK_KEYHANDLE_HEADER_LEN;
	uint8_t cmd = keyh[0];
	uint8_t opt1 = keyh[1]; 
	uint8_t opt2 = keyh[2];
	uint8_t opt3 = keyh[3];
	uint8_t browser;
	uint8_t os;
	uint8_t temp[256];
	uint8_t pubsize;
	extern uint8_t derived_key_challenge_mode;

	memcpy(client_handle, keyh+OK_KEYHANDLE_HEADER_LEN, handle_len);
		
	#ifdef DEBUG
    Serial.println("Keyhandle:");
    byteprint(client_handle, handle_len);
	#endif

    // 0 = refuse, 1 = derived keys only, 2 = also stored-slot OKDECRYPT/OKSIGN
    // (PGP). Evaluated once: it reads an EEPROM byte and the RPID out of
    // ctap_buffer, and calling it twice invited the two answers to disagree.
    const int wc_level = webcryptcheck(_appid, client_handle);
    if (wc_level) {
      	outputmode=DISCARD; // Discard output 
		if (cmd == OKCONNECT && !CRYPTO_AUTH) {
			large_buffer_offset = 0;
			// Set time if not already set
			set_time(client_handle);
			memset(ecc_public_key, 0, sizeof(ecc_public_key));
			// Generate a random NACL key that we will use for data in transit encryption OnlyKey <--> Web App
			// This is optional and enabled by ENCRYPT_RESP
			// crypto_box_keypair uses RNG2 to create random 32 byte private
			// crypto_box_keypair puts generated private in ecc_private_key and public in ecc_public_key along with OnlyKey version info
			crypto_box_keypair(ecc_public_key, ecc_private_key); //Generate keys
			#ifdef DEBUG
			Serial.println("OnlyKey public = ");
			byteprint(ecc_public_key, 32);
			#endif
			memcpy(ecc_public_key+32, HW_MODEL(UNLOCKED), sizeof(UNLOCKED)+1);
			// Response goes out via WEBAUTHN
			outputmode=WEBAUTHN;
			memcpy(temp, ecc_public_key, sizeof(ecc_public_key)); //Store OnlyKey public NACL transit key (includes OnlyKey version info)
			memcpy(ecc_public_key, client_handle+9, 32); //Get app public NACL transit key
			browser = client_handle[9+32];
			os = client_handle[9+32+1];
			#ifdef DEBUG
			Serial.println("App public = ");
			byteprint(ecc_public_key, 32);
			Serial.print("Browser = ");
			Serial.println((char)browser);
			Serial.print("OS = ");
			Serial.println((char)os);
			#endif
			//NACL for transit encryption, this setting isn't currently user configurable
			type = 1; 
			if (okcrypto_shared_secret (ecc_public_key, transit_key)) {
				ret = CTAP2_ERR_OPERATION_DENIED;
				printf2(TAG_ERR,"Error with ECC Shared Secret\n");
				return ret;
			}
			#ifdef DEBUG
			Serial.println("Transit Shared Secret = ");
			byteprint(transit_key, 32);
			#endif
			// Hash the shared secret to generate the AES transit private key
			SHA256_CTX context;
			sha256_init(&context);
			sha256_update(&context, transit_key, 32);
			sha256_final(&context, transit_key);
			#ifdef DEBUG
			Serial.println("Transit AES Key = ");
			byteprint(transit_key, 32);
			#endif
			pending_operation=CTAP2_ERR_DATA_READY;
			// OnlyKey Private Web (beta)
			// This is a simple way of providing web apps with a shared secret
			// for use in encryption/signing. This shared secret is derived
			// based on input public key, domain (origin) and allowing  
			// additional data as input to private derivation (HKDF). Key types supported 
			// include NACL, P256R1, P256K1, and Curve25519. No user presence is 
			// required making this useful for encrypted/private web pages that may
			// be decrypted and viewed only when OnlyKey is connected and unlocked.
			if (opt1>=DERIVE_PUBLIC_KEY) {
				if (opt1 > DERIVE_OPCODE_MAX) {
					// Was 3 or 4 (the removed REQ_PRESS pair), or garbage.
					// Refuse rather than fall through: without this check an
					// opt1 of 4 would miss every `opt1==DERIVE_SHAREDSEC` test
					// below and be served as a PUBLIC KEY request, answering a
					// shared-secret call with a public key and no error.
					ret = CTAP2_ERR_EXTENSION_NOT_SUPPORTED;
					wipedata();
					return ret;
				}
				if (opt3) opt3=2; // 1=encrypt everything, 2=encrypt everything except transit public so app can derive shared secret
				uint8_t *input_pubkey = client_handle+43+32; // Use uncompressed ecc pubkeys, could use compressed in future
				// additional_data[0] is now always 0. It used to be 1 for the
				// REQ_PRESS opcodes, which made them a second key domain; see
				// the note by the opcode defines. One label, one key.
				uint8_t additional_data[33] = {0};
				// The touch-free opt-in (derived_key_challenge_mode bit 3) is
				// GONE. It used to gate the non-REQ_PRESS opcodes: without it
				// they were refused outright with
				// CTAP2_ERR_EXTENSION_NOT_SUPPORTED. Two things were wrong with
				// that.
				//
				// It did not do what its name said. "REQ_PRESS" on a PUBLIC KEY
				// derivation never asked for a press - it only selected a
				// different key - so a caller could always get a touch-free
				// public-key derivation by sending opcode 3, bit 3 or no bit 3.
				// The only real presence test was on the shared-secret variant.
				//
				// And it made the shipped web app depend on a non-default
				// setting: password-generator.js passes press_required=false for
				// BOTH calls and vault.js passes false for the public-key step,
				// so on a factory-default key (bit 3 clear) those features were
				// refused outright rather than prompting for a tap.
				//
				// Presence is now decided by WHAT is being asked for, not by
				// which opcode the caller picked or what the user configured:
				//
				//   public key   - no touch. It is public data, and the caller
				//                  cannot turn that into a secret.
				//   shared secret - ALWAYS a touch, both opcodes, no opt-out.
				//                  This is a decryption capability.
				//
				// That makes touch-free decapsulation unreachable by any
				// setting, and incidentally fixes the password generator and the
				// vault on default devices.
				memcpy(additional_data+1, client_handle+43, 32); // 32 bytes of data to include in key derivation
				opt2++;
				memset(ecc_public_key, 0, sizeof(ecc_public_key));

				// ---- X-Wing (mlkem768x25519), derived -----------------------
				// Wire keytype 5 -> opt2 == KEYTYPE_XWING(6) (opt2++ above).
				//
				// DERIVE_PUBLIC_KEY returns the full public recipient
				//   [ pk_M(1184) | pk_X(32) ] = XWING_PK_SIZE
				// staged into large_resp_buffer and retrieved in
				// MAX_LARGE_RESP_CHUNK pieces by send_stored_response() - the
				// same chunked path that already carries a 3309-byte ML-DSA-65
				// composite signature. It does NOT fit in temp[256], which is
				// why the payload is built in large_resp_buffer directly.
				//
				// It used to return [ pk_X(32) | mlkem_seed(32) ] and let the
				// host expand the seed. mlkem_seed is private key material
				// (it yields sk_M), so that handed out a private key in answer
				// to a request for a public one. ML-KEM has no short public
				// key - the only 32-byte value reproducing pk_M also reproduces
				// sk_M - so the public key itself has to be what is sent.
				//
				// DERIVE_SHAREDSEC is NO LONGER served here. Decapsulation now
				// needs the whole 1120-byte X-Wing ciphertext on the device
				// (ct_M included), which does not fit this single-shot
				// client_handle path. The browser sends it as a chunked
				// OKDECRYPT to slot RESERVED_KEY_WEB_AGENT_DERIVATION carrying
				// [ label32 | ct(1120) ], the same tunnel composite_decrypt
				// already uses; okcrypto_decrypt() handles it there.
				if (opt2 == KEYTYPE_XWING) {
					uint8_t *label32 = client_handle + 43;
					if (opt1 == DERIVE_SHAREDSEC) {
						hidprint("Error use OKDECRYPT for derived X-Wing decapsulation");
						ret = send_stored_response(output, opt3);
						return ret;
					}
					const int hdr = 32 + sizeof(UNLOCKED) + 1;
					memmove(large_resp_buffer, temp, hdr);   /* transit pubkey + status */
					#ifdef DEBUG
					Serial.print("XWING derive start ms=");
					Serial.println(millis());
					#endif
					okcrypto_xwing_derive_getpubkey(label32, large_resp_buffer + hdr);
					#ifdef DEBUG
					Serial.print("XWING derive done ms=");
					Serial.print(millis());
					Serial.print(" hdr=");
					Serial.print(hdr);
					Serial.print(" total=");
					Serial.println(hdr + XWING_PK_SIZE);
					#endif
					send_transport_response(large_resp_buffer, hdr + XWING_PK_SIZE, opt3, false);
					ret = send_stored_response(output, opt3);
					#ifdef DEBUG
					Serial.print("XWING derive ret=");
					Serial.print(ret);
					Serial.print(" staged=");
					Serial.print(large_resp_buffer_offset);
					Serial.print(" cursor=");
					Serial.println(large_resp_buffer_cursor);
					#endif
					return ret;
				}

				//Similar format to SSH derivation but use RESERVED_KEY_WEB_AGENT_DERIVATION key
				if (opt2 == KEYTYPE_NACL || opt2 == KEYTYPE_CURVE25519) {
					okcrypto_derive_key(KEYTYPE_CURVE25519, additional_data, RESERVED_KEY_WEB_AGENT_DERIVATION); //Curve25519
					pubsize=32;
				}
				else if (opt2 == KEYTYPE_P256R1) {
					okcrypto_derive_key(KEYTYPE_P256R1, additional_data, RESERVED_KEY_WEB_AGENT_DERIVATION);
					memmove(ecc_public_key+1, ecc_public_key, 64);
					ecc_public_key[0] = 4;
					pubsize=65;
				}
				else if (opt2 == KEYTYPE_P256K1) {
					okcrypto_derive_key(KEYTYPE_P256K1, additional_data, RESERVED_KEY_WEB_AGENT_DERIVATION);
					memmove(ecc_public_key+1, ecc_public_key, 64);
					ecc_public_key[0] = 4;
					pubsize=65;
				} 

				// Derived private key stored in ecc_private_key
				// Derived public key stored in ecc_public_key

				memcpy(temp+32+sizeof(UNLOCKED)+1, ecc_public_key, pubsize); // Copy derived public key to temp

				#ifdef DEBUG
				Serial.println("Returned Public");
				byteprint(ecc_public_key, pubsize);
				Serial.println("Derived Private");
				byteprint(ecc_private_key, sizeof(ecc_private_key));
				#endif

				if (opt1==DERIVE_SHAREDSEC) { // Return DERIVE_PUBLIC_KEY and DERIVE_SHAREDSEC
					#ifdef DEBUG
					Serial.println("Input Pubkey");
					byteprint(input_pubkey, pubsize);
					#endif
					if (os == 'W' && packet_buffer_details[3] == 'W') {
						// Already generated shared secret, Windows duplicate request
						packet_buffer_details[3] = 0; 
						ret = send_stored_response(output, opt3);
						return ret;
					}
					else { 
						// Generate Shared Secret. The user's web-derive input
						// mode (field 30) decides this outright, including
						// USER_INPUT_NONE: an unattended agent using an SSH key
						// from that slot has to be able to run
						// without a prompt, and that is the whole point of the
						// setting. Default is a button press and no-touch is a
						// deliberate opt-in, made in config mode.
						//
						// An earlier revision floored this at a press on the
						// reasoning that a shared secret is a decryption
						// capability. It is - but the floor made the setting a
						// lie, and the unattended-agent case is exactly what
						// field 30 exists for. Note the consequence plainly: with
						// field 30 set to 2, any request from a trusted origin
						// derives and decapsulates silently for as long as the
						// key is unlocked. That is the bargain the setting makes,
						// and it is why it is off by default and why it takes
						// config mode to change.
						//
						// Public-key derivation is ungated regardless: it is
						// public data and the caller cannot turn it into a
						// secret.
						{
							int g = web_agent_derive_gate(USER_INPUT_NONE, client_handle + 43, 32 + pubsize);
							if (g) return g;
							if (os == 'W') packet_buffer_details[3] = 'W';
						}
						// Use ecc_private_key and provided pubkey to generate shared secret
						if (okcrypto_shared_secret (input_pubkey, temp+32+sizeof(UNLOCKED)+1+pubsize)) { // Generate derived key shared secret in temp
							ret = CTAP2_ERR_OPERATION_DENIED;
							printf2(TAG_ERR,"Error with ECC Shared Secret\n");
							return ret;
						}
						#ifdef DEBUG
						Serial.println("Shared Secret");
						byteprint(temp+32+sizeof(UNLOCKED)+1+pubsize, 32);
						#endif
						send_transport_response(temp, 32+sizeof(UNLOCKED)+1+pubsize+sizeof(ecc_private_key), opt3, false); // Encrypt data in trasit using transit key if opt3 and send right away
						ret = send_stored_response(output, opt3);
						return ret;
					}
				} else { // Just Return DERIVE_PUBLIC_KEY
					send_transport_response(temp, 32+sizeof(UNLOCKED)+1+pubsize, opt3, false); //Encrypt if opt3 and send right away
					ret = send_stored_response(output, opt3);
					return ret;
				}
			} else {
				send_transport_response (temp, 32+sizeof(UNLOCKED)+1, opt3, false); //Encrypt if opt3 and send right away
			}
		} else if (wc_level) {  // Protected mode, only allow crp.to and localhost
			//Todo add localhost support
			okcrypto_aes_crypto_box (client_handle, handle_len, true);
			#ifdef DEBUG
			Serial.println("Decrypted client handle");
			byteprint(client_handle, handle_len);
			Serial.println("Received FIDO2 request to send data to OnlyKey");
			#endif

			if (cmd == OKPING) { //Ping
				outputmode=WEBAUTHN;
				if(!CRYPTO_AUTH && !large_resp_buffer_offset) {
					#ifdef DEBUG
					Serial.println("Error incorrect challenge was entered");
					#endif
					hidprint("Error incorrect challenge was entered");
				} else {
					#ifdef DEBUG
					Serial.println("Sending stored data from ping request");
					#endif
				}
			}
			// Break the FIDO message into packets
			else if (!CRYPTO_AUTH) {
				// opt1 is the SLOT for these commands. A derived-key request
				// (RESERVED_KEY_WEB_AGENT_DERIVATION) is allowed at level 1 - it is
				// the derived X-Wing decapsulation path, which is chunked and
				// so cannot use the single-shot OKCONNECT route. Anything
				// naming a real slot is a stored-key operation (PGP and
				// friends) and needs level 2, i.e. the user opting in with
				// OKWC_ALLOW_STORED_KEY in field 31. Without this check,
				// disabling PGP over FIDO2
				// would also disable derived decapsulation, since both arrive
				// as OKDECRYPT.
				//
				// OKPING is deliberately NOT gated: it is how a large response
				// is retrieved in MAX_LARGE_RESP_CHUNK pieces, and the derived
				// recipient is 1216 bytes, so level 1 needs it.
				if (wc_level < 2 && opt1 != RESERVED_KEY_WEB_AGENT_DERIVATION) {
					#ifdef DEBUG
					Serial.println("Stored-key operations over FIDO2 are disabled");
					#endif
					hidprint("Error stored key use over FIDO2 not enabled");
					ret = send_stored_response(output, opt3);
					return ret;
				}
				int i=0;
				if (!last_request_opt3) last_request_opt3 = opt3; // first packet
				else if (opt3 <= last_request_opt3) return 0; // duplicate packet, thanks to win 10 1903 sending all FIDO2 messages twice

				while(handle_len>0) { // Max size packet minus header
					memset(recv_buffer, 0, sizeof(recv_buffer));
					if (handle_len>=57) memmove(recv_buffer+7, client_handle+(i*57), 57);
					else memmove(recv_buffer+7, client_handle+(i*57), handle_len);
					memset(recv_buffer, 0xFF, 4);
					recv_buffer[4] = cmd;
					recv_buffer[5] = opt1; //slot
					recv_buffer[6] = 0xFF;
					if (opt2 && handle_len<=57) recv_buffer[6] = handle_len; // last packet
					if (cmd == OKDECRYPT) {
						last_request_opt3 = opt3;
						NEO_Color = 128; //Turquoise
						large_buffer_offset = 0;
						outputmode=WEBAUTHN;
						#ifdef DEBUG
						Serial.println("OKDECRYPT Chunk");
						byteprint(recv_buffer, 64);
						#endif
						okcrypto_decrypt(recv_buffer);
					} else if (cmd == OKSIGN) {
						last_request_opt3 = opt3;
						NEO_Color = 213; //Purple
						large_buffer_offset = 0;
						outputmode=WEBAUTHN;
						#ifdef DEBUG
						Serial.println("OKSIGN Chunk");
						byteprint(recv_buffer, 64);
						#endif
						okcrypto_sign(recv_buffer);
					}
					handle_len-=57;
					i++;
				}
				// opt2 marked this the final chunk, so the message is complete
				// and the next one must start from a clean high-water mark.
				if (opt2) last_request_opt3 = 0;
				ret = 0;
				}
		}
		ret = send_stored_response(output, opt3);
		return ret;
			
		//if (!isfade) fadeon(NEO_Color);
	} 

    ret = CTAP2_ERR_EXTENSION_NOT_SUPPORTED; //APPID doesn't match
    wipedata();
    return ret;
}

int16_t send_stored_response(uint8_t * output, uint8_t opt3) {
  int16_t ret = 0;
	if(profilemode!=NONENCRYPTEDPROFILE) {
		#ifdef DEBUG
		Serial.print("Sending data on OnlyKey via Webauthn ");
		Serial.println(large_resp_buffer_offset);
		#endif
		#ifdef DEBUG_BULK_DUMPS
		byteprint(large_resp_buffer, large_resp_buffer_offset);
		#endif
    // Check if large response is ready
		if (pending_operation==CTAP2_ERR_OPERATION_PENDING) {
			#ifdef DEBUG
			Serial.print("CTAP2_ERR_OPERATION_PENDING");
			#endif
			ret = CTAP2_ERR_OPERATION_PENDING;
		} else if (large_resp_buffer_offset) {
			// Chunked retrieval: large_resp_buffer_offset can exceed what one
			// WebAuthn assertion carries (a 3309 B ML-DSA-65 signature vs.
			// ~513 B usable), so a full response may take several OKPING
			// polls. large_resp_buffer_cursor tracks what has been delivered.
			//
			// A non-zero opt3 that is <= large_resp_buffer_last_opt3 means this
			// poll duplicates the one just answered (the Windows 10 1903
			// double-fire this file guards against elsewhere via
			// packet_buffer_details[3]) - re-serve the same bytes rather than
			// advancing, or a duplicate silently skips a chunk and corrupts the
			// reassembled response.
			//
			// opt3 == 0 carries no sequence information and must never be read
			// as a duplicate: poll_for_response() in the web app sends OKPING
			// with opt3 = 0, while the request that filled the buffer (e.g.
			// DERIVE_PUBLIC_KEY) sets last_opt3 = 1. Treating those polls as
			// duplicates re-served chunk 1 forever and the cursor never moved.
			int is_duplicate = opt3 && large_resp_buffer_last_opt3 && opt3 <= large_resp_buffer_last_opt3;
			int chunk_start = is_duplicate
				? (large_resp_buffer_cursor > MAX_LARGE_RESP_CHUNK ? large_resp_buffer_cursor - MAX_LARGE_RESP_CHUNK : 0)
				: large_resp_buffer_cursor;
			int remaining = large_resp_buffer_offset - chunk_start;
			int chunk_len = remaining > MAX_LARGE_RESP_CHUNK ? MAX_LARGE_RESP_CHUNK : remaining;
			#ifdef DEBUG
			Serial.print("chunk opt3=");
			Serial.print(opt3);
			Serial.print(" last=");
			Serial.print(large_resp_buffer_last_opt3);
			Serial.print(" dup=");
			Serial.print(is_duplicate);
			Serial.print(" start=");
			Serial.print(chunk_start);
			Serial.print(" len=");
			Serial.print(chunk_len);
			Serial.print(" of=");
			Serial.println(large_resp_buffer_offset);
			#endif
			extension_writeback_init(output, chunk_len);
			extension_writeback(large_resp_buffer + chunk_start, chunk_len);
			if (!is_duplicate) {
				large_resp_buffer_cursor = chunk_start + chunk_len;
				large_resp_buffer_last_opt3 = opt3;
			}
			// Windows 10 1903 bug, it sends every fido2 request/response twice
			// Everything happens twice, and the computer only pays attention to the 2nd request/response.
			// This means we can't wipe the response after it's retrieved, have to wipe
			// based on a timer
			//memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
			wipedata(); // Wipe timer started/extended while chunks remain
			if (large_resp_buffer_cursor >= large_resp_buffer_offset) {
				pending_operation=CTAP2_ERR_DATA_WIPE;
				large_resp_buffer_cursor = 0;
				large_resp_buffer_last_opt3 = 0;
			}
		} else if (CRYPTO_AUTH || packet_buffer_offset) {
			#ifdef DEBUG
			Serial.println("Ping success");
			#endif
			memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
			ret = CTAP2_ERR_USER_ACTION_PENDING;
		} else if (!CRYPTO_AUTH) {
			#ifdef DEBUG
			Serial.print("Error no data ready to be retrieved");
			#endif
			//custom_error(6);
      		ret = CTAP2_ERR_NO_OPERATION_PENDING;
			fadeoff(1);
		}
		return ret;
	}
	// The whole body above is inside `if (profilemode != NONENCRYPTEDPROFILE)`,
	// so a non-encrypted profile falls off the end of a non-void function. ret
	// is still 0 on that path, which is what the inner return would produce.
	return ret;
}

#endif
