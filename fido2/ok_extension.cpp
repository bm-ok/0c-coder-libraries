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

// Functions for use with derived key (RESERVED_KEY_WEB_DERIVATION)
#define DERIVE_PUBLIC_KEY 1
#define DERIVE_SHAREDSEC 2
#define DERIVE_PUBLIC_KEY_REQ_PRESS 3
#define DERIVE_SHAREDSEC_REQ_PRESS 4
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


int16_t bridge_to_onlykey(uint8_t * _appid, uint8_t * keyh, int handle_len, uint8_t * output) {
    int8_t ret = 0;
	uint8_t client_handle[256];
	handle_len-=10;
	uint8_t cmd = keyh[0];
	uint8_t opt1 = keyh[1]; 
	uint8_t opt2 = keyh[2];
	uint8_t opt3 = keyh[3];
	uint8_t browser;
	uint8_t os;
	uint8_t temp[256];
	uint8_t pubsize;
	extern uint8_t derived_key_challenge_mode;

	memcpy(client_handle, keyh+10, handle_len);
		
	#ifdef DEBUG
    Serial.println("Keyhandle:");
    byteprint(client_handle, handle_len);
	#endif

    if (webcryptcheck(_appid, client_handle)) {
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
				if (opt3) opt3=2; // 1=encrypt everything, 2=encrypt everything except transit public so app can derive shared secret
				uint8_t *input_pubkey = client_handle+43+32; // Use uncompressed ecc pubkeys, could use compressed in future
				uint8_t additional_data[33] = {0};
				if (opt1 == DERIVE_PUBLIC_KEY_REQ_PRESS || opt1 == DERIVE_SHAREDSEC_REQ_PRESS) {
					additional_data[0] = 1; // Generate different key for REQ_PRESS than non REQ_PRESS
				} else {
					// derived_key_challenge_mode is a RAM cache of an EEPROM
					// byte, unconditionally zeroed by wipetasks() and by every
					// done_process_packets() call (the OnlyKey raw-HID
					// pipeline - PIN unlock, status, OKCONNECT, SSH/GPG - a
					// completely separate dispatch path from this FIDO2/CTAP
					// one), and only reloaded there for slot codes >200 (an
					// SSH/GPG-specific convention, okcrypto.cpp:207/369/650)
					// that this FIDO2 path never sends. So the RAM copy is
					// essentially always stale by the time this check runs,
					// regardless of what's actually persisted in EEPROM.
					// Reload directly here instead of trusting the cache -
					// okeeprom_eeget_derived_key_challenge_mode() is a plain
					// single-byte eeprom_read_byte(), no side effects.
					okeeprom_eeget_derived_key_challenge_mode(&derived_key_challenge_mode);
					if (!(is_bit_set(derived_key_challenge_mode, 3))) {
						//derived keys per site without touch not enabeled
						ret = CTAP2_ERR_EXTENSION_NOT_SUPPORTED; //APPID doesn't match
						wipedata();
						return ret;
					}
				}
				memcpy(additional_data+1, client_handle+43, 32); // 32 bytes of data to include in key derivation
				opt2++;
				memset(ecc_public_key, 0, sizeof(ecc_public_key));

				// ---- X-Wing (mlkem768x25519) split custody -------------------
				// Wire keytype 5 -> opt2==KEYTYPE_XWING(6). Returns 64 bytes,
				// encrypted under the transit key when opt3:
				//   DERIVE_PUBLIC_KEY -> [ pk_X(32) | mlkem_seed(32) ]
				//   DERIVE_SHAREDSEC  -> [ ss_X(32) | mlkem_seed(32) ]
				// sk_X (X25519) never leaves the device; the browser expands
				// mlkem_seed and does the ML-KEM half locally.
				//
				// Calls the SAME okcrypto_xwing_web_derive() the raw-HID path
				// uses (okcrypto.cpp's okcrypto_getpubkey/okcrypto_decrypt,
				// already proven correct against the CLI - TC-16/TC-17) rather
				// than re-deriving inline, after finding live (TC-18/TC-19,
				// browser<->CLI interop) that an earlier inline copy here
				// produced a DIFFERENT sk_X than the CLI for the same label:
				// okcrypto_hkdf() folds whatever RPID string is staged at
				// ctap_buffer+4 into the derivation, and the raw-HID path
				// explicitly stages "onlyagent.app" there
				// (okcrypto_xwing_web_derive itself) before deriving, but this
				// FIDO2 dispatch path never did - it derived using whatever
				// RPID happened to already be in ctap_buffer from the
				// surrounding CTAP2 request instead. Calling the shared
				// function fixes that by construction and removes the
				// duplicate-implementation drift risk entirely. This also
				// means X-Wing derives the same key regardless of REQ_PRESS
				// (okcrypto_xwing_web_derive has no such distinction, matching
				// the CLI path, which never had one either) - unlike the
				// generic EC keytypes below, whose REQ_PRESS/non-REQ_PRESS
				// separation this doesn't touch.
				if (opt2 == KEYTYPE_XWING) {
					uint8_t *xout = temp + 32 + sizeof(UNLOCKED) + 1;
					uint8_t *label32 = client_handle + 43;
					if (opt1 == DERIVE_SHAREDSEC || opt1 == DERIVE_SHAREDSEC_REQ_PRESS) {
						if (opt1 == DERIVE_SHAREDSEC_REQ_PRESS) {
							int but;
							device_set_status(CTAPHID_STATUS_UPNEEDED);
							but = ctap_user_presence_test(CTAP2_UP_DELAY_MS);
							if (but > 1) return CTAP2_ERR_PROCESSING;
							else if (but < 0) return CTAP2_ERR_KEEPALIVE_CANCEL;
							else if (but == 0) { pending_operation = 0; return CTAP2_ERR_ACTION_TIMEOUT; }
						}
						// ct_X = input pubkey from the age stanza
						uint8_t *ct_X = client_handle + 43 + 32;
						okcrypto_xwing_web_derive(label32, ct_X, xout);
					} else {
						okcrypto_xwing_web_derive(label32, NULL, xout);
					}
					send_transport_response(temp, 32 + sizeof(UNLOCKED) + 1 + 64, opt3, false);
					ret = send_stored_response(output, opt3);
					return ret;
				}

				//Similar format to SSH derivation but use RESERVED_KEY_WEB_DERIVATION key
				if (opt2 == KEYTYPE_NACL || opt2 == KEYTYPE_CURVE25519) {
					okcrypto_derive_key(KEYTYPE_CURVE25519, additional_data, RESERVED_KEY_WEB_DERIVATION); //Curve25519
					pubsize=32;
				}
				else if (opt2 == KEYTYPE_P256R1) {
					okcrypto_derive_key(KEYTYPE_P256R1, additional_data, RESERVED_KEY_WEB_DERIVATION);
					memmove(ecc_public_key+1, ecc_public_key, 64);
					ecc_public_key[0] = 4;
					pubsize=65;
				}
				else if (opt2 == KEYTYPE_P256K1) {
					okcrypto_derive_key(KEYTYPE_P256K1, additional_data, RESERVED_KEY_WEB_DERIVATION);
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

				if (opt1==DERIVE_SHAREDSEC || opt1==DERIVE_SHAREDSEC_REQ_PRESS) { // Return DERIVE_PUBLIC_KEY and DERIVE_SHAREDSEC
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
						// Generate Shared Secret
						if (opt1==DERIVE_SHAREDSEC_REQ_PRESS) {
							int but;
							device_set_status(CTAPHID_STATUS_UPNEEDED);
							but = ctap_user_presence_test(CTAP2_UP_DELAY_MS);
							if ( but > 1 )
							{
								return CTAP2_ERR_PROCESSING;
							}
							else if (but < 0)
							{
								return CTAP2_ERR_KEEPALIVE_CANCEL;
							}
							else if (but == 0)
							{
								pending_operation=0;
								return CTAP2_ERR_ACTION_TIMEOUT;
							} else if (os == 'W') {
								packet_buffer_details[3] = 'W';
							}
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
		} else if (webcryptcheck(_appid, client_handle)>1) {  // Protected mode, only allow crp.to and localhost
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
		Serial.println("Sending data on OnlyKey via Webauthn");
		byteprint(large_resp_buffer, large_resp_buffer_offset);
		Serial.println(large_resp_buffer_offset);
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
			// opt3 <= large_resp_buffer_last_opt3 means this poll duplicates
			// the one just answered (the Windows 10 1903 double-fire this file
			// guards against elsewhere via packet_buffer_details[3]) - re-serve
			// the same bytes rather than advancing, or a duplicate silently
			// skips a chunk and corrupts the reassembled response.
			int is_duplicate = large_resp_buffer_last_opt3 && opt3 <= large_resp_buffer_last_opt3;
			int chunk_start = is_duplicate
				? (large_resp_buffer_cursor > MAX_LARGE_RESP_CHUNK ? large_resp_buffer_cursor - MAX_LARGE_RESP_CHUNK : 0)
				: large_resp_buffer_cursor;
			int remaining = large_resp_buffer_offset - chunk_start;
			int chunk_len = remaining > MAX_LARGE_RESP_CHUNK ? MAX_LARGE_RESP_CHUNK : remaining;
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
