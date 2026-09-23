#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Exhaustive check of the field 21/22/30/31 policy logic, transcribed from
 * okcore.cpp and fido2/device.cpp. Build and run:
 *   cc -o /tmp/fpt field_policy_test.c && /tmp/fpt
 *   cc -DOK_ALLOW_NO_PRESS -o /tmp/fpt field_policy_test.c && /tmp/fpt
 *
 * Field 31 is stored as (policy | OKWC_WRITTEN). EEPROM that was never written
 * reads 0xFF on a new part, but wipeEEPROM() - every factory default and every
 * wipe - leaves 0x00, so BOTH must read as "never configured". A raw policy
 * byte (0-3) cannot be the marker. */

/* Constants copied verbatim from okcore.h */
#define USER_INPUT_CHALLENGE 0
#define USER_INPUT_PRESS 1
#define USER_INPUT_NONE 2
#define OKWC_ALLOW_STORED_KEY  0x01
#define OKWC_DISABLE_EXT       0x02
#define OKWC_VALID_MASK        (OKWC_ALLOW_STORED_KEY | OKWC_DISABLE_EXT)
#define OKWC_WRITTEN           0x80
#define OKWC_IS_WRITTEN(raw)   (((raw) & (uint8_t)~OKWC_VALID_MASK) == OKWC_WRITTEN)
#define RESERVED_KEY_WEB_AGENT_DERIVATION 128

/* Simulated EEPROM */
static uint8_t ee_f21, ee_f22, ee_f30, ee_f31;

/* --- transcribed from okcore.cpp --- */
static uint8_t okcore_web_agent_derive_mode(void) {
    uint8_t mode = ee_f30;
    if (mode > USER_INPUT_NONE) mode = USER_INPUT_PRESS;
    return mode;
}
static uint8_t okcore_user_input_mode_for_slot(uint8_t slot) {
    if (slot == RESERVED_KEY_WEB_AGENT_DERIVATION) return okcore_web_agent_derive_mode();
    uint8_t derived = (slot > 200);
    uint8_t raw = derived ? ee_f21 : ee_f22;
    uint8_t mode = raw & 0x03;
    if (derived && mode == USER_INPUT_NONE && !OKWC_IS_WRITTEN(ee_f31))
        mode = USER_INPUT_CHALLENGE;
#ifndef OK_ALLOW_NO_PRESS
    if (mode == USER_INPUT_NONE) mode = USER_INPUT_CHALLENGE;
#endif
    if (mode > USER_INPUT_NONE) mode = USER_INPUT_CHALLENGE;
    return mode;
}
static uint8_t okcore_webcrypt_policy(void) {
    uint8_t raw = ee_f31;
    if (OKWC_IS_WRITTEN(raw)) return raw & OKWC_VALID_MASK;
    uint8_t legacy = ee_f21;
    if (legacy == 0xFF) return OKWC_ALLOW_STORED_KEY;
    return OKWC_ALLOW_STORED_KEY | ((legacy & 0x02) ? OKWC_DISABLE_EXT : 0);
}
/* --- transcribed from device.cpp webcryptcheck() tail --- */
static int webcrypt_level(int origin_trusted) {
    uint8_t p = okcore_webcrypt_policy();
    if (origin_trusted && !(p & OKWC_DISABLE_EXT))
        return (p & OKWC_ALLOW_STORED_KEY) ? 2 : 1;
    return 0;
}
/* what the field 31 set_slot() path stores for an accepted value */
static uint8_t stored(uint8_t v) { return (uint8_t)(v | OKWC_WRITTEN); }

int main(void) {
    int fail = 0, n = 0;
    const uint8_t blanks[2] = { 0xFF, 0x00 };   /* new part, wiped part */

    for (int k = 0; k < 2; k++) {
        uint8_t blank = blanks[k];
        /* 1. Blank key. Defaults are what v3.0.4 did - derive yes, PGP yes,
           extension on (decided 2026-09-23) - and never "none" for input. */
        ee_f21 = ee_f22 = ee_f30 = ee_f31 = blank;
        if (webcrypt_level(1) != 2) { printf("FAIL blank 0x%02X: level %d != 2\n", blank, webcrypt_level(1)); fail++; }
        if (okcore_web_agent_derive_mode() == USER_INPUT_NONE) { printf("FAIL blank 0x%02X: web derive mode none\n", blank); fail++; }
        if (okcore_user_input_mode_for_slot(210) != USER_INPUT_CHALLENGE) { printf("FAIL blank 0x%02X: derived slot not challenge\n", blank); fail++; }
        n += 3;

        /* 2. While field 31 is unwritten: legacy disable intent is kept, and
           otherwise stored keys are allowed as on v3.0.4. */
        ee_f31 = blank;
        for (int b = 0; b < 256; b++) {
            ee_f21 = (uint8_t)b;
            int legacy_disabled = (b != 0xFF) && (b & 0x02);
            int lvl = webcrypt_level(1);
            if (legacy_disabled && lvl != 0) { printf("FAIL f31 0x%02X legacy 0x%02X: extension was disabled, now level %d\n", blank, b, lvl); fail++; }
            if (!legacy_disabled && lvl != 2) { printf("FAIL f31 0x%02X legacy 0x%02X: level %d, v3.0.4 allowed PGP\n", blank, b, lvl); fail++; }
            n += 2;
        }

        /* 3. No legacy byte may reach a less restrictive input mode than it
           meant. Legacy bit 0 = press; everything else lands on the challenge. */
        ee_f31 = blank;
        for (int b = 0; b < 256; b++) {
            ee_f21 = (uint8_t)b;
            uint8_t m = okcore_user_input_mode_for_slot(210);
            if (m == USER_INPUT_NONE) { printf("FAIL f31 0x%02X legacy 0x%02X: reached USER_INPUT_NONE\n", blank, b); fail++; }
            uint8_t want = ((b & 0x03) == USER_INPUT_PRESS) ? USER_INPUT_PRESS : USER_INPUT_CHALLENGE;
            if (m != want) { printf("FAIL f31 0x%02X legacy 0x%02X: mode %u want %u\n", blank, b, m, want); fail++; }
            n += 2;
        }
    }

    /* 4. An explicit field 31 write ends inheritance in BOTH directions. */
    ee_f21 = 0x02;                 /* legacy: extension disabled */
    ee_f31 = stored(0);            /* user explicitly re-enables, PGP off */
    if (webcrypt_level(1) != 1) { printf("FAIL explicit 0 not honoured\n"); fail++; }
    ee_f31 = stored(OKWC_ALLOW_STORED_KEY);
    if (webcrypt_level(1) != 2) { printf("FAIL explicit PGP opt-in blocked\n"); fail++; }
    ee_f31 = stored(OKWC_DISABLE_EXT);
    if (webcrypt_level(1) != 0) { printf("FAIL explicit disable ignored\n"); fail++; }
    ee_f21 = 0x00;                 /* no legacy intent */
    ee_f31 = stored(OKWC_DISABLE_EXT);
    if (webcrypt_level(1) != 0) { printf("FAIL explicit disable ignored (clean legacy)\n"); fail++; }
    ee_f31 = stored(0);
    if (webcrypt_level(1) != 1) { printf("FAIL explicit 0 not honoured (clean legacy)\n"); fail++; }
    n += 5;

    /* 5. An untrusted origin gets nothing, whatever the byte says. */
    for (int p = 0; p < 256; p++) {
        ee_f31 = (uint8_t)p;
        if (webcrypt_level(0) != 0) { printf("FAIL untrusted origin got level %d (f31 0x%02X)\n", webcrypt_level(0), p); fail++; }
        n++;
    }

    /* 6. Every byte: a written byte is exactly its policy; anything else is
       "never configured" and never leaks undefined bits. */
    ee_f21 = 0x00;
    for (int p = 0; p < 256; p++) {
        ee_f31 = (uint8_t)p;
        uint8_t eff = okcore_webcrypt_policy();
        if (eff & ~OKWC_VALID_MASK) { printf("FAIL f31 0x%02X leaked undefined bits\n", p); fail++; }
        int lvl = webcrypt_level(1);
        int want = OKWC_IS_WRITTEN(p)
            ? ((p & OKWC_DISABLE_EXT) ? 0 : ((p & OKWC_ALLOW_STORED_KEY) ? 2 : 1))
            : 2;
        if (lvl != want) { printf("FAIL f31 0x%02X: level %d want %d\n", p, lvl, want); fail++; }
        n += 2;
    }
    if (OKWC_IS_WRITTEN(0x00) || OKWC_IS_WRITTEN(0xFF)) { printf("FAIL a blank byte reads as written\n"); fail++; }
    n++;

    /* 7. After an explicit field 31 write, field 21 value 2 is the enum's
       "none" again - subject to the build flag, which is what gates it in
       production. */
    ee_f21 = 0x02; ee_f31 = stored(0);
#ifdef OK_ALLOW_NO_PRESS
    if (okcore_user_input_mode_for_slot(210) != USER_INPUT_NONE) { printf("FAIL post-migration 2 not honoured\n"); fail++; }
#else
    if (okcore_user_input_mode_for_slot(210) != USER_INPUT_CHALLENGE) { printf("FAIL post-migration 2 not failing closed\n"); fail++; }
#endif
    n++;

    printf("%d assertions, %d failures\n", n, fail);
    return fail != 0;
}
