#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* Transcribed bounds logic from the patched firmware. Each test states the
 * attack from the review and asserts the patched code refuses it while still
 * accepting every legitimate input. */

#define CTAPHID_BUFFER_SIZE 6585
#define LARGE_BUFFER_SIZE   1120
#define MLKEM_SK_SIZE       2400
#define MLKEM_PK_SIZE       1184
#define MAX_RSA_KEY_SIZE    512
#define EElen_label   16
#define EElen_url     56
#define EElen_username 56
#define EElen_totpkey 64
#define OK_KEYHANDLE_HEADER_LEN 10

static int fails = 0, checks = 0;
#define CHECK(cond, msg) do { checks++; if(!(cond)){ printf("FAIL: %s\n", msg); fails++; } } while(0)

/* --- C1: bridge_to_onlykey length gate --------------------------------- */
static int bridge_accepts(int handle_len) {
    uint8_t client_handle[256];
    if (handle_len < OK_KEYHANDLE_HEADER_LEN || handle_len > (int)sizeof(client_handle)) return 0;
    handle_len -= OK_KEYHANDLE_HEADER_LEN;
    return 1 + handle_len;   /* 1 + payload bytes copied */
}

/* --- H1/M4: flash setter slot gate ------------------------------------- */
static int setter_accepts(int eelen, int slot) {
    size_t tempsz = 2048;
    if (slot < 1 || (size_t)(eelen * slot) > tempsz) return 0;
    return 1;
}
static int setter_last_index(int eelen, int slot) { return eelen*(slot-1) + eelen-1; }

/* --- M4: set_slot terminator scan -------------------------------------- */
static int scan_length(const uint8_t *buffer) {
    int length = 0;
    for (int z = 0; (z + 10) < 64 &&
         buffer[z+7]+buffer[z+8]+buffer[z+9]+buffer[z+10] != 0x00; z++)
        length = z + 1;
    return length;
}

/* --- M1: RSA 512 chunk clamp ------------------------------------------- */
static int rsa_total_written(void) {
    int off = 0, total = 0;
    while (off <= 456) {
        int room = MAX_RSA_KEY_SIZE - off;
        int cpy = room < 57 ? room : 57;
        if (off + cpy > MAX_RSA_KEY_SIZE) return -1;   /* overflow */
        total = off + cpy;
        off += 57;
    }
    return total;
}

/* --- M2: derive chunk size gate ---------------------------------------- */
static int derive_chunk_accepts(uint8_t b6) {
    if (b6 != 0xFF && b6 > 57) return 0;
    return 1;
}

/* --- L1: continuation packet binding ----------------------------------- */
static int cont_accepts(uint8_t first_cmd, uint8_t first_slot, uint8_t cmd, uint8_t slot) {
    if (first_cmd != cmd || first_slot != slot) return 0;
    return 1;
}

int main(void) {
    /* C1 — the exact attack: a 9-byte credential id. */
    CHECK(bridge_accepts(9)  == 0, "C1: 9-byte keyhandle must be refused");
    CHECK(bridge_accepts(0)  == 0, "C1: 0-length keyhandle (256 truncated to uint8_t) refused");
    for (int n = 1; n < 10; n++)
        CHECK(bridge_accepts(n) == 0, "C1: every sub-header length refused");
    CHECK(bridge_accepts(10) == 1,   "C1: exactly-header length accepted, 0 payload");
    CHECK(bridge_accepts(256) == 1+246, "C1: max keyhandle accepted, 246 payload bytes");
    CHECK(bridge_accepts(257) == 0,  "C1: over-max refused");
    /* and no accepted length can produce a copy past the 256-byte frame */
    for (int n = 10; n <= 256; n++) {
        int r = bridge_accepts(n);
        CHECK(r >= 1 && (r-1) <= 256, "C1: accepted copy fits client_handle");
    }

    /* H1 — the flash setters. */
    CHECK(setter_accepts(EElen_url, 0) == 0,   "H1: slot 0 refused (url)");
    CHECK(setter_accepts(EElen_url, 255) == 0, "H1: slot 255 refused (url)");
    CHECK(setter_accepts(EElen_label, 0) == 0, "H1: slot 0 refused (label) - the underflow the old >127 check missed");
    CHECK(setter_accepts(EElen_totpkey, 33) == 0, "H1: 2FA slot 33 refused");
    /* every accepted slot must stay inside temp[2048] */
    int lens[4] = {EElen_label, EElen_url, EElen_username, EElen_totpkey};
    for (int i = 0; i < 4; i++)
        for (int slot = -5; slot <= 300; slot++)
            if (setter_accepts(lens[i], slot))
                CHECK(setter_last_index(lens[i], slot) < 2048 && slot >= 1,
                      "H1: accepted slot writes inside temp[2048]");
    /* real slots must still work */
    for (int slot = 1; slot <= 24; slot++)
        for (int i = 0; i < 4; i++)
            CHECK(setter_accepts(lens[i], slot) == 1, "H1: real slots 1-24 still accepted");
    for (int slot = 25; slot <= 128; slot++)
        CHECK(setter_accepts(EElen_label, slot) == 1, "H1: key-label slots up to 128 still accepted");

    /* M4 — terminator scan cannot leave the packet. */
    uint8_t all_nonzero[64]; memset(all_nonzero, 0xAA, sizeof(all_nonzero));
    int L = scan_length(all_nonzero);
    CHECK(L <= 57, "M4: scan bounded to the 57 payload bytes");
    CHECK(L == 54, "M4: fully non-zero packet stops at z+10 < 64");
    uint8_t normal[64]; memset(normal, 0, sizeof(normal));
    memset(normal+7, 0x41, 20);
    CHECK(scan_length(normal) == 20, "M4: ordinary 20-byte value still measured correctly");

    /* M1 — the 512-byte key still loads, and nothing is written past 512. */
    CHECK(rsa_total_written() == 512, "M1: 4096-bit key loads to exactly 512 bytes");

    /* M2 — oversized derive chunk. */
    CHECK(derive_chunk_accepts(0xFF) == 1, "M2: continuation marker still accepted");
    CHECK(derive_chunk_accepts(57) == 1,   "M2: full final chunk accepted");
    CHECK(derive_chunk_accepts(12) == 1,   "M2: short final chunk accepted");
    for (int b = 58; b <= 254; b++)
        CHECK(derive_chunk_accepts((uint8_t)b) == 0, "M2: 58..254 refused");

    /* L1 — continuation binding. */
    CHECK(cont_accepts(240, 5, 240, 5) == 1, "L1: matching cmd+slot accepted");
    CHECK(cont_accepts(240, 5, 240, 9) == 0, "L1: same cmd, different slot now refused");
    CHECK(cont_accepts(240, 5, 237, 5) == 0, "L1: different cmd refused");
    CHECK(cont_accepts(240, 5, 237, 9) == 0, "L1: both different refused");

    /* H3 — scratch placement. */
    int off = CTAPHID_BUFFER_SIZE - LARGE_BUFFER_SIZE - (MLKEM_SK_SIZE + MLKEM_PK_SIZE);
    int scratch_end = off + MLKEM_SK_SIZE + MLKEM_PK_SIZE;
    int lb_start = CTAPHID_BUFFER_SIZE - LARGE_BUFFER_SIZE;
    CHECK(off >= 1024, "H3: room left below scratch for an inbound CTAP request");
    CHECK(scratch_end <= lb_start, "H3: scratch does not overlap large_buffer (the staged ciphertext)");

    printf("%d checks, %d failures\n", checks, fails);
    return fails != 0;
}
