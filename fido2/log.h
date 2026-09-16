// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _LOG_H
#define _LOG_H

//#include APP_CONFIG
#include <stdint.h>
#include "Arduino.h"
#include "onlykey.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef DEBUG
#define DEBUG_LEVEL 1
#else
#define DEBUG_LEVEL 0
#endif

//#define ENABLE_FILE_LOGGING

void LOG(uint32_t tag, const char * filename, int num, const char * fmt, ...);
void LOG_HEX(uint32_t tag, uint8_t * data, int length);

void set_logging_tag(uint32_t tag);

typedef enum
{
    TAG_GEN      = (1 << 0),
    TAG_MC       = (1 << 1),
    TAG_GA       = (1 << 2),
    TAG_CP       = (1 << 3),
    TAG_ERR      = (1 << 4),
    TAG_PARSE    = (1 << 5),
    TAG_CTAP     = (1 << 6),
    TAG_U2F      = (1 << 7),
    TAG_DUMP     = (1 << 8),
    TAG_GREEN    = (1 << 9),
    TAG_RED      = (1 << 10),
    TAG_TIME     = (1 << 11),
    TAG_HID      = (1 << 12),
    TAG_USB      = (1 << 13),
    TAG_WALLET   = (1 << 14),
    TAG_STOR     = (1 << 15),
    TAG_DUMP2    = (1 << 16),
    TAG_BOOT     = (1 << 17),
    TAG_EXT      = (1 << 18),
    TAG_NFC      = (1 << 19),
    TAG_NFC_APDU = (1 << 20),
    TAG_CCID     = (1 << 21),
    TAG_CM       = (1 << 22),

    TAG_NO_TAG   = (1UL << 30),
    TAG_FILENO   = (1UL << 31)
} LOG_TAG;

#if DEBUG_LEVEL > 0

void set_logging_mask(uint32_t mask);

#define printf1(tag,fmt, ...) do {\
			Serial.println(tag);\
            Serial.println(fmt);\
           } while(0) 
#define printf2(tag,fmt, ...) do {\
			Serial.println(tag);\
			Serial.println(fmt);\
            Serial.println(__FILE__);\
            Serial.println(__LINE__);\
           } while(0) 
#define printf3(tag,fmt, ...) do {\
			Serial.println(tag);\
			Serial.println(fmt);\
            Serial.println(__FILE__);\
            Serial.println(__LINE__);\
           } while(0) 

//uint32_t timestamp();
// Hex dumps are the expensive part of this logging, and they sit INSIDE the
// CTAPHID transaction: ctap_end_get_assertion() dumps sigder (up to 512 B) and
// ctap_request() dumps the whole CBOR response before a single response frame
// is written. At ~3 characters per byte over SEREMU that is several KB of
// back-pressure between the host's request and its answer. Keep the printf
// text, drop the dumps, unless DEBUG_BULK_DUMPS is asked for (onlykey.h).
#ifdef DEBUG_BULK_DUMPS
#define dump_hex1(tag,data,len) byteprint(data,len)
#else
#define dump_hex1(tag,data,len)
#endif
#define timestamp()

#else

#define set_logging_mask(mask)
#define printf1(tag,fmt, ...)
#define printf2(tag,fmt, ...)
#define printf3(tag,fmt, ...)
#define dump_hex1(tag,data,len)
#define timestamp()

#endif
#ifdef __cplusplus
}
#endif

#endif
