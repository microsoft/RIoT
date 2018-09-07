/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

//
// 4-MAY-2015; RIoT adaptation (DennisMa;MSFT).
//
#include "stdint.h"
#include "RiotKdf.h"

#pragma CHECKED_SCOPE ON

#if HOST_IS_LITTLE_ENDIAN
#define UINT32_TO_BIGENDIAN(i)          \
        ( ((i) & 0xff000000ULL >> 24)      \
        | ((i) & 0x00ff0000ULL >> 8)       \
        | ((i) & 0x0000ff00ULL << 8)       \
        | ((i) & 0x000000ffULL << 24))
#else
#define UINT32_TO_BIG_ENDIAN(i) (i)
#endif
#define UINT32_FROM_BIGENDIAN uint32_tO_BIGENDIAN

//
// Create the fixed content for a KDF
// @param fixed  buffer to receive the fixed content
// @param fixedSize  indicates the available space in fixed
// @param label the label parameter (optional)
// @param labelSize
// @param context the context value (optional)
// @param contextSize
// @param numberOfBits the number of bits to be produced
//
size_t RIOT_KDF_FIXED(
	uint8_t         *fixed   : byte_count(fixedSize),
	size_t          fixedSize,
	const uint8_t   *label : itype(_Nt_array_ptr<const uint8_t>) byte_count(labelSize),
	size_t          labelSize,
	const uint8_t   *context : byte_count(contextSize),
	size_t          contextSize,
	uint32_t        numberOfBits
)
{
    size_t          total = (((label) ? labelSize : 0) + ((context) ? contextSize : 0) + 5);

    assert(fixedSize >= total);
    
    // TODO: since total is > than both labelSize and contextSize, the memcpys are safe
    // This might be hard for the compiler to reason about, not just simple unsigned comparison

    if (label) {
        memcpy(_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(fixed, byte_count(labelSize)), label, labelSize);
        fixed += labelSize;
    }
    *fixed++ = 0;
    if (context) {
        memcpy(_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(fixed, byte_count(contextSize)), context, contextSize);
        fixed += contextSize;
    }
    numberOfBits = UINT32_TO_BIGENDIAN(numberOfBits);
    memcpy(_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(fixed, byte_count(4)), &numberOfBits, 4);
    return total;
}


//
// Do KDF from SP800-108 -- HMAC based counter mode. This function does a single
// iteration. The counter parameter is incremented before it is used so that
// a caller can set counter to 0 for the first iteration.
// @param out the output digest of a single iteration (a SHA256 digest)
// @param key the HMAC key
// @param keySize
// @param counter the running counter value (may be NULL)
// @param fixed the label parameter (optional)
// @param fixedSize
//
void RIOT_KDF_SHA256(
    uint8_t         *out     : byte_count(SHA256_DIGEST_LENGTH),
    const uint8_t   *key     : byte_count(keySize),
    size_t          keySize,
    uint32_t        *counter : itype(_Ptr<uint32_t>),
    const uint8_t   *fixed   : byte_count(fixedSize),
    size_t          fixedSize
)
{
    RIOT_HMAC_SHA256_CTX    ctx;
    uint32_t                ctr = counter ? ++*counter : 1;

    assert(out && key && fixed);

    // Start the HMAC
    RIOT_HMAC_SHA256_Init(&ctx, key, keySize);
    // Add the counter
    ctr = UINT32_TO_BIGENDIAN(ctr);
    // TODO: Compiler has trouble with the cast to uint8 * from uint32 *. Does not cast the size with it.
    RIOT_HMAC_SHA256_Update(&ctx, _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&ctr, byte_count(4)), 4);
    // Add fixed stuff
    RIOT_HMAC_SHA256_Update(&ctx, fixed, fixedSize);
    RIOT_HMAC_SHA256_Final(&ctx, out);
}

#pragma CHECKED_SCOPE OFF