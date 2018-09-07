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
#include "RiotHmac.h"

#pragma CHECKED_SCOPE ON

void
RIOT_HMAC_SHA256_Init(
    RIOT_HMAC_SHA256_CTX *ctx : itype(_Ptr<RIOT_HMAC_SHA256_CTX>),
    const uint8_t *key : byte_count(keyLen),
    size_t keyLen
)
{
    size_t cnt;

    assert(ctx && key);

    // if keyLen > 64, hash it and use it as key
    if (keyLen > HMAC_SHA256_BLOCK_LENGTH) {
        RIOT_SHA256_Block_ctx(&ctx->hashCtx, key, keyLen, ctx->opad);
        keyLen = SHA256_DIGEST_LENGTH;
    } else {
        // otherwise it's less than 64 and fits in opad.
        // TODO: Unsigned comparison, need dynamic bounds cast
        memcpy(_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(ctx->opad, byte_count(keyLen)), key, keyLen);
    }
    //
    // the HMAC_SHA256 process
    //
    // SHA256((K XOR opad) || SHA256((K XOR ipad) || msg))
    //
    // K is the key
    // ipad is filled with 0x36
    // opad is filled with 0x5c
    // msg is the message
    //

    //
    // prepare inner hash SHA256((K XOR ipad) || msg)
    // K XOR ipad
    //
    for (cnt = 0; cnt < keyLen; cnt++) {
        ctx->opad[cnt] ^= 0x36;
    }
    // TODO: Going into the middle of buffer, need dynamic bounds cast
    _Array_ptr<uint8_t> atKeyLen : byte_count(sizeof(ctx->opad) - keyLen) = _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&ctx->opad[keyLen], byte_count(sizeof(ctx->opad) - keyLen));
    memset(atKeyLen, 0x36, sizeof(ctx->opad) - keyLen);

    RIOT_SHA256_Init(&ctx->hashCtx);
    RIOT_SHA256_Update(&ctx->hashCtx, ctx->opad, HMAC_SHA256_BLOCK_LENGTH);

    // Turn ipad into opad
    for (cnt = 0; cnt < sizeof(ctx->opad); cnt++) {
        ctx->opad[cnt] ^= (0x5c ^ 0x36);
    }
}

void
RIOT_HMAC_SHA256_Update(
    RIOT_HMAC_SHA256_CTX *ctx : itype(_Ptr<RIOT_HMAC_SHA256_CTX>),
    const uint8_t *data : byte_count(dataLen),
    size_t dataLen
)
{
    RIOT_SHA256_Update(&ctx->hashCtx, data, dataLen);
    return;
}

void
RIOT_HMAC_SHA256_Final(
    RIOT_HMAC_SHA256_CTX *ctx : itype(_Ptr<RIOT_HMAC_SHA256_CTX>),
    uint8_t *digest : byte_count(SHA256_DIGEST_LENGTH)
)
{
    // complete inner hash SHA256(K XOR ipad, msg)
    RIOT_SHA256_Final(&ctx->hashCtx, digest);

    // perform outer hash SHA256(K XOR opad, SHA256(K XOR ipad, msg))
    RIOT_SHA256_Init(&ctx->hashCtx);
    RIOT_SHA256_Update(&ctx->hashCtx, ctx->opad, HMAC_SHA256_BLOCK_LENGTH);
    RIOT_SHA256_Update(&ctx->hashCtx, digest, SHA256_DIGEST_LENGTH);
    RIOT_SHA256_Final(&ctx->hashCtx, digest);
    return;
}

#pragma CHECKED_SCOPE OFF


