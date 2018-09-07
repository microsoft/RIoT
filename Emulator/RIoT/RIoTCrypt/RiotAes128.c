/******************************************************************************
 * Copyright (c) 2013, AllSeen Alliance. All rights reserved.
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
// 4-MAY-2015; RIoT adaptation (DennisMa;MSFT)
//
#include "RiotTarget.h"
#include "RiotAes128.h"

#define _AES_COMPILE_
#include "RiotAesTables.c"

#pragma CHECKED_SCOPE ON

#define ROTL8(x)  ((((uint32_t)(x)) << 8)  | (((uint32_t)(x)) >> 24))
#define ROTL16(x) ((((uint32_t)(x)) << 16) | (((uint32_t)(x)) >> 16))
#define ROTL24(x) ((((uint32_t)(x)) << 24) | (((uint32_t)(x)) >> 8))

#define SHFL8(x)  (((uint32_t)(x)) << 8)
#define SHFL16(x) (((uint32_t)(x)) << 16)
#define SHFL24(x) (((uint32_t)(x)) << 24)

#define ROW_0(x) (uint8_t)(x)
#define ROW_1(x) (uint8_t)((x) >> 8)
#define ROW_2(x) (uint8_t)((x) >> 16)
#define ROW_3(x) (uint8_t)((x) >> 24)

#define round_column(x0, x1, x2, x3)    \
    ftable[ROW_0(x0)]                   \
    ^ ROTL8 (ftable[ROW_1(x1)])         \
    ^ ROTL16(ftable[ROW_2(x2)])         \
    ^ ROTL24(ftable[ROW_3(x3)])

//
// yN are inputs xN are outputs
//
#define round(y0, y1, y2, y3, x0, x1, x2, x3, key)  \
    y0 = round_column(x0, x1, x2, x3) ^ *key++;     \
    y1 = round_column(x1, x2, x3, x0) ^ *key++;     \
    y2 = round_column(x2, x3, x0, x1) ^ *key++;     \
    y3 = round_column(x3, x0, x1, x2) ^ *key++;

#define lastround_column(x0, x1, x2, x3)    \
    (uint32_t)sbox[ROW_0(x0)]               \
    ^ SHFL8(sbox[ROW_1(x1)])                \
    ^ SHFL16(sbox[ROW_2(x2)])               \
    ^ SHFL24(sbox[ROW_3(x3)])

//
// yN are inputs xN are outputs
//
#define lastround(y0, y1, y2, y3, x0, x1, x2, x3, key)  \
    y0 = lastround_column(x0, x1, x2, x3) ^ *key++;     \
    y1 = lastround_column(x1, x2, x3, x0) ^ *key++;     \
    y2 = lastround_column(x2, x3, x0, x1) ^ *key++;     \
    y3 = lastround_column(x3, x0, x1, x2) ^ *key++;

static void Pack32(_Array_ptr<uint32_t> u32 : byte_count(AES_BLOCK_SIZE), 
	               _Array_ptr<const uint8_t> u8 : byte_count(AES_BLOCK_SIZE))
{
#if HOST_IS_LITTLE_ENDIAN
    memcpy(u32, u8, 16);
#else
    int i;
    for (i = 0; i < 4; ++i, ++u32, u8 += 4) {
        *u32 = (uint32_t)u8[0] | (u8[1] << 8) | (u8[2] << 16) | (u8[3] << 24);
    }
#endif
}

static void Unpack32(_Array_ptr<uint8_t> u8 : byte_count(16), 
	                 _Array_ptr<const uint32_t> u32 : byte_count(16))
{
#if HOST_IS_LITTLE_ENDIAN
    memcpy(u8, u32, 16);
#else
    int i;
    for (i = 0; i < 4; ++i, ++u32) {
        *u8++ = (uint8_t)(*u32);
        *u8++ = (uint8_t)(*u32 >>  8);
        *u8++ = (uint8_t)(*u32 >> 16);
        *u8++ = (uint8_t)(*u32 >> 24);
    }
#endif
}

static uint32_t SubBytes(uint32_t a)
{
    return (uint32_t)sbox[(uint8_t)(a)]              |
           (sbox[(uint8_t)(a >> 8)] << 8)   |
           (sbox[(uint8_t)(a >> 16)] << 16) |
           (sbox[(uint8_t)(a >> 24)] << 24);
}

#define ROUNDS 10

static void EncryptRounds(_Array_ptr<uint32_t> out : count(4), 
	                      _Array_ptr<uint32_t> in  : count(4), 
	                      _Array_ptr<uint32_t> key : count(AES128_ENCRYPT_SCHEDULE_LEN))
{
    int i;
    uint32_t x0 = in[0] ^ key[0];
    uint32_t x1 = in[1] ^ key[1];
    uint32_t x2 = in[2] ^ key[2];
    uint32_t x3 = in[3] ^ key[3];
    uint32_t y0;
    uint32_t y1;
    uint32_t y2;
    uint32_t y3;
    key += 4;

    for (i = 0; i < 4; i++) {
        round(y0, y1, y2, y3, x0, x1, x2, x3, key);
        round(x0, x1, x2, x3, y0, y1, y2, y3, key);
    }

    round(y0, y1, y2, y3, x0, x1, x2, x3, key);
    lastround(x0, x1, x2, x3, y0, y1, y2, y3, key);

    out[0] = x0;
    out[1] = x1;
    out[2] = x2;
    out[3] = x3;
}

void RIOT_AES128_Enable(const uint8_t *key : byte_count(AES_BLOCK_SIZE), 
						aes128EncryptKey_t *aesEncryptKey : itype(_Ptr<aes128EncryptKey_t_ch>))
{
    int i;
    _Array_ptr<uint32_t> beginKey : byte_count(AES_BLOCK_SIZE) = 
		(_Array_ptr<uint32_t>)aesEncryptKey;

    Pack32(beginKey, key);

	_Array_ptr<uint32_t> fkey : byte_count(sizeof(aes128EncryptKey_t_ch)) = (_Array_ptr<uint32_t>)aesEncryptKey;

    for (i = 0; i <= ROUNDS; ++i, fkey += 4) {
        fkey[4] = fkey[0] ^ SubBytes(ROTL24(fkey[3])) ^ Rconst[i];
        fkey[5] = fkey[1] ^ fkey[4];
        fkey[6] = fkey[2] ^ fkey[5];
        fkey[7] = fkey[3] ^ fkey[6];
    }
}


void RIOT_AES128_Disable(aes128EncryptKey_t *aesEncryptionKey : itype(_Ptr<aes128EncryptKey_t_ch>))
{
    memset(aesEncryptionKey, 0, sizeof(aes128EncryptKey_t));
}

#if AES_CTR_MODE
void RIOT_AES_CTR_128(const aes128EncryptKey_t *aes128EncryptKey : itype(_Ptr<const aes128EncryptKey_t_ch>),
	const uint8_t *in : byte_count(len),
	uint8_t *out : byte_count(len), 
    uint32_t len,
	uint8_t *ctr : byte_count(AES_BLOCK_SIZE))
{
    uint32_t     counter _Checked[4];
#if HOST_IS_LITTLE_ENDIAN
    // Point to the big endian counter at the end of the IV
    _Array_ptr<uint8_t> pCtr : bounds(counter, counter + 4) = (_Array_ptr<uint8_t>)(&counter[3]);
#endif
    uint32_t     tmp _Checked[4];

    // Counter is really the IV for the encryption. The counter will take the
    // low-order 4 octets of the IV and use that as a counter.
    Pack32(counter, ctr);

    while (len) {

        // DJM: DICE (min->MIN)
        uint32_t n = MIN(len, 16);
		// TODO: casting ints to bytes, need a dynamic bounds cast
        _Array_ptr<uint8_t> p : byte_count(n) = 
			_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(tmp, byte_count(n));
        EncryptRounds(tmp, counter, (_Array_ptr<uint32_t>)&(*aes128EncryptKey));
        len -= n;
        while (n--) {
            *out++ = *p++ ^ *in++;
        }
        //
        // The counter field is big-endian because that is what is in the standard.
        //
#if HOST_IS_LITTLE_ENDIAN
        //
        // A big-endian increment of a 32 bit value on a little-endian CPU.
        //
        if ((pCtr[3] += 1) == 0)
            if ((pCtr[2] += 1) == 0)
                if ((pCtr[1] += 1) == 0)
                { pCtr[0] += 1; }
#else
        counter[3] += 1;
#endif
    }

    Unpack32(ctr, counter);
}
#endif

#if AES_CBC_MODE
void RIOT_AES_CBC_128_ENCRYPT(
    const aes128EncryptKey_t *aes128EncryptKey : itype(_Ptr<const aes128EncryptKey_t_ch>), 
    const uint8_t *in : byte_count(len),
    uint8_t *out : byte_count(len), 
    uint32_t len,
    uint8_t *iv : count(AES_BLOCK_SIZE))
{
    uint32_t xorbuf _Checked[AES_BLOCK_SIZE/sizeof(uint32_t)];
    uint32_t ivt _Checked[AES_BLOCK_SIZE/sizeof(uint32_t)];

    assert(len > 0 && (len % AES_BLOCK_SIZE) == 0);

    Pack32(ivt, iv);
    while (len) {
        uint32_t i;
		// We know from the assert that len is a multiple of AES_BLOCK_SIZE
        Pack32(xorbuf, _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(in, byte_count(AES_BLOCK_SIZE)));
        for (i = 0; i < AES_BLOCK_SIZE / sizeof(uint32_t); ++i) {
            xorbuf[i] ^= ivt[i];
        }

        // TODO: need bundled block here
        EncryptRounds(ivt, xorbuf, (_Array_ptr<uint32_t>)aes128EncryptKey);
		// We know from the assert that len is a multiple of AES_BLOCK_SIZE
        Unpack32(_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(out, byte_count(AES_BLOCK_SIZE)), ivt);
        out += AES_BLOCK_SIZE;
        in += AES_BLOCK_SIZE;
        len -= AES_BLOCK_SIZE;
    }
    Unpack32(iv, ivt);
}
#endif


#if AES_ECB_MODE
void RIOT_AES_ECB_128_ENCRYPT(const aes128EncryptKey_t *aes128EncryptKey : itype(_Ptr<const aes128EncryptKey_t_ch>),
	const uint8_t *in : byte_count(size),
	uint8_t *out : byte_count(size), size_t size)
{
    uint32_t in32 _Checked[4];
    uint32_t out32 _Checked[4];

    assert(size > 0 && (size % AES_BLOCK_SIZE) == 0);

    for (; size != 0; size -= AES_BLOCK_SIZE) {
		// We know from the assert that size is a multiple of AES_BLOCK_SIZE
        Pack32(in32, _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(in, byte_count(AES_BLOCK_SIZE)));
        EncryptRounds(out32, in32, (_Array_ptr<uint32_t>)aes128EncryptKey);
        Unpack32(_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(out, byte_count(AES_BLOCK_SIZE)), out32);
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
}
#endif

#define CRYPTO_TESTS

//
// Symmetric Test Functions
//
//#define CRYPTO_TESTS
#ifdef CRYPTO_TESTS

_Nt_array_ptr<const char> modes _Checked[] = {
#if AES_CTR_MODE
    "CTR",
#endif
#if AES_CBC_MODE
    "CBC",
#endif
#if AES_ECB_MODE
    "ECB",
#endif
    ""
};

_Array_ptr<_Nt_array_ptr<const char>> riot_aes_modes(void)
{
    return &modes[0];
}

#pragma CHECKED_SCOPE OFF

#endif
