/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include "RiotCrypt.h"

#pragma CHECKED_SCOPE ON

#define RIOT_MAX_KDF_FIXED_SIZE     RIOT_MAX_KDF_CONTEXT_LENGTH + \
                                    RIOT_MAX_KDF_LABEL_LENGTH   + 5

RIOT_STATUS
RiotCrypt_Kdf(
    uint8_t        *result  : byte_count(resultSize),        // OUT: Buffer to receive the derived bytes
    size_t          resultSize,                              // IN:  Capacity of the result buffer
    const uint8_t  *source  : byte_count(sourceSize),        // IN:  Initial data for derivation
    size_t          sourceSize,                              // IN:  Size of the source data in bytes
    const uint8_t  *context : byte_count(contextSize),       // IN:  Derivation context (may be NULL)
    size_t          contextSize,                             // IN:  Size of the context in bytes
    const uint8_t  *label   : itype(_Nt_array_ptr<const uint8_t>) byte_count(labelSize),  // IN:  Label for derivation (may be NULL)
    size_t          labelSize,                               // IN:  Size of the label in bytes
    uint32_t        bytesToDerive                            // IN:  Number of bytes to be produced
)
{
    uint8_t  fixed _Checked[RIOT_MAX_KDF_FIXED_SIZE];
    size_t   fixedSize = sizeof(fixed);
    uint32_t counter = 0;

    if (contextSize > RIOT_MAX_KDF_CONTEXT_LENGTH ||
        labelSize > RIOT_MAX_KDF_LABEL_LENGTH ||
        bytesToDerive > resultSize ||
        bytesToDerive % RIOT_KEY_LENGTH != 0) {
        return RIOT_INVALID_PARAMETER;
    }

	_Array_ptr<uint8_t> fixedPtr : byte_count(fixedSize) = 
		_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&fixed[0], byte_count(fixedSize));
    
    // Fixed a bug in the call to RIOT_KDF_FIXED below: 
    // the argument pairs (label, labelSize) and (context, contextSize)
    // had been swapped previously. Caught by making label of type
    // _Nt_array_ptr (aka a string).
    fixedSize = RIOT_KDF_FIXED(fixedPtr, fixedSize, label, labelSize, context, contextSize, bytesToDerive * 8);

    while (counter < (bytesToDerive / (RIOT_KEY_LENGTH))) {
		// TODO: We know from the if statement above that 
		// resultSize >= bytesToDerive == counterMax * RIOT_KEY_LENGTH
		// For any particular call, we care about a much smaller
		// portion of result's bounds, so dynamically bounds cast.
		_Array_ptr<uint8_t> resultSmallBounds : byte_count(RIOT_KEY_LENGTH) = 
			_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(result + (counter * RIOT_KEY_LENGTH), byte_count(RIOT_KEY_LENGTH));

        RIOT_KDF_SHA256(resultSmallBounds,
                        source, sourceSize, &counter,
                        fixedPtr, fixedSize);
    }

    return RIOT_SUCCESS;
}

typedef RIOT_SHA256_CONTEXT     RIOT_HASH_CONTEXT;

#define RiotCrypt_HashInit      RIOT_SHA256_Init
#define RiotCrypt_HashUpdate    RIOT_SHA256_Update
#define RiotCrypt_HashFinal     RIOT_SHA256_Final

RIOT_STATUS
RiotCrypt_Hash(
	uint8_t        *result : byte_count(resultSize),   // OUT: Buffer to receive the digest
	size_t          resultSize,                        // IN:  Capacity of the result buffer
	const void     *data : byte_count(dataSize),       // IN:  Data to hash
	size_t          dataSize                           // IN:  Data size in bytes
)
{
    RIOT_HASH_CONTEXT ctx;

    if (resultSize < RIOT_DIGEST_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

	// TODO: unsigned comparison on resultSize, needs dynamic bounds cast
	_Array_ptr<uint8_t> tmp_result : byte_count(RIOT_DIGEST_LENGTH) = 
		_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(result, byte_count(RIOT_DIGEST_LENGTH));

    RiotCrypt_HashInit(&ctx);
    RiotCrypt_HashUpdate(&ctx, data, dataSize);
    RiotCrypt_HashFinal(&ctx, tmp_result);

    return RIOT_SUCCESS;
}

RIOT_STATUS
RiotCrypt_Hash2(
	uint8_t        *result : byte_count(resultSize),  // OUT: Buffer to receive the digest
	size_t          resultSize,                       // IN:  Capacity of the result buffer
	const void     *data1  : byte_count(data1Size),   // IN:  1st operand to hash
	size_t          data1Size,                        // IN:  1st operand size in bytes
	const void     *data2  : byte_count(data2Size),   // IN:  2nd operand to hash
	size_t          data2Size                         // IN:  2nd operand size in bytes
)
{
    RIOT_HASH_CONTEXT ctx;

    if (resultSize < RIOT_DIGEST_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

	// TODO: unsigned comparison on resultSize, needs dynamic bounds cast
	_Array_ptr<uint8_t> tmp_result : byte_count(RIOT_DIGEST_LENGTH) =
		_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(result, byte_count(RIOT_DIGEST_LENGTH));

    RiotCrypt_HashInit(&ctx);
    RiotCrypt_HashUpdate(&ctx, data1, data1Size);
    RiotCrypt_HashUpdate(&ctx, data2, data2Size);
    RiotCrypt_HashFinal(&ctx, tmp_result);

    return RIOT_SUCCESS;
}

typedef RIOT_HMAC_SHA256_CTX    RIOT_HMAC_CONTEXT;

#define RiotCrypt_HmacInit      RIOT_HMAC_SHA256_Init
#define RiotCrypt_HmacUpdate    RIOT_HMAC_SHA256_Update
#define RiotCrypt_HmacFinal     RIOT_HMAC_SHA256_Final

RIOT_STATUS
RiotCrypt_Hmac(
	uint8_t        *result : byte_count(resultCapacity),  // OUT: Buffer to receive the HMAC
	size_t          resultCapacity,                       // IN:  Capacity of the result buffer
	const void     *data   : byte_count(dataSize),        // IN:  Data to HMAC
	size_t          dataSize,                             // IN:  Data size in bytes
	const uint8_t  *key    : byte_count(keySize),         // IN:  HMAC key
	size_t          keySize                               // IN:  HMAC key size in bytes
)
{
    RIOT_HMAC_CONTEXT ctx;

    if (resultCapacity < RIOT_HMAC_LENGTH ||
        keySize != RIOT_HMAC_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

	// TODO: unsigned comparison on resultSize, needs dynamic bounds cast
	_Array_ptr<uint8_t> tmp_result : byte_count(RIOT_HMAC_LENGTH) =
		_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(result, byte_count(RIOT_HMAC_LENGTH));

    RiotCrypt_HmacInit(&ctx, key, keySize);
    RiotCrypt_HmacUpdate(&ctx, data, dataSize);
    RiotCrypt_HmacFinal(&ctx, tmp_result);

    return RIOT_SUCCESS;
}

RIOT_STATUS
RiotCrypt_Hmac2(
	uint8_t        *result : byte_count(resultCapacity),  // OUT: Buffer to receive the HMAC
	size_t          resultCapacity,                       // IN:  Capacity of the result buffer
	const void     *data1  : byte_count(data1Size),       // IN:  1st operand to HMAC
	size_t          data1Size,                            // IN:  1st operand size in bytes
	const void     *data2  : byte_count(data2Size),       // IN:  2nd operand to HMAC
	size_t          data2Size,                            // IN:  2nd operand size in bytes
	const uint8_t  *key    : byte_count(keySize),         // IN:  HMAC key
	size_t          keySize                               // IN:  HMAC key size in bytes
)
{
    RIOT_HMAC_CONTEXT ctx;

    if (resultCapacity < RIOT_HMAC_LENGTH ||
        keySize != RIOT_HMAC_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

	// TODO: unsigned comparison on resultSize, needs dynamic bounds cast
	_Array_ptr<uint8_t> tmp_result : byte_count(RIOT_HMAC_LENGTH) =
		_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(result, byte_count(RIOT_HMAC_LENGTH));

    RiotCrypt_HmacInit(&ctx, key, keySize);
    RiotCrypt_HmacUpdate(&ctx, data1, data1Size);
    RiotCrypt_HmacUpdate(&ctx, data2, data2Size);
    RiotCrypt_HmacFinal(&ctx, tmp_result);

    return RIOT_SUCCESS;
}

RIOT_STATUS
RiotCrypt_DeriveEccKey(
    RIOT_ECC_PUBLIC    *publicPart  : itype(_Ptr<RIOT_ECC_PUBLIC>),                                    // OUT: Derived public key
    RIOT_ECC_PRIVATE   *privatePart : itype(_Ptr<RIOT_ECC_PRIVATE>),                                   // OUT: Derived private key
    const void         *srcData     : byte_count(srcDataSize),                                         // IN:  Initial data for derivation
    size_t              srcDataSize,                                                                   // IN:  Size of the source data in bytes
    const uint8_t      *label       : itype(_Nt_array_ptr<const uint8_t>) byte_count(labelSize), // IN:  Label for derivation (may be NULL)
    size_t              labelSize                                                                      // IN:  Size of the label in bytes
)
{
    bigval_t       srcVal  = { 0 };
	_Ptr<bigval_t> pSrcVal = NULL;

    if (srcDataSize > sizeof(bigval_t)) {
        return RIOT_INVALID_PARAMETER;
    }

    if (srcDataSize == sizeof(bigval_t)) {
		_Array_ptr<const void> explicitlySizedSrcData : byte_count(sizeof(bigval_t)) = 
			_Dynamic_bounds_cast<_Array_ptr<const void>>(srcData, byte_count(sizeof(bigval_t)));
        pSrcVal = (_Ptr<bigval_t>)explicitlySizedSrcData;
    } else { // size is smaller than a bigval_t, so have to pass by bytes
		_Array_ptr<uint8_t> tmp : byte_count(srcDataSize) = _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&srcVal, byte_count(srcDataSize));
        memcpy(tmp, srcData, srcDataSize);
        pSrcVal = &srcVal;
    }

    return RIOT_DeriveDsaKeyPair(publicPart, privatePart,
                                 pSrcVal, label, labelSize);
}

void
RiotCrypt_ExportEccPub(
    RIOT_ECC_PUBLIC     *a : itype(_Ptr<RIOT_ECC_PUBLIC>),           // IN:  ECC Public Key to export
    uint8_t             *b : byte_count(1 + 2*RIOT_ECC_COORD_BYTES), // OUT: Buffer to receive the public key
    uint32_t            *s : itype(_Ptr<uint32_t>)                   // OUT: Pointer to receive the buffer size (may be NULL)
)
{
    *b++ = 0x04;
    BigValToBigInt(b, &a->x);
    b += RIOT_ECC_COORD_BYTES;
    BigValToBigInt(b, &a->y);
    if (s) {
        *s = 1 + 2 * RIOT_ECC_COORD_BYTES;
    }
}


RIOT_STATUS
RiotCrypt_Sign(
	RIOT_ECC_SIGNATURE     *sig  : itype(_Ptr<RIOT_ECC_SIGNATURE>),     // OUT: Signature of data
	const void             *data : byte_count(dataSize),                // IN:  Data to sign
	size_t                  dataSize,                                   // IN:  Data size in bytes
	const RIOT_ECC_PRIVATE *key  : itype(_Ptr<const RIOT_ECC_PRIVATE>)  // IN:  Signing key
)
{
    uint8_t digest _Checked[RIOT_DIGEST_LENGTH];

    RiotCrypt_Hash(digest, sizeof(digest), data, dataSize);

    return RIOT_DSASignDigest(digest, key, sig);
}

RIOT_STATUS
RiotCrypt_SignDigest(
    RIOT_ECC_SIGNATURE     *sig    : itype(_Ptr<RIOT_ECC_SIGNATURE>),    // OUT: Signature of digest
    const uint8_t          *digest : byte_count(digestSize),             // IN:  Digest to sign
    size_t                  digestSize,                                  // IN:  Size of the digest in bytes
    const RIOT_ECC_PRIVATE *key    : itype(_Ptr<const RIOT_ECC_PRIVATE>) // IN:  Signing key
)
{
    if (digestSize != RIOT_DIGEST_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

	_Array_ptr<const uint8_t> digestExplicitSize : count(RIOT_DIGEST_LENGTH) = _Dynamic_bounds_cast<_Array_ptr<const uint8_t>>(digest, count(RIOT_DIGEST_LENGTH));

    return RIOT_DSASignDigest(digestExplicitSize, key, sig);
}

RIOT_STATUS
RiotCrypt_Verify(
    const void                 *data : byte_count(dataSize),                  // IN: Data to verify signature of
    size_t                      dataSize,                                       // IN: Size of data in bytes
    const RIOT_ECC_SIGNATURE   *sig  : itype(_Ptr<const RIOT_ECC_SIGNATURE>), // IN: Signature to verify
    const RIOT_ECC_PUBLIC      *key  : itype(_Ptr<const RIOT_ECC_PUBLIC>)       // IN: ECC public key of signer
)
{
    uint8_t digest _Checked[RIOT_DIGEST_LENGTH];

    RiotCrypt_Hash(digest, sizeof(digest), data, dataSize);

    return RIOT_DSAVerifyDigest(digest, sig, key);
}

RIOT_STATUS
RiotCrypt_VerifyDigest(
	const uint8_t              *digest : byte_count(digestSize),               // IN: Digest to verify signature of
	size_t                      digestSize,                                     // IN: Size of the digest
	const RIOT_ECC_SIGNATURE   *sig    : itype(_Ptr<const RIOT_ECC_SIGNATURE>), // IN: Signature to verify
	const RIOT_ECC_PUBLIC      *key    : itype(_Ptr<const RIOT_ECC_PUBLIC>)     // IN: ECC public key of signer
)
{
    if (digestSize != RIOT_DIGEST_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

	_Array_ptr<const uint8_t> digestExplicitlySized : count(RIOT_DIGEST_LENGTH) = _Dynamic_bounds_cast<_Array_ptr<const uint8_t>>(digest, count(RIOT_DIGEST_LENGTH));
    return RIOT_DSAVerifyDigest(digestExplicitlySized, sig, key);
}

#if USES_EPHEMERAL
#define RIOT_LABEL_EXCHANGE     "Exchange"
RIOT_STATUS
RiotCrypt_EccEncrypt(
	uint8_t                *result : byte_count(resultCapacity),         // OUT: Buffer to receive encrypted data
	size_t                  resultCapacity,                              // IN:  Capacity of the result buffer
	RIOT_ECC_PUBLIC        *ephKey : itype(_Ptr<RIOT_ECC_PUBLIC>),       // OUT: Ephemeral key to produce
	const void             *data   : byte_count(dataSize),               // IN:  Data to encrypt
	size_t                  dataSize,                                    // IN:  Data size in bytes
	const RIOT_ECC_PUBLIC  *key    : itype(_Ptr<const RIOT_ECC_PUBLIC>)  // IN:  Encryption key
)
{
    ecc_privatekey  ephPriv;
    ecc_secret      secret;
    uint8_t         exchKey _Checked[RIOT_KEY_LENGTH];
    RIOT_STATUS     status;

    status = RIOT_GenerateDHKeyPair(ephKey, &ephPriv);

    if (status != RIOT_SUCCESS) {
        return status;
    }

    status = RIOT_GenerateShareSecret((_Ptr<RIOT_ECC_PUBLIC>)key, &ephPriv, &secret);

    if (status != RIOT_SUCCESS) {
        return status;
    }

	_Array_ptr<uint8_t> secretPtr : byte_count(sizeof(secret)) = _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&secret, byte_count(sizeof(secret)));

    status = RiotCrypt_Kdf(exchKey, sizeof(exchKey),
                           secretPtr, sizeof(secret),
                           NULL, 0, (_Nt_array_ptr<const uint8_t>)RIOT_LABEL_EXCHANGE,
                           (sizeof(RIOT_LABEL_EXCHANGE) - 1),
                           sizeof(exchKey));

    if (status != RIOT_SUCCESS) {
        return status;
    }

    status = RiotCrypt_SymEncryptDecrypt(result, resultCapacity,
                                         data, dataSize, exchKey);
    return status;
}

RIOT_STATUS
RiotCrypt_EccDecrypt(
	uint8_t                *result : byte_count(resultCapacity),          // OUT: Buffer to receive decrypted data
	size_t                  resultCapacity,                               // IN:  Capacity of the result buffer
	const void             *data   : byte_count(dataSize),                // IN:  Data to decrypt
	size_t                  dataSize,                                     // IN:  Data size in bytes
	RIOT_ECC_PUBLIC        *ephKey : itype(_Ptr<RIOT_ECC_PUBLIC>),        // IN:  Ephemeral key to produce
	const RIOT_ECC_PRIVATE *key    : itype(_Ptr<const RIOT_ECC_PRIVATE>)  // IN:  Decryption key
)
{
    ecc_secret      secret;
    uint8_t         exchKey _Checked[RIOT_KEY_LENGTH];
    RIOT_STATUS     status;

    status = RIOT_GenerateShareSecret(ephKey, (_Ptr<RIOT_ECC_PRIVATE>)key, &secret);

    if (status != RIOT_SUCCESS) {
        return status;
    }

	_Array_ptr<uint8_t> secretInBytes : byte_count(sizeof(secret)) = 
		_Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&secret, byte_count(sizeof(secret)));

    status = RiotCrypt_Kdf(exchKey, sizeof(exchKey),
                           secretInBytes, sizeof(secret),
                           NULL, 0, (_Nt_array_ptr<const uint8_t>)RIOT_LABEL_EXCHANGE,
                           (sizeof(RIOT_LABEL_EXCHANGE) - 1),
                           sizeof(exchKey));

    if (status != RIOT_SUCCESS) {
        return status;
    }

    status = RiotCrypt_SymEncryptDecrypt(result, resultCapacity,
                                         data, dataSize, exchKey);
    return status;
}
#endif

RIOT_STATUS
RiotCrypt_SymEncryptDecrypt(
	void       *outData                  : byte_count(outSize),                                          // OUT: Output data
	size_t      outSize,                                                                                 // IN:  Size of output data in bytes
	const void *inData                   : byte_count(inSize),                                           // IN:  Input data
	size_t      inSize,                                                                                  // IN:  Size of input data in bytes
	uint8_t     key[RIOT_SYM_KEY_LENGTH] : itype(uint8_t _Checked[RIOT_SYM_KEY_LENGTH])   // IN/OUT: Symmetric key & IV
)
{
	// TODO: iv is the second half of key. Need a dynamic bounds cast.
    _Array_ptr<uint8_t>    iv : byte_count(AES_BLOCK_SIZE) = _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(key + 16, byte_count(AES_BLOCK_SIZE));
    aes128EncryptKey_t_ch  aesKey;

    if (outSize < inSize) {
        return RIOT_INVALID_PARAMETER;
    }

	// TODO: For AES_CTR_128, outsize must exactly == inSize. Dynamic bounds cast needed to shrink
    // TODO: Since the length inSize is cast to uint32_t, need to explicitly cast the bounds as well. This is a pain.
	_Array_ptr<void> tmpOutData : byte_count((uint32_t)inSize) = _Dynamic_bounds_cast<_Array_ptr<void>>(outData, byte_count((uint32_t)inSize));
    _Array_ptr<void> tmpInData  : byte_count((uint32_t)inSize) = _Dynamic_bounds_cast<_Array_ptr<void>>(inData,  byte_count((uint32_t)inSize));

    RIOT_AES128_Enable(key, &aesKey);
    RIOT_AES_CTR_128((_Ptr<const aes128EncryptKey_t_ch>)&aesKey, tmpInData, tmpOutData, (uint32_t)inSize, iv);
    RIOT_AES128_Disable(&aesKey);

    return RIOT_SUCCESS;
}

#pragma CHECKED_SCOPE OFF
