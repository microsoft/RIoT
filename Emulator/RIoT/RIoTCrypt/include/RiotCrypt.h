/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/

//
// This source implements the interface between the RIoT framework and
// its cryptographic functions.
//

#ifndef _RIOT_CRYPTO_H
#define _RIOT_CRYPTO_H

//
// As the RIoT framework is minimalistic, it will normally support only one
// flavor of each cryptographic operation, i.e., one key strength, one digest
// size, etc.
//
// Macro definitions and typedefs in this header provide the level of
// indirection to allow changing cryptographic primitives, parameters,
// and/or underlying crypto libraries with no or minimal impact on the
// reference code.
//

#include <stdint.h>
#include <stdbool.h>
#include "RiotSha256.h"
#include "RiotAes128.h"
#include "RiotHmac.h"
#include "RiotKdf.h"
#include "RiotEcc.h"
#include "RiotBase64.h"

#pragma CHECKED_SCOPE ON

// Size, in bytes, of a RIoT digest using the chosen hash algorithm.
#define RIOT_DIGEST_LENGTH      SHA256_DIGEST_LENGTH

// Size, in bytes, of a RIoT HMAC.
#define RIOT_HMAC_LENGTH        RIOT_DIGEST_LENGTH

// Size, in bytes, of internal keys used by the RIoT framework.
// NOTE:    This number of bytes is used for key derivation.
#define RIOT_KEY_LENGTH         RIOT_DIGEST_LENGTH

// Number of bits in internal symmetric keys used by the RIoT framework.
// NOTE:    This number of bits is used for key derivation. The symmetric
//          algorithm implemenbted by the RIoT framework may use only a
//          subset of these bytes for encryption.
#define RIOT_KEY_BITS           (RIOT_KEY_LENGTH * 8)

// Number of bytes in symmetric encryption keys used by the RIoT framework.
// This number also includes IV/Counter bytes.
#define RIOT_SYM_KEY_LENGTH             (16 + 16)

// Size, in bytes, of encoded RIoT Key length
#define RIOT_ENCODED_BUFFER_MAX         (0x80)

// Maximal number of bytes in a label/context passed to the RIoT KDF routine.
#define RIOT_MAX_KDF_CONTEXT_LENGTH     RIOT_DIGEST_LENGTH

// Maximal number of bytes in a label/context passed to the RIoT KDF routine.
#define RIOT_MAX_KDF_LABEL_LENGTH       RIOT_DIGEST_LENGTH

// Maximal number of bytes in a RIOT_AIK certificate
#define RIOT_MAX_CERT_LENGTH        2048

typedef ecc_publickey           RIOT_ECC_PUBLIC;
typedef ecc_privatekey          RIOT_ECC_PRIVATE;
typedef ecc_signature           RIOT_ECC_SIGNATURE;

typedef enum {
    RIOT_ENCRYPT,
    RIOT_DECRYPT
} RIOT_CRYPT_OP_TYPE;

RIOT_STATUS
RiotCrypt_Kdf(
    uint8_t        *result  : byte_count(resultSize),                                         // OUT: Buffer to receive the derived bytes
    size_t          resultSize,                                                               // IN:  Capacity of the result buffer
    const uint8_t  *source  : byte_count(sourceSize),                                         // IN:  Initial data for derivation
    size_t          sourceSize,                                                               // IN:  Size of the source data in bytes
    const uint8_t  *context : byte_count(contextSize),                                        // IN:  Derivation context (may be NULL)
    size_t          contextSize,                                                              // IN:  Size of the context in bytes
    const uint8_t  *label   : itype(_Nt_array_ptr<const uint8_t>) byte_count(labelSize),  // IN:  Label for derivation (may be NULL)
    size_t          labelSize,                                                                // IN:  Size of the label in bytes
    uint32_t        bytesToDerive                                                             // IN:  Number of bytes to be produced
);

RIOT_STATUS
RiotCrypt_Hash(
    uint8_t        *result : byte_count(resultSize),            // OUT: Buffer to receive the digest
    size_t          resultSize,                                 // IN:  Capacity of the result buffer
    const void     *data   : byte_count(dataSize),              // IN:  Data to hash
    size_t          dataSize                                                                  // IN:  Data size in bytes
);

RIOT_STATUS
RiotCrypt_Hash2(
    uint8_t        *result : byte_count(resultSize),            // OUT: Buffer to receive the digest
    size_t          resultSize,                                 // IN:  Capacity of the result buffer
    const void     *data1  : byte_count(data1Size),             // IN:  1st operand to hash
    size_t          data1Size,                                  // IN:  1st operand size in bytes
    const void     *data2  : byte_count(data2Size),             // IN:  2nd operand to hash
    size_t          data2Size                                   // IN:  2nd operand size in bytes
);

RIOT_STATUS
RiotCrypt_Hmac(
    uint8_t        *result : byte_count(resultCapacity),        // OUT: Buffer to receive the HMAC
    size_t          resultCapacity,                             // IN:  Capacity of the result buffer
    const void     *data   : byte_count(dataSize),              // IN:  Data to HMAC
    size_t          dataSize,                                   // IN:  Data size in bytes
    const uint8_t  *key    : byte_count(keySize),               // IN:  HMAC key
    size_t          keySize                                     // IN:  HMAC key size in bytes
);

RIOT_STATUS
RiotCrypt_Hmac2(
    uint8_t        *result : byte_count(resultCapacity),        // OUT: Buffer to receive the HMAC
    size_t          resultCapacity,                             // IN:  Capacity of the result buffer
    const void     *data1  : byte_count(data1Size),             // IN:  1st operand to HMAC
    size_t          data1Size,                                  // IN:  1st operand size in bytes
    const void     *data2  : byte_count(data2Size),             // IN:  2nd operand to HMAC
    size_t          data2Size,                                  // IN:  2nd operand size in bytes
    const uint8_t  *key    : byte_count(keySize),               // IN:  HMAC key
    size_t          keySize                                     // IN:  HMAC key size in bytes
);

RIOT_STATUS
RiotCrypt_DeriveEccKey(
    RIOT_ECC_PUBLIC    *publicPart  : itype(_Ptr<RIOT_ECC_PUBLIC>),    // OUT: Derived public key
    RIOT_ECC_PRIVATE   *privatePart : itype(_Ptr<RIOT_ECC_PRIVATE>),   // OUT: Derived private key
    const void         *srcData     : byte_count(srcDataSize),         // IN:  Initial data for derivation
    size_t              srcDataSize,                                   // IN:  Size of the source data in bytes
    const uint8_t      *label       : itype(_Nt_array_ptr<const uint8_t>) byte_count(labelSize),           // IN:  Label for derivation (may be NULL)
    size_t              labelSize                                      // IN:  Size of the label in bytes
);

void
RiotCrypt_ExportEccPub(
    RIOT_ECC_PUBLIC     *a : itype(_Ptr<RIOT_ECC_PUBLIC>),           // IN:  ECC Public Key to export
    uint8_t             *b : byte_count(1 + 2*RIOT_ECC_COORD_BYTES), // OUT: Buffer to receive the public key
    uint32_t            *s : itype(_Ptr<uint32_t>)                   // OUT: Pointer to receive the buffer size (may be NULL)
);

RIOT_STATUS
RiotCrypt_Sign(
    RIOT_ECC_SIGNATURE     *sig  : itype(_Ptr<RIOT_ECC_SIGNATURE>),    // OUT: Signature of data
    const void             *data : byte_count(dataSize),               // IN:  Data to sign
    size_t                  dataSize,                                  // IN:  Data size in bytes
    const RIOT_ECC_PRIVATE *key  : itype(_Ptr<const RIOT_ECC_PRIVATE>) // IN:  Signing key
);

RIOT_STATUS
RiotCrypt_SignDigest(
    RIOT_ECC_SIGNATURE     *sig    : itype(_Ptr<RIOT_ECC_SIGNATURE>),      // OUT: Signature of digest
    const uint8_t          *digest : byte_count(digestSize),               // IN:  Digest to sign
    size_t                  digestSize,                                    // IN:  Size of the digest in bytes
    const RIOT_ECC_PRIVATE *key    : itype(_Ptr<const RIOT_ECC_PRIVATE>)   // IN:  Signing key
);

RIOT_STATUS
RiotCrypt_Verify(
    const void                 *data : byte_count(dataSize),    // IN: Data to verify signature of
    size_t                      dataSize,                                                     // IN: Size of data in bytes
    const RIOT_ECC_SIGNATURE   *sig  : itype(_Ptr<const RIOT_ECC_SIGNATURE>),                 // IN: Signature to verify
    const RIOT_ECC_PUBLIC      *key  : itype(_Ptr<const RIOT_ECC_PUBLIC>)                     // IN: ECC public key of signer
);

RIOT_STATUS
RiotCrypt_VerifyDigest(
    const uint8_t              *digest : byte_count(digestSize),                 // IN: Digest to verify signature of
    size_t                      digestSize,                                      // IN: Size of the digest
    const RIOT_ECC_SIGNATURE   *sig    : itype(_Ptr<const RIOT_ECC_SIGNATURE>),  // IN: Signature to verify
    const RIOT_ECC_PUBLIC      *key    : itype(_Ptr<const RIOT_ECC_PUBLIC>)      // IN: ECC public key of signer
);

RIOT_STATUS
RiotCrypt_EccEncrypt(
    uint8_t                *result : byte_count(resultCapacity),         // OUT: Buffer to receive encrypted data
    size_t                  resultCapacity,                              // IN:  Capacity of the result buffer
    RIOT_ECC_PUBLIC        *ephKey : itype(_Ptr<RIOT_ECC_PUBLIC>),       // OUT: Ephemeral key to produce
    const void             *data   : byte_count(dataSize),               // IN:  Data to encrypt
    size_t                  dataSize,                                    // IN:  Data size in bytes
    const RIOT_ECC_PUBLIC  *key    : itype(_Ptr<const RIOT_ECC_PUBLIC>)  // IN:  Encryption key
);

RIOT_STATUS
RiotCrypt_EccDecrypt(
    uint8_t                *result : byte_count(resultCapacity),          // OUT: Buffer to receive decrypted data
    size_t                  resultCapacity,                               // IN:  Capacity of the result buffer
    const void             *data   : byte_count(dataSize),                // IN:  Data to decrypt
    size_t                  dataSize,                                     // IN:  Data size in bytes
    RIOT_ECC_PUBLIC        *ephKey : itype(_Ptr<RIOT_ECC_PUBLIC>),        // IN:  Ephemeral key to produce
    const RIOT_ECC_PRIVATE *key    : itype(_Ptr<const RIOT_ECC_PRIVATE>)  // IN:  Decryption key
);

RIOT_STATUS
RiotCrypt_SymEncryptDecrypt(
    void       *outData                  : byte_count(outSize),                                // OUT: Output data
    size_t      outSize,                                                                       // IN:  Size of output data in bytes
    const void *inData                   : byte_count(inSize),                                 // IN:  Input data
    size_t      inSize,                                                                        // IN:  Size of input data in bytes
    uint8_t     key[RIOT_SYM_KEY_LENGTH] : itype(uint8_t _Checked[RIOT_SYM_KEY_LENGTH])        // IN/OUT: Symmetric key & IV
);

#pragma CHECKED_SCOPE OFF

#endif