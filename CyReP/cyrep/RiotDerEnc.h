/*(Copyright)

Microsoft Copyright 2015, 2016
Confidential Information

*/
#ifndef __RIOT_DER_ENC_H__
#define __RIOT_DER_ENC_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DER_MAX_PEM     0x500
#define DER_MAX_TBS     0x400
#define DER_MAX_NESTED  0x10

//
// Context structure for the DER-encoder. This structure contains a fixed-
// length array for nested SEQUENCES (which imposes a nesting limit).
// The buffer use for encoded data is caller-allocted.
//
typedef struct
{
    uint8_t     *Buffer;        // Encoded data
    uint32_t     Length;        // Size, in bytes, of Buffer
    uint32_t     Position;      // Current buffer position

    // SETS, SEQUENCES, etc. can be nested. This array contains the start of
    // the payload for collection types and is set by  DERStartSequenceOrSet().
    // Collections are "popped" using DEREndSequenceOrSet().
    int CollectionStart[DER_MAX_NESTED];
    int CollectionPos;
} DERBuilderContext;

// We only have a small subset of potential PEM encodings
enum RiotCertType {
    R_CERT_TYPE = 0,
    R_PUBLICKEY_TYPE,
    R_ECC_PRIVATEKEY_TYPE,
    R_CERT_REQ_TYPE,
    R_LAST_CERT_TYPE
};

void
DERInitContext(
    DERBuilderContext   *Context,
    uint8_t             *Buffer,
    uint32_t             Length
);

int
DERGetEncodedLength(
    DERBuilderContext   *Context
);


int
DERAddOID(
    DERBuilderContext   *Context,
    int                 *Values
);

int
DERAddUTF8String(
    DERBuilderContext   *Context,
    const char          *Str
);

int 
DERAddPrintableString(
    DERBuilderContext   *Context,
    const char          *Str
);


int
DERAddUTCTime(
    DERBuilderContext   *Context,
    const char          *Str
);

int
DERAddIntegerFromArray(
    DERBuilderContext   *Context,
    uint8_t             *Val,
    uint32_t            NumBytes
);

int
DERAddInteger(
    DERBuilderContext   *Context,
    int                 Val
);

int
DERAddShortExplicitInteger(
    DERBuilderContext   *Context,
    int                  Val
);

int
DERAddBoolean(
    DERBuilderContext   *Context,
    bool                 Val
);


int
DERAddBitString(
    DERBuilderContext   *Context,
    uint8_t             *BitString,
    uint32_t             BitStringNumBytes
);

int
DERAddSequenceOctets(
    DERBuilderContext   *Context,
    uint8_t             Num,
    uint8_t             *OctetString,
    uint32_t             OctetStringLen
);

int
DERAddOctetString(
    DERBuilderContext   *Context,
    uint8_t             *OctetString,
    uint32_t             OctetStringLen
);

int
DERStartSequenceOrSet(
    DERBuilderContext   *Context,
    bool                 Sequence
);

int
DERStartExplicit(
    DERBuilderContext   *Context,
    uint32_t             Num
);

int
DERStartEnvelopingOctetString(
    DERBuilderContext   *Context
);

int
DERStartEnvelopingBitString(
    DERBuilderContext   *Context
);

int
DERPopNesting(
    DERBuilderContext   *Context
);

int
DERGetNestingDepth(
    DERBuilderContext   *Context
);

int
DERTbsToCert(
    DERBuilderContext   *Context
);

int
DERtoPEM(
    DERBuilderContext   *Context,
    uint32_t            Type,
    char                *PEM,
    uint32_t            *Length
);

int
DERtoPEM_Term(
    DERBuilderContext   *Context,
    uint32_t            Type,
    char                *PEM,
    uint32_t            *Length
);

typedef struct
{
    const uint8_t     *Buffer;        // Encoded data
    uint32_t          Length;        // Size, in bytes, of Buffer
    uint32_t          Position;      // Current buffer position
} DERDecoderContext;

void
DERInitDecoder(
    DERDecoderContext   *Context,
    const uint8_t       *EncodedBuffer,
    uint32_t            Length
);

int
DERGetObjectLen(
    DERDecoderContext   *Context,
    uint32_t            *Len
);

int
DERGetSequenceOrSetLength(
    DERDecoderContext   *Context,
    bool                 Sequence,
    uint32_t            *Len
);

int
DERGetIntegerToArray(
    DERDecoderContext   *Context,
    uint8_t             *Val,
    uint32_t            NumBytes,
    uint32_t            *UsedBytes
);

#ifdef __cplusplus
}
#endif

#endif // __RIOT_DER_ENC_H__
