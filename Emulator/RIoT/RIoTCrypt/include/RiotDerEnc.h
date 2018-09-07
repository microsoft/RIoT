/*(Copyright)

Microsoft Copyright 2015, 2016
Confidential Information

*/
#pragma once

#include <stdlib_checked.h>

#ifdef __cplusplus
extern "C" {
#endif 
#pragma CHECKED_SCOPE ON

#define DER_MAX_PEM     0x400
#define DER_MAX_TBS     0x300
#define DER_MAX_NESTED  0x10

//
// Context structure for the DER-encoder. This structure contains a fixed-
// length array for nested SEQUENCES (which imposes a nesting limit).
// The buffer use for encoded data is caller-allocted.
//
typedef struct
{
    uint8_t     *Buffer : itype(_Array_ptr<uint8_t>) byte_count(Length);    // Encoded data
    uint32_t     Length;													// Size, in bytes, of Buffer
    uint32_t     Position;													// Current buffer position

    // SETS, SEQUENCES, etc. can be nested. This array contains the start of
    // the payload for collection types and is set by  DERStartSequenceOrSet().
    // Collections are "popped" using DEREndSequenceOrSet().
    int CollectionStart[DER_MAX_NESTED] : itype(int _Checked[DER_MAX_NESTED]);
    int CollectionPos;
} DERBuilderContext;

// We only have a small subset of potential PEM encodings
enum CertType {
    CERT_TYPE = 0,
    PUBLICKEY_TYPE,
    ECC_PRIVATEKEY_TYPE,
    CERT_REQ_TYPE,
    LAST_CERT_TYPE
};

void
DERInitContext(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    uint8_t             *Buffer  : itype(_Array_ptr<uint8_t>) byte_count((size_t)Length),
    uint32_t             Length
);

int
DERGetEncodedLength(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>)
);

// Add an OID. The OID is an int-array (max 16) terminated with -1 
// (actually any negative number)
// TODO: We can't handle nonzero terminators. Unchecked for now
_Unchecked int
DERAddOID(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    int                 *Values  : itype(_Array_ptr<int>)
);

int
DERAddUTF8String(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    const char          *Str     : itype(_Nt_array_ptr<const char>)
);

int 
DERAddPrintableString(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    const char          *Str     : itype(_Nt_array_ptr<const char>)
);


int
DERAddUTCTime(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    const char          *Str     : itype(_Nt_array_ptr<const char>)
);

// Input integer is assumed unsigned with most signficant byte first.
// A leading zero will be added if the most significant input bit is set.
// Leading zeros in the input number will be removed.
int
DERAddIntegerFromArray(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    uint8_t             *Val     : itype(_Array_ptr<uint8_t>) byte_count((size_t)NumBytes),
    uint32_t            NumBytes
);

int
DERAddInteger(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    int                 Val
);

int
DERAddShortExplicitInteger(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    int                  Val
);

int
DERAddBoolean(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    bool                 Val
);


int
DERAddBitString(
    DERBuilderContext   *Context   : itype(_Ptr<DERBuilderContext>),
    uint8_t             *BitString : itype(_Array_ptr<uint8_t>) byte_count((size_t)BitStringNumBytes),
    uint32_t             BitStringNumBytes
);

int
DERAddOctetString(
    DERBuilderContext   *Context     : itype(_Ptr<DERBuilderContext>),
    uint8_t             *OctetString : itype(_Array_ptr<uint8_t>) byte_count((size_t)OctetStringLen),
    uint32_t             OctetStringLen
);

int
DERStartSequenceOrSet(
    DERBuilderContext   *Context  : itype(_Ptr<DERBuilderContext>),
    bool                 Sequence
);

int
DERStartExplicit(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    uint32_t             Num
);

int
DERStartEnvelopingOctetString(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>)
);

int
DERStartEnvelopingBitString(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>)
);

int
DERPopNesting(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>)
);

int
DERGetNestingDepth(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>)
);

int
DERTbsToCert(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>)
);


int
DERtoPEM(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    uint32_t            Type,
    char                *PEM     : itype(_Nt_array_ptr<char>) count(*Length),
    uint32_t            *Length  : itype(_Ptr<uint32_t>)
);

#pragma CHECKED_SCOPE OFF

#ifdef __cplusplus
}
#endif
