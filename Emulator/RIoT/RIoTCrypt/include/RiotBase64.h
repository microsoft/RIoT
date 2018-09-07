// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_BASE64_H
#define RIOT_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma CHECKED_SCOPE ON

#define Base64Length(l) ((l == 0) ? (1) : (((((l - 1) / 3) + 1) * 4) + 1))

int
Base64Encode(
    const unsigned char *Input  : itype(_Nt_array_ptr<const unsigned char>) byte_count(Length),
    uint32_t             Length,
    char                *Output : itype(_Nt_array_ptr<char>),
    uint32_t            *OutLen : itype(_Ptr<uint32_t>) // Optional, may be NULL
);

int
Base64Decode(
    const char      *Input  : itype(_Nt_array_ptr<const char>),
    unsigned char   *Output : itype(_Nt_array_ptr<unsigned char>) count(*OutLen),
    uint32_t        *OutLen : itype(_Ptr<uint32_t>) 
);

#pragma CHECKED_SCOPE OFF

#ifdef __cplusplus
}
#endif

#endif
