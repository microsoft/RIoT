// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_BASE64_H
#define RIOT_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

uint32_t Base64Length(uint32_t ByteCount);

int
Base64Encode(
    const unsigned char *Input,
    uint32_t             Length,
    char                *Output,
    uint32_t            *OutLen
);

int
Base64Decode(
    const char      *Input,
    unsigned char   *Output,
    uint32_t        *OutLen
);

#ifdef __cplusplus
}
#endif

#endif
