#ifndef _TCPS_CBOR_ID_H
#define _TCPS_CBOR_ID_H
/******************************************************************************
* Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

// TODO: define a common header that tooling and agent can 
//  share the following defines.
#define TCPS_ID_MAP_VER_CURENT    1

#define TCPS_IDENTITY_MAP_VER      "VER"
#define TCPS_IDENTITY_MAP_FWID     "FIRMWID"
#define TCPS_IDENTITY_MAP_AUTH     "CODEAUTH"
#define TCPS_IDENTITY_MAP_PUBKEY   "PUBKEY"

typedef struct _TcpsAssertion {
    char *Name;
    uint8_t *Data;
    uint32_t DataSize;
}TcpsAssertion;

RIOT_STATUS
BuildTCPSAliasIdentity(
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **Id,
    uint32_t *IdSize
);

RIOT_STATUS
BuildTCPSDeviceIdentity(
    RIOT_ECC_PUBLIC *Pub,
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **Id,
    uint32_t *IdSize
);

void
FreeTCPSId(
    uint8_t *Id
);

#ifdef __cplusplus
}
#endif
#endif
