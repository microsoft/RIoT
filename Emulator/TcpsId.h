#pragma once
#include <stdint.h>


#include <RiotStatus.h>
#include <RiotEcc.h>

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