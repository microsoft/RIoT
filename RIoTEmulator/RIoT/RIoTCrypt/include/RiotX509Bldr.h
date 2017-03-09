#ifndef _RIOT_X509_BLDR_H
#define _RIOT_X509_BLDR_H

#include "RiotCrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RIOT_X509_SNUM_LEN  0x05

// Const x509 "to be signed" data
typedef struct
{
    uint8_t SerialNum[RIOT_X509_SNUM_LEN];
    const char *IssuerCommon;
    const char *IssuerOrg;
    const char *IssuerCountry;
    const char *ValidFrom;
    const char *ValidTo;
    const char *SubjectCommon;
    const char *SubjectOrg;
    const char *SubjectCountry;
} RIOT_X509_TBS_DATA;

int
X509GetDEREncodedTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *AliasKeyPub,
    RIOT_ECC_PUBLIC     *DevIdKeyPub,
    uint8_t             *Fwid,
    uint32_t             FwidLen
);

int
X509MakeAliasCert(
    DERBuilderContext   *AliasCert,
    uint8_t             *Tbs,
    uint32_t             TbsLen,
    RIOT_ECC_SIGNATURE  *TbsSig
);

int
X509GetDEREccPub(
    DERBuilderContext   *Context,
    RIOT_ECC_PUBLIC      Pub
);

int
X509GetDEREcc(
    DERBuilderContext   *Context,
    RIOT_ECC_PUBLIC      Pub,
    RIOT_ECC_PRIVATE     Priv
);

#ifdef __cplusplus
}
#endif
#endif