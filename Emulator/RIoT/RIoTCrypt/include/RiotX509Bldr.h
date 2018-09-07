#ifndef _RIOT_X509_BLDR_H
#define _RIOT_X509_BLDR_H

#include "RiotCrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma CHECKED_SCOPE ON

#define RIOT_X509_SNUM_LEN  0x05

// KeyUsage :: = BIT STRING{
//     digitalSignature(0),
//     nonRepudiation(1),
//     keyEncipherment(2),
//     dataEncipherment(3),
//     keyAgreement(4),
//     keyCertSign(5),
//     cRLSign(6)
// }
#define RIOT_X509_KEY_USAGE 0x4  // keyCertSign

// Const x509 "to be signed" data
typedef struct
{
    uint8_t SerialNum[RIOT_X509_SNUM_LEN] : itype(uint8_t _Checked[RIOT_X509_SNUM_LEN]);
    const char *IssuerCommon              : itype(_Nt_array_ptr<const char>);
    const char *IssuerOrg                 : itype(_Nt_array_ptr<const char>);
    const char *IssuerCountry             : itype(_Nt_array_ptr<const char>);
    const char *ValidFrom                 : itype(_Nt_array_ptr<const char>);
    const char *ValidTo                   : itype(_Nt_array_ptr<const char>);
    const char *SubjectCommon             : itype(_Nt_array_ptr<const char>);
    const char *SubjectOrg                : itype(_Nt_array_ptr<const char>);
    const char *SubjectCountry            : itype(_Nt_array_ptr<const char>);
} RIOT_X509_TBS_DATA;

int
X509GetDeviceCertTBS(
    DERBuilderContext   *Tbs         : itype(_Ptr<DERBuilderContext>),
    RIOT_X509_TBS_DATA  *TbsData     : itype(_Ptr<RIOT_X509_TBS_DATA>),
    RIOT_ECC_PUBLIC     *DevIdKeyPub : itype(_Ptr<RIOT_ECC_PUBLIC>)
);

int
X509MakeDeviceCert(
    DERBuilderContext   *DeviceIDCert : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_SIGNATURE  *TbsSig       : itype(_Ptr<RIOT_ECC_SIGNATURE>)
);

int
X509GetAliasCertTBS(
    DERBuilderContext   *Tbs         : itype(_Ptr<DERBuilderContext>),
    RIOT_X509_TBS_DATA  *TbsData     : itype(_Ptr<RIOT_X509_TBS_DATA>),
    RIOT_ECC_PUBLIC     *AliasKeyPub : itype(_Ptr<RIOT_ECC_PUBLIC>),
    RIOT_ECC_PUBLIC     *DevIdKeyPub : itype(_Ptr<RIOT_ECC_PUBLIC>),
    uint8_t             *Fwid        : byte_count((size_t)FwidLen),
    uint32_t             FwidLen
);

int
X509MakeAliasCert(
    DERBuilderContext   *AliasCert : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_SIGNATURE  *TbsSig    : itype(_Ptr<RIOT_ECC_SIGNATURE>)
);

int
X509GetDEREccPub(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_PUBLIC      Pub
);

int
X509GetDEREcc(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_PUBLIC      Pub,
    RIOT_ECC_PRIVATE     Priv
);

int
X509GetDERCsrTbs(
    DERBuilderContext   *Context     : itype(_Ptr<DERBuilderContext>),
    RIOT_X509_TBS_DATA  *TbsData     : itype(_Ptr<RIOT_X509_TBS_DATA>),
    RIOT_ECC_PUBLIC     *DeviceIDPub : itype(_Ptr<RIOT_ECC_PUBLIC>)
);

int
X509GetDERCsr(
    DERBuilderContext   *Context   : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_SIGNATURE  *Signature : itype(_Ptr<RIOT_ECC_SIGNATURE>)
);

int
X509GetRootCertTBS(
    DERBuilderContext   *Tbs        : itype(_Ptr<DERBuilderContext>),
    RIOT_X509_TBS_DATA  *TbsData    : itype(_Ptr<RIOT_X509_TBS_DATA>),
    RIOT_ECC_PUBLIC     *RootKeyPub : itype(_Ptr<RIOT_ECC_PUBLIC>)
);

int
X509MakeRootCert(
    DERBuilderContext   *RootCert  : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_SIGNATURE  *TbsSig    : itype(_Ptr<RIOT_ECC_SIGNATURE>)
);

#pragma CHECKED_SCOPE OFF

#ifdef __cplusplus
}
#endif

#endif