#ifndef _RIOT_X509_BLDR_H
#define _RIOT_X509_BLDR_H

#ifdef __cplusplus
extern "C" {
#endif

#define RIOT_X509_SNUM_LEN  0x10

// KeyUsage is defined as a 4 byte bit string, with flag = 0
// KeyUsage :: = BIT STRING{
//     digitalSignature(0),
//     nonRepudiation(1),
//     keyEncipherment(2),
//     dataEncipherment(3),
//     keyAgreement(4),
//     keyCertSign(5),
//     cRLSign(6)
// }
#define RIOT_X509_CA_KEY_USAGE {0x86, 0x00, 0x00, 0x00}

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


typedef struct
{
    int* Oid;
    uint8_t* DerBuffer;
    uint32_t DerBufferSize;
} RIOT_X509_OID;

int
X509GetDeviceCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    const RIOT_ECC_PUBLIC     *DevIdKeyPub,
    const RIOT_ECC_PUBLIC     *IssuerIdKeyPub,
    uint8_t             *Tcps,
    uint32_t            TcpsLen,
    int32_t             PathLength
);

int
X509MakeDeviceCert(
    DERBuilderContext   *DeviceIDCert,
    RIOT_ECC_SIGNATURE  *TbsSig
);

int
X509GetAliasCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *AliasKeyPub,
    RIOT_ECC_PUBLIC     *DevIdKeyPub,
    uint8_t             *Fwid,
    uint32_t             FwidLen,
    uint8_t             *Tcps,
    uint32_t             TcpsLen,
    int32_t              PathLen
);

int
X509MakeAliasCert(
    DERBuilderContext   *AliasCert,
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

int
X509GetDERCsrTBS(
    DERBuilderContext       *Context,
    RIOT_X509_TBS_DATA      *TbsData,
    const RIOT_ECC_PUBLIC   *DeviceIDPub,
    RIOT_X509_OID           *OidExtensions,
    const size_t            OidExtensionsCount
);

int
X509GetCSRCertTBS(
    DERBuilderContext           *Tbs,
    RIOT_X509_TBS_DATA          *TbsData,
    const RIOT_ECC_PUBLIC       *CsrKeyPub,
    const RIOT_ECC_PUBLIC       *AuthorityKeyPub,
    int32_t                     PathLen,
    const uint8_t               *SubjectKeyDerBuffer,
    uint32_t                    SubjectKeyDerBufferSize,
    const uint8_t               *ExtensionDerBuffer,
    uint32_t                    ExtensionDerBufferSize
);

int
X509GetDERCsr(
    DERBuilderContext   *Context,
    RIOT_ECC_SIGNATURE  *Signature
);

int
X509GetRootCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    const RIOT_ECC_PUBLIC     *RootKeyPub,
    int32_t             PathLength
);

int
X509MakeRootCert(
    DERBuilderContext   *AliasCert,
    RIOT_ECC_SIGNATURE  *TbsSig
);

int
X509GetEccPub(
    DERBuilderContext   *Context,
    ecc_publickey       *Pub
);

int
X509GetEccPrv(
    DERBuilderContext       *Context,
    const ecc_publickey     *Pub,
    const ecc_privatekey    *Prv
);

#ifdef __cplusplus
}
#endif
#endif