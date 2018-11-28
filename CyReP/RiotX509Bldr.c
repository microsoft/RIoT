/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include <RiotTarget.h>
#include <RiotStatus.h>
#include <RiotSha256.h>
#include <RiotHmac.h>
#include <RiotKdf.h>
#include <RiotEcc.h>
#include <RiotDerEnc.h>
#include <RiotX509Bldr.h>
#include <RiotCrypt.h>

#define ASRT(_X) if(!(_X))      {goto Error;}
#define CHK(_X)  if(((_X)) < 0) {goto Error;}

// OIDs.  Note that the encoder expects a -1 sentinel.
static int riotOID[] = { 2,23,133,5,4,1,-1 };
static int tcpsOID[] = { 2,23,133,5,4,2,-1 };
static int ecdsaWithSHA256OID[] = { 1,2,840,10045,4,3,2,-1 };
static int ecPublicKeyOID[] = { 1,2,840,10045, 2,1,-1 };
static int prime256v1OID[] = { 1,2,840,10045, 3,1,7,-1 };
static int extensionRequestOID[] = { 1,2,840,113549,1,9,14,-1 };
static int keyUsageOID[] = { 2,5,29,15,-1 };
static int extKeyUsageOID[] = { 2,5,29,37,-1 };
//static int subjectAltNameOID[] = { 2,5,29,17,-1 };
static int clientAuthOID[] = { 1,3,6,1,5,5,7,3,2,-1 };
static int serverAuthOID[] = { 1,3,6,1,5,5,7,3,1,-1 };
static int sha256OID[] = { 2,16,840,1,101,3,4,2,1,-1 };
static int commonNameOID[] = { 2,5,4,3,-1 };
static int countryNameOID[] = { 2,5,4,6,-1 };
static int orgNameOID[] = { 2,5,4,10,-1 };
static int basicConstraintsOID[] = { 2,5,29,19,-1 };
static int subjectKeyIdentifierOID[] = { 2,5,29,14,-1 };
static int authorityKeyIdentifierOID[] = { 2,5,29,35,-1 };

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdate-time"
#endif
const char DeviceBuildId[] = __DATE__ "-" __TIME__;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static int
X509AddExtensions(
    DERBuilderContext   *Tbs,
    uint8_t             *DevIdPub,
    uint32_t             DevIdPubLen,
    uint8_t             *AliasKeyId,
    uint32_t             AliasKeyIdLen,
    uint8_t             *Fwid,
    uint32_t             FwidLen,
    uint8_t             *Tcps,
    uint32_t             TcpsLen,
    int32_t              PathLen,
    const uint8_t*       ExtensionBuffer,
    uint32_t             ExtensionBufferSize
)
// Create the RIoT extensions.  The RIoT subject altName + extended key usage.
{
    uint8_t     authorityKeyId[RIOT_DIGEST_LENGTH];
    uint8_t     keyUsageCA[] = RIOT_X509_CA_KEY_USAGE;

    CHK(DERStartExplicit(Tbs, 3));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, subjectKeyIdentifierOID));
    CHK(            DERStartEnvelopingOctetString(Tbs));
    CHK(                DERAddOctetString(Tbs, AliasKeyId, AliasKeyIdLen));
    CHK(            DERPopNesting(Tbs));
    CHK(        DERPopNesting(Tbs));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, authorityKeyIdentifierOID));
    CHK(            DERStartEnvelopingOctetString(Tbs));
    CHK(                DERStartSequenceOrSet(Tbs, true));
                            RiotCrypt_Hash(authorityKeyId, sizeof(authorityKeyId), DevIdPub, DevIdPubLen);
    CHK(                    DERAddSequenceOctets(Tbs, 0, authorityKeyId, sizeof(authorityKeyId)));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(        DERPopNesting(Tbs));
    if (PathLen >= 0)
    {
        CHK(    DERStartSequenceOrSet(Tbs, true));
        CHK(        DERAddOID(Tbs, basicConstraintsOID));
        CHK(        DERAddBoolean(Tbs, true));
        CHK(        DERStartEnvelopingOctetString(Tbs));
        CHK(            DERStartSequenceOrSet(Tbs, true));
        if (PathLen > 0)
        {
            CHK(        DERAddBoolean(Tbs, true));
            CHK(        DERAddInteger(Tbs, PathLen));
        }
        else
        {
            CHK(        DERAddBoolean(Tbs, false));
        }
        CHK(            DERPopNesting(Tbs));
        CHK(        DERPopNesting(Tbs));
        CHK(    DERPopNesting(Tbs));
    }
    if (PathLen > 0)
    {
        CHK(    DERStartSequenceOrSet(Tbs, true));
        CHK(        DERAddOID(Tbs, keyUsageOID));
        CHK(        DERStartEnvelopingOctetString(Tbs));
        CHK(            DERAddBitString(Tbs, keyUsageCA, sizeof(keyUsageCA)));
        CHK(        DERPopNesting(Tbs));
        CHK(    DERPopNesting(Tbs));
    }
    else
    {
        CHK(    DERStartSequenceOrSet(Tbs, true));
        CHK(        DERAddOID(Tbs, extKeyUsageOID));
        CHK(        DERAddBoolean(Tbs, true));
        CHK(        DERStartEnvelopingOctetString(Tbs));
        CHK(            DERStartSequenceOrSet(Tbs, true));
        CHK(                DERAddOID(Tbs, clientAuthOID));
        CHK(                DERAddOID(Tbs, serverAuthOID));
        CHK(            DERPopNesting(Tbs));
        CHK(        DERPopNesting(Tbs));
        CHK(    DERPopNesting(Tbs));
    }
    if (TcpsLen == 0 && ExtensionBufferSize == 0) // riotOID
    {
        CHK(    DERStartSequenceOrSet(Tbs, true));
        CHK(        DERAddOID(Tbs, riotOID));
        CHK(        DERStartEnvelopingOctetString(Tbs));
        CHK(            DERStartSequenceOrSet(Tbs, true));
        CHK(                DERAddInteger(Tbs, 1));
        CHK(                DERStartSequenceOrSet(Tbs, true));
        CHK(                    DERStartSequenceOrSet(Tbs, true));
        CHK(                        DERAddOID(Tbs, ecPublicKeyOID));
        CHK(                        DERAddOID(Tbs, prime256v1OID));
        CHK(                    DERPopNesting(Tbs));
        CHK(                    DERAddBitString(Tbs, DevIdPub, DevIdPubLen));
        CHK(                DERPopNesting(Tbs));
        CHK(                DERStartSequenceOrSet(Tbs, true));
        CHK(                    DERAddOID(Tbs, sha256OID));
        CHK(                    DERAddOctetString(Tbs, Fwid, FwidLen));
        CHK(                DERPopNesting(Tbs));
        CHK(            DERPopNesting(Tbs));
        CHK(        DERPopNesting(Tbs));
        CHK(    DERPopNesting(Tbs));
    }
    else if (ExtensionBufferSize == 0) // tcpsOID
    {
        CHK(    DERStartSequenceOrSet(Tbs, true));
        CHK(        DERAddOID(Tbs, tcpsOID));
        CHK(        DERStartEnvelopingOctetString(Tbs));
        CHK(            DERAddOctetString(Tbs, Tcps, TcpsLen));
        CHK(        DERPopNesting(Tbs));
        CHK(    DERPopNesting(Tbs));
    }
    else // OID buffer
    {
        if (Tbs->Length - Tbs->Position < ExtensionBufferSize)
        {
            goto Error;
        }
        memcpy(Tbs->Buffer + Tbs->Position, ExtensionBuffer, ExtensionBufferSize);
        Tbs->Position += ExtensionBufferSize;
    }
    CHK(    DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));

    return 0;

Error:
    return -1;
}

static int
X509AddX501Name(
    DERBuilderContext   *Context,
    const char          *CommonName,
    const char          *OrgName,
    const char          *CountryName
)
{
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERStartSequenceOrSet(Context, false));
    CHK(            DERStartSequenceOrSet(Context, true));
    CHK(                DERAddOID(Context, commonNameOID));
    CHK(                DERAddUTF8String(Context, CommonName));
    CHK(            DERPopNesting(Context));
    CHK(        DERPopNesting(Context));
    if (CountryName != NULL)
    {
        CHK(        DERStartSequenceOrSet(Context, false));
        CHK(            DERStartSequenceOrSet(Context, true));
        CHK(                DERAddOID(Context, countryNameOID));
        CHK(                DERAddUTF8String(Context, CountryName));
        CHK(            DERPopNesting(Context));
        CHK(        DERPopNesting(Context));
    }
    if (OrgName != NULL)
    {
        CHK(        DERStartSequenceOrSet(Context, false));
        CHK(            DERStartSequenceOrSet(Context, true));
        CHK(                DERAddOID(Context, orgNameOID));
        CHK(                DERAddUTF8String(Context, OrgName));
        CHK(            DERPopNesting(Context));
        CHK(        DERPopNesting(Context));
    }
    CHK(    DERPopNesting(Context));

    return 0;

Error:
    return -1;
}

int
X509GetDeviceCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *DevIdKeyPub,
    RIOT_ECC_PUBLIC     *IssuerIdKeyPub,
    uint8_t             *Tcps,
    uint32_t            TcpsLen,
    int32_t             PathLength
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;
    uint8_t     keyId[RIOT_DIGEST_LENGTH];
    uint8_t     issuerKeyId[RIOT_DIGEST_LENGTH];
    uint8_t     keyUsageCA[] = RIOT_X509_CA_KEY_USAGE;

    if (IssuerIdKeyPub != NULL)
    {
        RiotCrypt_ExportEccPub(IssuerIdKeyPub, encBuffer, &encBufferLen);
        RiotCrypt_Hash(issuerKeyId, sizeof(issuerKeyId), encBuffer, encBufferLen);
    }

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, RIOT_X509_SNUM_LEN));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, TbsData->IssuerOrg, TbsData->IssuerCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddUTCTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddUTCTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, TbsData->SubjectOrg, TbsData->SubjectCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, ecPublicKeyOID));
    CHK(            DERAddOID(Tbs, prime256v1OID));
    CHK(        DERPopNesting(Tbs));
                RiotCrypt_ExportEccPub(DevIdKeyPub, encBuffer, &encBufferLen);
                RiotCrypt_Hash(keyId, sizeof(keyId), encBuffer, encBufferLen);
    CHK(        DERAddBitString(Tbs, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Tbs));
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, subjectKeyIdentifierOID));
    CHK(                DERStartEnvelopingOctetString(Tbs));
    CHK(                    DERAddOctetString(Tbs, keyId, sizeof(keyId)));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, authorityKeyIdentifierOID));
    CHK(                DERStartEnvelopingOctetString(Tbs));
    CHK(                    DERStartSequenceOrSet(Tbs, true));
    CHK(                        DERAddSequenceOctets(Tbs, 0, issuerKeyId, sizeof(issuerKeyId)));
    CHK(                    DERPopNesting(Tbs));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    if (PathLength >= 0)
    {
        CHK(            DERStartSequenceOrSet(Tbs, true));
        CHK(                DERAddOID(Tbs, basicConstraintsOID));
        CHK(                DERAddBoolean(Tbs, true));
        CHK(                DERStartEnvelopingOctetString(Tbs));
        CHK(                    DERStartSequenceOrSet(Tbs, true));
        if(PathLength > 0)
        {
            CHK(                    DERAddBoolean(Tbs, true));
            CHK(                    DERAddInteger(Tbs, PathLength));
        }
        else
        {
            CHK(                    DERAddBoolean(Tbs, false));
        }
        CHK(                    DERPopNesting(Tbs));
        CHK(                DERPopNesting(Tbs));
        CHK(            DERPopNesting(Tbs));
    }
    if (PathLength > 0)
    {
        CHK(        DERStartSequenceOrSet(Tbs, true));
        CHK(            DERAddOID(Tbs, keyUsageOID));
        CHK(            DERStartEnvelopingOctetString(Tbs));
        CHK(                DERAddBitString(Tbs, keyUsageCA, sizeof(keyUsageCA)));
        CHK(            DERPopNesting(Tbs));
        CHK(        DERPopNesting(Tbs));
    }
    else
    {
        CHK(        DERStartSequenceOrSet(Tbs, true));
        CHK(            DERAddOID(Tbs, extKeyUsageOID));
        CHK(            DERAddBoolean(Tbs, true));
        CHK(            DERStartEnvelopingOctetString(Tbs));
        CHK(                DERStartSequenceOrSet(Tbs, true));
        CHK(                    DERAddOID(Tbs, clientAuthOID));
        CHK(                    DERAddOID(Tbs, serverAuthOID));
        CHK(                DERPopNesting(Tbs));
        CHK(            DERPopNesting(Tbs));
        CHK(        DERPopNesting(Tbs));
    }
    if (TcpsLen == 0)
    {
        CHK(            DERStartSequenceOrSet(Tbs, true));
        CHK(                DERAddOID(Tbs, riotOID));
        CHK(                DERStartEnvelopingOctetString(Tbs));
        CHK(                    DERStartSequenceOrSet(Tbs, true));
        CHK(                        DERAddInteger(Tbs, 1));
        CHK(                        DERStartSequenceOrSet(Tbs, true));
        CHK(                            DERStartSequenceOrSet(Tbs, true));
        CHK(                                DERAddOID(Tbs, ecPublicKeyOID));
        CHK(                                DERAddOID(Tbs, prime256v1OID));
        CHK(                            DERPopNesting(Tbs));
        CHK(                            DERAddBitString(Tbs, encBuffer, encBufferLen));
        CHK(                        DERPopNesting(Tbs));
        CHK(                        DERStartSequenceOrSet(Tbs, true));
        CHK(                            DERAddOID(Tbs, sha256OID));
        CHK(                            DERAddOctetString(Tbs, (uint8_t*)DeviceBuildId, sizeof(DeviceBuildId) - 1));
        CHK(                        DERPopNesting(Tbs));
        CHK(                    DERPopNesting(Tbs));
        CHK(                DERPopNesting(Tbs));
        CHK(            DERPopNesting(Tbs));
    }
    else
    {
        CHK(        DERStartSequenceOrSet(Tbs, true));
        CHK(            DERAddOID(Tbs, tcpsOID));
        CHK(            DERStartEnvelopingOctetString(Tbs));
        CHK(                DERAddOctetString(Tbs, Tcps, TcpsLen));
        CHK(            DERPopNesting(Tbs));
        CHK(        DERPopNesting(Tbs));
    }
    CHK(        DERPopNesting(Tbs));
    CHK(    DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));

    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;

Error:
    return -1;
}

int
X509MakeDeviceCert(
    DERBuilderContext   *DeviceIDCert,
    RIOT_ECC_SIGNATURE  *TbsSig
)
// Create a Device Certificate given a ready-to-sign TBS region in the context
{
    uint8_t     encBuffer[((BIGLEN - 1) * 4)];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);

    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(DeviceIDCert));
    CHK(    DERStartSequenceOrSet(DeviceIDCert, true));
    CHK(        DERAddOID(DeviceIDCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(DeviceIDCert));
    CHK(    DERStartEnvelopingBitString(DeviceIDCert));
    CHK(        DERStartSequenceOrSet(DeviceIDCert, true));
                    BigValToBigInt(encBuffer, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(DeviceIDCert, encBuffer, encBufferLen));
                    BigValToBigInt(encBuffer, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(DeviceIDCert, encBuffer, encBufferLen));
    CHK(        DERPopNesting(DeviceIDCert));
    CHK(    DERPopNesting(DeviceIDCert));
    CHK(DERPopNesting(DeviceIDCert));

    ASRT(DERGetNestingDepth(DeviceIDCert) == 0);
    return 0;

Error:
    return -1;
}

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
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;
    uint8_t     subjectKeyId[RIOT_DIGEST_LENGTH];

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, RIOT_X509_SNUM_LEN));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, TbsData->IssuerOrg, TbsData->IssuerCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddUTCTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddUTCTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, TbsData->SubjectOrg, TbsData->SubjectCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, ecPublicKeyOID));
    CHK(            DERAddOID(Tbs, prime256v1OID));
    CHK(        DERPopNesting(Tbs));
                RiotCrypt_ExportEccPub(AliasKeyPub, encBuffer, &encBufferLen);
                RiotCrypt_Hash(subjectKeyId, sizeof(subjectKeyId), encBuffer, encBufferLen);
    CHK(        DERAddBitString(Tbs, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Tbs));
            RiotCrypt_ExportEccPub(DevIdKeyPub, encBuffer, &encBufferLen);
    CHK(    X509AddExtensions(Tbs, encBuffer, encBufferLen, subjectKeyId, sizeof(subjectKeyId), Fwid, FwidLen, Tcps, TcpsLen, PathLen, NULL, 0));
    CHK(DERPopNesting(Tbs));
    
    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;

Error:
    return -1;
}

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
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;
    uint8_t     subjectKeyId[RIOT_DIGEST_LENGTH];

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, RIOT_X509_SNUM_LEN));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, TbsData->IssuerOrg, TbsData->IssuerCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddUTCTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddUTCTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));

    if (Tbs->Length - Tbs->Position < SubjectKeyDerBufferSize)
    {
        goto Error;
    }

    memcpy(Tbs->Buffer + Tbs->Position, SubjectKeyDerBuffer, SubjectKeyDerBufferSize);
    Tbs->Position += SubjectKeyDerBufferSize;

    RiotCrypt_ExportEccPub(CsrKeyPub, encBuffer, &encBufferLen);
    RiotCrypt_Hash(subjectKeyId, sizeof(subjectKeyId), encBuffer, encBufferLen);

    RiotCrypt_ExportEccPub(AuthorityKeyPub, encBuffer, &encBufferLen);
    CHK(    X509AddExtensions(Tbs, encBuffer, encBufferLen, subjectKeyId, sizeof(subjectKeyId), NULL, 0, NULL, 0, PathLen, ExtensionDerBuffer, ExtensionDerBufferSize));
    CHK(DERPopNesting(Tbs));

    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;

Error:
    return -1;
}

int 
X509MakeAliasCert(
    DERBuilderContext   *AliasCert,
    RIOT_ECC_SIGNATURE  *TbsSig
)
// Create an Alias Certificate given a ready-to-sign TBS region in the context
{
    uint8_t     encBuffer[((BIGLEN - 1) * 4)];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);

    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(AliasCert));   
    CHK(    DERStartSequenceOrSet(AliasCert, true));
    CHK(        DERAddOID(AliasCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(AliasCert));
    CHK(    DERStartEnvelopingBitString(AliasCert));
    CHK(        DERStartSequenceOrSet(AliasCert, true));
                    BigValToBigInt(encBuffer, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(AliasCert, encBuffer, encBufferLen));
                    BigValToBigInt(encBuffer, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(AliasCert, encBuffer, encBufferLen));
    CHK(        DERPopNesting(AliasCert));
    CHK(    DERPopNesting(AliasCert));
    CHK(DERPopNesting(AliasCert));

    ASRT(DERGetNestingDepth(AliasCert) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetDEREccPub(
    DERBuilderContext   *Context,
    RIOT_ECC_PUBLIC      Pub
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERAddOID(Context, ecPublicKeyOID));
    CHK(        DERAddOID(Context, prime256v1OID));
    CHK(    DERPopNesting(Context));
            RiotCrypt_ExportEccPub(&Pub, encBuffer, &encBufferLen);
    CHK(    DERAddBitString(Context, encBuffer, encBufferLen));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetDEREcc(
    DERBuilderContext   *Context,
    RIOT_ECC_PUBLIC      Pub,
    RIOT_ECC_PRIVATE     Priv
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERAddInteger(Context, 1));
            BigValToBigInt(encBuffer, &Priv);
    CHK(    DERAddOctetString(Context, encBuffer, 32));
    CHK(    DERStartExplicit(Context, 0));
    CHK(        DERAddOID(Context, prime256v1OID));
    CHK(    DERPopNesting(Context));
    CHK(    DERStartExplicit(Context, 1));
                RiotCrypt_ExportEccPub(&Pub, encBuffer, &encBufferLen);
    CHK(        DERAddBitString(Context, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetDERCsrTBS(
    DERBuilderContext       *Context,
    RIOT_X509_TBS_DATA      *TbsData,
    const RIOT_ECC_PUBLIC   *DeviceIDPub,
    RIOT_X509_OID           *OidExtensions,
    const size_t            OidExtensionsCount
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERAddInteger(Context, 0));
    CHK(    X509AddX501Name(Context, TbsData->IssuerCommon, TbsData->IssuerOrg, TbsData->IssuerCountry));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERStartSequenceOrSet(Context, true));
    CHK(            DERAddOID(Context, ecPublicKeyOID));
    CHK(            DERAddOID(Context, prime256v1OID));
    CHK(        DERPopNesting(Context));
                RiotCrypt_ExportEccPub(DeviceIDPub, encBuffer, &encBufferLen);
    CHK(        DERAddBitString(Context, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Context));

    CHK(    DERStartExplicit(Context, 0));
    CHK(        DERStartSequenceOrSet(Context, true));
    CHK(            DERAddOID(Context, extensionRequestOID));
    CHK(            DERStartSequenceOrSet(Context, false));
    CHK(                DERStartSequenceOrSet(Context, true));

    for (size_t i = 0; i < OidExtensionsCount; i++)
    {
        CHK(                DERStartSequenceOrSet(Context, true));
        CHK(                    DERAddOID(Context, OidExtensions[i].Oid));
        CHK(                    DERStartEnvelopingOctetString(Context));
        CHK(                        DERAddOctetString(Context, OidExtensions[i].DerBuffer, OidExtensions[i].DerBufferSize));
        CHK(                    DERPopNesting(Context));
        CHK(                DERPopNesting(Context));
    }

    CHK(                DERPopNesting(Context));
    CHK(            DERPopNesting(Context));
    CHK(        DERPopNesting(Context));

    CHK(    DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetDERCsr(
    DERBuilderContext   *Context,
    RIOT_ECC_SIGNATURE  *Signature
)
{
    uint8_t     encBuffer[((BIGLEN - 1) * 4)];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);

    // Elevate the "TBS" block into a real certificate, i.e., copy it
    // into an enclosing sequence and then add the signature block.
    CHK(DERTbsToCert(Context));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERAddOID(Context, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Context));
    CHK(    DERStartEnvelopingBitString(Context));
    CHK(        DERStartSequenceOrSet(Context, true));
                    BigValToBigInt(encBuffer, &Signature->r);
    CHK(            DERAddIntegerFromArray(Context, encBuffer, encBufferLen));
                    BigValToBigInt(encBuffer, &Signature->s);
    CHK(            DERAddIntegerFromArray(Context, encBuffer, encBufferLen));
    CHK(        DERPopNesting(Context));
    CHK(    DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetRootCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *RootKeyPub,
    int32_t             PathLength
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;
    uint8_t     keyId[RIOT_DIGEST_LENGTH];
	uint8_t     keyUsageCA[] = RIOT_X509_CA_KEY_USAGE;

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, RIOT_X509_SNUM_LEN));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, TbsData->IssuerOrg, TbsData->IssuerCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddUTCTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddUTCTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, TbsData->SubjectOrg, TbsData->SubjectCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, ecPublicKeyOID));
    CHK(            DERAddOID(Tbs, prime256v1OID));
    CHK(        DERPopNesting(Tbs));
                RiotCrypt_ExportEccPub(RootKeyPub, encBuffer, &encBufferLen);
    CHK(        DERAddBitString(Tbs, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Tbs));
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, subjectKeyIdentifierOID));
    CHK(                DERStartEnvelopingOctetString(Tbs));
                            RiotCrypt_ExportEccPub(RootKeyPub, encBuffer, &encBufferLen);
                            RiotCrypt_Hash(keyId, sizeof(keyId), encBuffer, encBufferLen);
    CHK(                    DERAddOctetString(Tbs, keyId, sizeof(keyId)));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, authorityKeyIdentifierOID));
    CHK(                DERStartEnvelopingOctetString(Tbs));
    CHK(                    DERStartSequenceOrSet(Tbs, true));
    CHK(                        DERAddSequenceOctets(Tbs, 0, keyId, sizeof(keyId)));
    CHK(                    DERPopNesting(Tbs));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, keyUsageOID));
    CHK(                DERStartEnvelopingOctetString(Tbs));
    CHK(                    DERAddBitString(Tbs, keyUsageCA, sizeof(keyUsageCA)));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    if (PathLength >= 0)
    {
        CHK(            DERStartSequenceOrSet(Tbs, true));
        CHK(                DERAddOID(Tbs, basicConstraintsOID));
        CHK(                DERAddBoolean(Tbs, true));
        CHK(                DERStartEnvelopingOctetString(Tbs));
        CHK(                    DERStartSequenceOrSet(Tbs, true));
        if (PathLength > 0)
        {
            CHK(                    DERAddBoolean(Tbs, true));
            CHK(                    DERAddInteger(Tbs, PathLength));
        }
        else
        {
            CHK(                    DERAddBoolean(Tbs, false));
        }
        CHK(                    DERPopNesting(Tbs));
        CHK(                DERPopNesting(Tbs));
        CHK(            DERPopNesting(Tbs));
    }
    CHK(        DERPopNesting(Tbs));
    CHK(    DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));

    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;

Error:
    return -1;
}

int
X509MakeRootCert(
    DERBuilderContext   *RootCert,
    RIOT_ECC_SIGNATURE  *TbsSig
)
// Create an Alias Certificate given a ready-to-sign TBS region in the context
{
    uint8_t     encBuffer[((BIGLEN - 1) * 4)];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);

    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(RootCert));
    CHK(    DERStartSequenceOrSet(RootCert, true));
    CHK(        DERAddOID(RootCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(RootCert));
    CHK(    DERStartEnvelopingBitString(RootCert));
    CHK(        DERStartSequenceOrSet(RootCert, true));
                    BigValToBigInt(encBuffer, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(RootCert, encBuffer, encBufferLen));
                    BigValToBigInt(encBuffer, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(RootCert, encBuffer, encBufferLen));
    CHK(        DERPopNesting(RootCert));
    CHK(    DERPopNesting(RootCert));
    CHK(DERPopNesting(RootCert));

    ASRT(DERGetNestingDepth(RootCert) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetEccPub(
    DERBuilderContext   *Context,
    ecc_publickey       *Pub
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERAddOID(Context, ecPublicKeyOID));
    CHK(        DERAddOID(Context, prime256v1OID));
    CHK(    DERPopNesting(Context));
            RiotCrypt_ExportEccPub(Pub, encBuffer, &encBufferLen);
    CHK(    DERAddBitString(Context, encBuffer, encBufferLen * 8));
    CHK(DERPopNesting(Context));

    return 0;

Error:
    return -1;
}

int
X509GetEccPrv(
    DERBuilderContext       *Context,
    const ecc_publickey     *Pub,
    const ecc_privatekey    *Prv
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERAddInteger(Context, 1));
            BigValToBigInt(encBuffer, Prv);
    CHK(    DERAddOctetString(Context, encBuffer, encBufferLen));
    CHK(    DERStartExplicit(Context, 0));
    CHK(        DERAddOID(Context, prime256v1OID));
    CHK(    DERPopNesting(Context));
            RiotCrypt_ExportEccPub(Pub, encBuffer, &encBufferLen);
    CHK(    DERStartExplicit(Context, 1));
    CHK(        DERAddBitString(Context, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    return 0;

Error:
    return -1;
}
