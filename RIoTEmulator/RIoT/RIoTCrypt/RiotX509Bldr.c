/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include <stdint.h>
#include <stdbool.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h> // TODO: REMOVE THIS

#include "RiotDerEnc.h"
#include "RiotX509Bldr.h"

#define ASRT(_X) if(!(_X))      {goto Error;}
#define CHK(_X)  if(((_X)) < 0) {goto Error;}

// OIDs.  Note that the encoder expects a -1 sentinel.
static int ecdsaWithSHA256OID[] = { 1,2,840,10045,4,3,2,-1 };
static int ecPublicKeyOID[] = { 1,2,840,10045, 2,1,-1 };
static int prime256v1OID[] = { 1,2,840,10045, 3,1,7,-1 };
static int extKeyUsageOID[] = { 2,5,29,37,-1 };
static int subjectAltNameOID[] = { 2,5,29,17,-1 };
static int clientAuthOID[] = { 1,3,6,1,5,5,7,3,2,-1 };
static int sha256OID[] = { 2,16,840,1,101,3,4,2,1,-1 };
static int commonNameOID[] = { 2,5,4,3,-1 };
static int countryNameOID[] = { 2,5,4,6,-1 };
static int orgNameOID[] = { 2,5,4,10,-1 };

int riotOID[] = { 1,2,3,4,5,6,-1 };

int 
X509AddExtensions(
    DERBuilderContext   *Tbs,
    uint8_t             *DevIdPub,
    uint32_t             DevIdPubLen,
    uint8_t             *Fwid,
    uint32_t             FwidLen
);

int
X509AddX501Name(
    DERBuilderContext   *Context,
    const char          *CommonName,
    const char          *OrgName,
    const char          *CountryName
);

int X509GetDEREncodedTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *AliasKeyPub,
    RIOT_ECC_PUBLIC     *DevIdKeyPub,
    uint8_t             *Fwid,
    uint32_t             FwidLen
)
{
    uint8_t     encBuffer[65];
    uint32_t    encBufferLen;

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
    CHK(        DERAddBitString(Tbs, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Tbs));
            RiotCrypt_ExportEccPub(DevIdKeyPub, encBuffer, &encBufferLen);
    CHK(    X509AddExtensions(Tbs, encBuffer, encBufferLen, Fwid, FwidLen));
    CHK(DERPopNesting(Tbs));
    
    ASRT(DERGetNestingDepth(Tbs) == 0);

    return 0;
Error:
    return -1;
}

int
X509AddExtensions(
    DERBuilderContext   *Tbs,
    uint8_t             *DevIdPub,
    uint32_t             DevIdPubLen,
    uint8_t             *Fwid,
    uint32_t             FwidLen
)
// Create the RIoT extensions.  The RIoT subject altName + extended key usage.
{
    CHK(DERStartExplicit(Tbs, 3));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, extKeyUsageOID));
    CHK(            DERAddBoolean(Tbs, true));
    CHK(            DERStartEnvelopingOctetString(Tbs));
    CHK(                DERStartSequenceOrSet(Tbs, true));
    CHK(                    DERAddOID(Tbs, clientAuthOID));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(        DERPopNesting(Tbs));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, subjectAltNameOID));
    CHK(            DERAddBoolean(Tbs, TRUE));
    CHK(            DERStartEnvelopingOctetString(Tbs));
    CHK(                DERStartSequenceOrSet(Tbs, true));
    CHK(                    DERStartExplicit(Tbs, 0));
    CHK(                        DERAddOID(Tbs, riotOID));
    CHK(                        DERStartSequenceOrSet(Tbs, true));
    CHK(                            DERAddInteger(Tbs, 1));
    CHK(                            DERStartSequenceOrSet(Tbs, true));
    CHK(                                DERStartSequenceOrSet(Tbs, true));
    CHK(                                    DERAddOID(Tbs, ecPublicKeyOID));
    CHK(                                    DERAddOID(Tbs, prime256v1OID));
    CHK(                                DERPopNesting(Tbs));
    CHK(                                DERAddBitString(Tbs, DevIdPub, DevIdPubLen));
    CHK(                            DERPopNesting(Tbs));
    CHK(                            DERStartSequenceOrSet(Tbs, true));
    CHK(                                DERAddOID(Tbs, sha256OID));
    CHK(                                DERAddOctetString(Tbs, Fwid, FwidLen));
    CHK(                            DERPopNesting(Tbs));
    CHK(                        DERPopNesting(Tbs));
    CHK(                    DERPopNesting(Tbs));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(        DERPopNesting(Tbs));
    CHK(    DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));
    return 0;
Error:
    return -1;
}

int 
X509MakeAliasCert(
    DERBuilderContext   *AliasCert,
    uint8_t             *Tbs,
    uint32_t             TbsLen,
    RIOT_ECC_SIGNATURE  *TbsSig
)
// Create an ALias Certificate given a TBS and the matching signature.
{
    uint8_t     encBuffer[((BIGLEN - 1) * 4)];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);

    ASRT(AliasCert->Length >= (TbsLen + 32));

    CHK(DERStartSequenceOrSet(AliasCert, TRUE));
        memcpy(AliasCert->Buffer + AliasCert->Position, Tbs, TbsLen);
        AliasCert->Position += TbsLen;
    CHK(    DERStartSequenceOrSet(AliasCert, TRUE));
    CHK(        DERAddOID(AliasCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(AliasCert));
    CHK(    DERStartEnvelopingBitString(AliasCert));
    CHK(        DERStartSequenceOrSet(AliasCert, TRUE));
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
    CHK(        DERStartSequenceOrSet(Context, false));
    CHK(            DERStartSequenceOrSet(Context, true));
    CHK(                DERAddOID(Context, countryNameOID));
    CHK(                DERAddUTF8String(Context, CountryName));
    CHK(            DERPopNesting(Context));
    CHK(        DERPopNesting(Context));
    CHK(        DERStartSequenceOrSet(Context, false));
    CHK(            DERStartSequenceOrSet(Context, true));
    CHK(                DERAddOID(Context, orgNameOID));
    CHK(                DERAddUTF8String(Context, OrgName));
    CHK(            DERPopNesting(Context));
    CHK(        DERPopNesting(Context));
    CHK(    DERPopNesting(Context));
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

    return 0;
Error:
    return -1;

}