/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include <stdint.h>
#include <stdbool.h>

#include "include/RiotDerEnc.h"
#include "include/RiotX509Bldr.h"

#pragma CHECKED_SCOPE ON

#define ASRT(_X) if(!(_X))      {goto Error;}
#define CHK(_X)  if(((_X)) < 0) {goto Error;}

// OIDs.  Note that the encoder expects a -1 sentinel.
static int riotOID _Checked[] = { 2,23,133,5,4,1,-1 };
static int ecdsaWithSHA256OID _Checked[] = { 1,2,840,10045,4,3,2,-1 };
static int ecPublicKeyOID _Checked[] = { 1,2,840,10045, 2,1,-1 };
static int prime256v1OID _Checked[] = { 1,2,840,10045, 3,1,7,-1 };
static int keyUsageOID _Checked[] = { 2,5,29,15,-1 };
static int extKeyUsageOID _Checked[] = { 2,5,29,37,-1 };
//static int subjectAltNameOID[] = { 2,5,29,17,-1 };
static int clientAuthOID _Checked[] = { 1,3,6,1,5,5,7,3,2,-1 };
static int sha256OID _Checked[] = { 2,16,840,1,101,3,4,2,1,-1 };
static int commonNameOID _Checked[] = { 2,5,4,3,-1 };
static int countryNameOID _Checked[] = { 2,5,4,6,-1 };
static int orgNameOID _Checked[] = { 2,5,4,10,-1 };
static int basicConstraintsOID _Checked[] = { 2,5,29,19,-1 };

static int
X509AddExtensions(
    _Ptr<DERBuilderContext> Tbs,
    _Array_ptr<uint8_t>     DevIdPub : byte_count((size_t)DevIdPubLen),
    uint32_t                DevIdPubLen,
    _Array_ptr<uint8_t>     Fwid : byte_count((size_t)FwidLen),
    uint32_t                FwidLen
)
// Create the RIoT extensions.  The RIoT subject altName + extended key usage.
{
    CHK(DERStartExplicit(Tbs, 3));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, extKeyUsageOID));
    CHK(            DERStartEnvelopingOctetString(Tbs));
    CHK(                DERStartSequenceOrSet(Tbs, true));
    CHK(                    DERAddOID(Tbs, clientAuthOID));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(        DERPopNesting(Tbs));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, riotOID));
    CHK(            DERStartEnvelopingOctetString(Tbs));
    CHK(                DERStartSequenceOrSet(Tbs, true));
    CHK(                    DERAddInteger(Tbs, 1));
    CHK(                    DERStartSequenceOrSet(Tbs, true));
    CHK(                        DERStartSequenceOrSet(Tbs, true));
    CHK(                            DERAddOID(Tbs, ecPublicKeyOID));
    CHK(                            DERAddOID(Tbs, prime256v1OID));
    CHK(                        DERPopNesting(Tbs));
    CHK(                        DERAddBitString(Tbs, DevIdPub, DevIdPubLen));
    CHK(                    DERPopNesting(Tbs));
    CHK(                    DERStartSequenceOrSet(Tbs, true));
    CHK(                        DERAddOID(Tbs, sha256OID));
    CHK(                        DERAddOctetString(Tbs, Fwid, FwidLen));
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

static int
X509AddX501Name(
    _Ptr<DERBuilderContext>   Context,
    _Nt_array_ptr<const char> CommonName,
    _Nt_array_ptr<const char> OrgName,
    _Nt_array_ptr<const char> CountryName
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
X509GetDeviceCertTBS(
<<<<<<< Updated upstream
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *DevIdKeyPub
=======
    DERBuilderContext   *Tbs         : itype(_Ptr<DERBuilderContext>),
    RIOT_X509_TBS_DATA  *TbsData     : itype(_Ptr<RIOT_X509_TBS_DATA>),
    RIOT_ECC_PUBLIC     *DevIdKeyPub : itype(_Ptr<RIOT_ECC_PUBLIC>)
>>>>>>> Stashed changes
)
{
    uint8_t     encBuffer _Checked[65];
    uint32_t    encBufferLen;
    uint8_t     keyUsage = RIOT_X509_KEY_USAGE;

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
<<<<<<< Updated upstream
    CHK(        DERAddBitString(Tbs, encBuffer, encBufferLen));
=======
                // encBufferLen will be set to (1 + 2*RIOT_ECC_COORD_BYTES), 
                // which is 32, much less than the 65 encBuffer has
    CHK(        DERAddBitString(Tbs, 
                                _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&encBuffer[0], byte_count((size_t)encBufferLen)), 
                                encBufferLen));
>>>>>>> Stashed changes
    CHK(    DERPopNesting(Tbs));
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, keyUsageOID));
    CHK(                DERStartEnvelopingOctetString(Tbs));
                            encBufferLen = 1;
                            // TODO: encBufferLen is 1 here, why the complaint?
    CHK(                    DERAddBitString(Tbs, 
                                            _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&keyUsage, byte_count((size_t)encBufferLen)), 
                                            encBufferLen)); // Actually 6bits
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, basicConstraintsOID));
    CHK(                DERAddBoolean(Tbs, true));
    CHK(                DERStartEnvelopingOctetString(Tbs));
    CHK(                    DERStartSequenceOrSet(Tbs, true));
    CHK(                        DERAddBoolean(Tbs, true));
    CHK(                        DERAddInteger(Tbs, 1));
    CHK(                    DERPopNesting(Tbs));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
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
    DERBuilderContext   *DeviceIDCert : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_SIGNATURE  *TbsSig       : itype(_Ptr<RIOT_ECC_SIGNATURE>)
)
// Create a Device Certificate given a ready-to-sign TBS region in the context
{
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);
    uint8_t     encBufferArr _Checked[(BIGLEN - 1) * 4];
    _Array_ptr<uint8_t> encBufferPtr : byte_count((size_t)encBufferLen) = 
        _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&encBufferArr[0], byte_count((size_t)encBufferLen));

    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(DeviceIDCert));
    CHK(    DERStartSequenceOrSet(DeviceIDCert, true));
    CHK(        DERAddOID(DeviceIDCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(DeviceIDCert));
    CHK(    DERStartEnvelopingBitString(DeviceIDCert));
    CHK(        DERStartSequenceOrSet(DeviceIDCert, true));
                    BigValToBigInt(encBufferArr, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(DeviceIDCert, encBufferPtr, encBufferLen));
                    BigValToBigInt(encBufferArr, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(DeviceIDCert, encBufferPtr, encBufferLen));
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
    DERBuilderContext   *Tbs         : itype(_Ptr<DERBuilderContext>),
    RIOT_X509_TBS_DATA  *TbsData     : itype(_Ptr<RIOT_X509_TBS_DATA>),
    RIOT_ECC_PUBLIC     *AliasKeyPub : itype(_Ptr<RIOT_ECC_PUBLIC>),
    RIOT_ECC_PUBLIC     *DevIdKeyPub : itype(_Ptr<RIOT_ECC_PUBLIC>),
    uint8_t             *Fwid        : byte_count((size_t)FwidLen),
    uint32_t             FwidLen
)
{
<<<<<<< Updated upstream
    uint8_t     encBuffer[65];
=======
    uint8_t     encBuffer _Checked[65];
>>>>>>> Stashed changes
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
                // Again, encBufferLen is going to be smaller than the actual buffer
    CHK(        DERAddBitString(Tbs, 
                                _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(encBuffer, byte_count((size_t)encBufferLen)), 
                                encBufferLen));
    CHK(    DERPopNesting(Tbs));
            RiotCrypt_ExportEccPub(DevIdKeyPub, encBuffer, &encBufferLen);
    CHK(    X509AddExtensions(Tbs, 
                              _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(encBuffer, byte_count((size_t)encBufferLen)), 
                              encBufferLen, 
                              Fwid, 
                              FwidLen));
    CHK(DERPopNesting(Tbs));
    
    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;

Error:
    return -1;
}

int 
X509MakeAliasCert(
    DERBuilderContext   *AliasCert : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_SIGNATURE  *TbsSig    : itype(_Ptr<RIOT_ECC_SIGNATURE>)
)
// Create an Alias Certificate given a ready-to-sign TBS region in the context
{
    uint8_t     encBufferArr _Checked[((BIGLEN - 1) * 4)];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);
    _Array_ptr<uint8_t> encBufferPtr : byte_count((size_t)encBufferLen) = 
        _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&encBufferArr[0], byte_count((size_t)encBufferLen));

    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(AliasCert));   
    CHK(    DERStartSequenceOrSet(AliasCert, true));
    CHK(        DERAddOID(AliasCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(AliasCert));
    CHK(    DERStartEnvelopingBitString(AliasCert));
    CHK(        DERStartSequenceOrSet(AliasCert, true));
                    BigValToBigInt(encBufferArr, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(AliasCert, encBufferPtr, encBufferLen));
                    BigValToBigInt(encBufferArr, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(AliasCert, encBufferPtr, encBufferLen));
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
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_PUBLIC      Pub
)
{
    uint8_t     encBuffer _Checked[65];
    uint32_t    encBufferLen;

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERAddOID(Context, ecPublicKeyOID));
    CHK(        DERAddOID(Context, prime256v1OID));
    CHK(    DERPopNesting(Context));
            RiotCrypt_ExportEccPub(&Pub, encBuffer, &encBufferLen);
    CHK(    DERAddBitString(Context, 
                            _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(encBuffer, byte_count((size_t)encBufferLen)), 
                            encBufferLen));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetDEREcc(
    DERBuilderContext   *Context : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_PUBLIC      Pub,
    RIOT_ECC_PRIVATE     Priv
)
{
    uint8_t     encBuffer _Checked[65];
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
    CHK(        DERAddBitString(Context, 
                                _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(encBuffer, byte_count((size_t)encBufferLen)), 
                                encBufferLen));
    CHK(    DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetDERCsrTbs(
    DERBuilderContext   *Context     : itype(_Ptr<DERBuilderContext>),
    RIOT_X509_TBS_DATA  *TbsData     : itype(_Ptr<RIOT_X509_TBS_DATA>),
    RIOT_ECC_PUBLIC     *DeviceIDPub : itype(_Ptr<RIOT_ECC_PUBLIC>)
)
{
    uint8_t     encBuffer _Checked[65];
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
    CHK(        DERAddBitString(Context, 
                                _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(encBuffer, byte_count((size_t)encBufferLen)), 
                                encBufferLen));
    CHK(    DERPopNesting(Context));
    CHK(DERStartExplicit(Context,0));
    CHK(DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;

Error:
    return -1;
}

int
X509GetDERCsr(
    DERBuilderContext   *Context   : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_SIGNATURE  *Signature : itype(_Ptr<RIOT_ECC_SIGNATURE>)
)
{
    uint8_t     encBufferArr _Checked[((BIGLEN - 1) * 4)];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);
    _Array_ptr<uint8_t> encBufferPtr : byte_count((size_t)encBufferLen) = 
        _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&encBufferArr[0], byte_count((size_t)encBufferLen));


    // Elevate the "TBS" block into a real certificate, i.e., copy it
    // into an enclosing sequence and then add the signature block.
    CHK(DERTbsToCert(Context));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERAddOID(Context, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Context));
    CHK(    DERStartEnvelopingBitString(Context));
    CHK(        DERStartSequenceOrSet(Context, true));
                    BigValToBigInt(encBufferArr, &Signature->r);
    CHK(            DERAddIntegerFromArray(Context, encBufferPtr, encBufferLen));
                    BigValToBigInt(encBufferArr, &Signature->s);
    CHK(            DERAddIntegerFromArray(Context, encBufferPtr, encBufferLen));
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
    DERBuilderContext   *Tbs        : itype(_Ptr<DERBuilderContext>),
    RIOT_X509_TBS_DATA  *TbsData    : itype(_Ptr<RIOT_X509_TBS_DATA>),
    RIOT_ECC_PUBLIC     *RootKeyPub : itype(_Ptr<RIOT_ECC_PUBLIC>)
)
{
    uint8_t     encBuffer _Checked[65];
    uint32_t    encBufferLen;
    uint8_t     keyUsage = RIOT_X509_KEY_USAGE;

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
    CHK(        DERAddBitString(Tbs, 
                                _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(encBuffer, byte_count((size_t)encBufferLen)), 
                                encBufferLen));
    CHK(    DERPopNesting(Tbs));
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, keyUsageOID));
    CHK(                DERStartEnvelopingOctetString(Tbs));
                            encBufferLen = 1;
    CHK(                    DERAddBitString(Tbs, 
                                            _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&keyUsage, byte_count((size_t)encBufferLen)), 
                                            encBufferLen)); // Actually 6bits
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, basicConstraintsOID));
    CHK(                DERAddBoolean(Tbs, true));
    CHK(                DERStartEnvelopingOctetString(Tbs));
    CHK(                    DERStartSequenceOrSet(Tbs, true));
    CHK(                        DERAddBoolean(Tbs, true));
    CHK(                        DERAddInteger(Tbs, 2));
    CHK(                    DERPopNesting(Tbs));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
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
    DERBuilderContext   *RootCert : itype(_Ptr<DERBuilderContext>),
    RIOT_ECC_SIGNATURE  *TbsSig   : itype(_Ptr<RIOT_ECC_SIGNATURE>)
)
// Create an Alias Certificate given a ready-to-sign TBS region in the context
{
     uint8_t     encBufferArr _Checked[((BIGLEN - 1) * 4)];
    uint32_t    encBufferLen = ((BIGLEN - 1) * 4);
    _Array_ptr<uint8_t> encBufferPtr : byte_count((size_t)encBufferLen) = 
        _Dynamic_bounds_cast<_Array_ptr<uint8_t>>(&encBufferArr[0], byte_count((size_t)encBufferLen));


    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(RootCert));
    CHK(    DERStartSequenceOrSet(RootCert, true));
    CHK(        DERAddOID(RootCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(RootCert));
    CHK(    DERStartEnvelopingBitString(RootCert));
    CHK(        DERStartSequenceOrSet(RootCert, true));
                    BigValToBigInt(encBufferArr, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(RootCert, encBufferPtr, encBufferLen));
                    BigValToBigInt(encBufferArr, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(RootCert, encBufferPtr, encBufferLen));
    CHK(        DERPopNesting(RootCert));
    CHK(    DERPopNesting(RootCert));
    CHK(DERPopNesting(RootCert));

    ASRT(DERGetNestingDepth(RootCert) == 0);
    return 0;

Error:
    return -1;
}