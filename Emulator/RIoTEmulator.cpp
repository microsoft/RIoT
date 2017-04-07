/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include "stdafx.h"
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "RIoT.h"
#include "RiotCrypt.h"
#include "RiotDerEnc.h"
#include "RiotX509Bldr.h"
#include "DiceSha256.h"

//Debug
#define DEBUG

// Note that even though digest lengths are equivalent here, (and on most
// devices this will be the case) there is no requirement that DICE and RIoT
// use the same one-way function/digest length.
#define DICE_DIGEST_LENGTH  RIOT_DIGEST_LENGTH

// Note also that there is no requirement on the UDS length for a device.
// A 256-bit UDS is recommended but this size may vary among devices.
#define DICE_UDS_LENGTH     0x20

// Size, in bytes, returned when the required certificate buffer size is
// requested.  For this emulator the actual size (~552 bytes) is static,
// based on the contents of the x509TBSData struct (the fiels don't vary).
// As x509 data varies so will, obviously, the overall cert length. For now,
// just pick a reasonable minimum buffer size and worry about this later.
#define REASONABLE_MIN_CERT_SIZE    DER_MAX_TBS

// The static data fields that make up the Alias Cert "to be signed" region
RIOT_X509_TBS_DATA x509AliasTBSData = { { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E },
                                       "RIoT Core", "MSR_TEST", "US",
                                       "170101000000Z", "370101000000Z",
                                       "RIoT Device", "MSR_TEST", "US" };

// The static data fields that make up the DeviceID Cert "to be signed" region
RIOT_X509_TBS_DATA x509DeviceTBSData = { { 0x0E, 0x0D, 0x0C, 0x0B, 0x0A },
                                       "RIoT Core", "MSR_TEST", "US",
                                       "170101000000Z", "370101000000Z",
                                       "RIoT Core", "MSR_TEST", "US" };

// Random (i.e., simulated) RIoT Core "measurement"
uint8_t rDigest[DICE_DIGEST_LENGTH] = {
    0xb5, 0x85, 0x94, 0x93, 0x66, 0x1e, 0x2e, 0xae,
    0x96, 0x77, 0xc5, 0x5d, 0x59, 0x0b, 0x92, 0x94,
    0xe0, 0x94, 0xab, 0xaf, 0xd7, 0x40, 0x78, 0x7e,
    0x05, 0x0d, 0xfe, 0x6d, 0x85, 0x90, 0x53, 0xa0 };

int
CreateDeviceAuthBundle(
    BYTE    *Seed,
    DWORD    SeedSize,
    BYTE    *Fwid,
    DWORD    FwidSize,
    BYTE    *DeviceIDPublicEncoded,
    DWORD   *DeviceIDPublicEncodedSize,
    BYTE    *DeviceCertBuffer,
    DWORD   *DeviceCertBufSize,
    bool     SelfSignedDeviceCert,
    BYTE    *AliasKeyEncoded,
    DWORD   *AliasKeyEncodedSize,
    BYTE    *AliasCertBuffer,
    DWORD   *AliasCertBufSize
);

#ifdef DEBUG
void WriteTextFile(const char* fileName, uint8_t* buf, int bufLen, uint8_t append);
void WriteBinaryFile(const char* fileName, uint8_t* buf, int bufLen);
void HexConvert(uint8_t* in, int inLen, char* outBuf, int outLen);
void PrintHex(uint8_t* buf, int bufLen);
#endif

int
main()
{
    BYTE    UDS[DICE_UDS_LENGTH];
    BYTE    FWID[RIOT_DIGEST_LENGTH];
    BYTE    deviceIDPub[DER_MAX_PEM];
    BYTE    devCert[DER_MAX_PEM];
    BYTE    aliasKey[DER_MAX_PEM];
    BYTE    aliasCert[DER_MAX_PEM];    

    DWORD   deviceIDPubSize = DER_MAX_PEM;
    DWORD   aliaskeySize    = DER_MAX_PEM;
    DWORD   devCertSize     = DER_MAX_PEM;
    DWORD   aliasCertSize   = DER_MAX_PEM;

    CreateDeviceAuthBundle(UDS, DICE_UDS_LENGTH,
                           FWID, RIOT_DIGEST_LENGTH,
                           deviceIDPub, &deviceIDPubSize,
                           devCert, &devCertSize, true,
                           aliasKey, &aliaskeySize,
                           aliasCert, &aliasCertSize);

    return 0;
}

int
CreateDeviceAuthBundle(
    BYTE    *Seed,
    DWORD    SeedSize,
    BYTE    *Fwid,
    DWORD    FwidSize,
    BYTE    *DeviceIDPublicEncoded,
    DWORD   *DeviceIDPublicEncodedSize,
    BYTE    *DeviceCertBuffer,
    DWORD   *DeviceCertBufSize,
    bool     SelfSignedDeviceCert,
    BYTE    *AliasKeyEncoded,
    DWORD   *AliasKeyEncodedSize,
    BYTE    *AliasCertBuffer,
    DWORD   *AliasCertBufSize
)
{
    char                PEM[DER_MAX_PEM];
    uint8_t             cerBuffer[DER_MAX_TBS];
    uint8_t             derBuffer[DER_MAX_TBS];
    uint8_t             digest[DICE_DIGEST_LENGTH];
    uint8_t             CDI[DICE_DIGEST_LENGTH];
    RIOT_ECC_PUBLIC     deviceIDPub;
    RIOT_ECC_PRIVATE    deviceIDPriv;
    RIOT_ECC_PUBLIC     aliasKeyPub;
    RIOT_ECC_PRIVATE    aliasKeyPriv;
    RIOT_ECC_SIGNATURE  tbsSig;
    DERBuilderContext   derCtx;
    DERBuilderContext   cerCtx;
    uint32_t            length;

    // REVISIT: Implement "required size" invocation for this function?

    // Up-front parameter validation
    if (!(Seed) || (SeedSize != DICE_UDS_LENGTH) ||
        !(Fwid) || (FwidSize != RIOT_DIGEST_LENGTH)) {
        return -1;
    }

    // Don't use UDS directly
    DiceSHA256(Seed, DICE_UDS_LENGTH, digest);

    // Derive CDI based on UDS and RIoT Core "measurement"
    DiceSHA256_2(digest, DICE_DIGEST_LENGTH, rDigest, DICE_DIGEST_LENGTH, CDI);

    // Don't use CDI directly
    RiotCrypt_Hash(digest, RIOT_DIGEST_LENGTH, CDI, DICE_DIGEST_LENGTH);

    // Derive DeviceID key pair from CDI
    RiotCrypt_DeriveEccKey(&deviceIDPub,
                           &deviceIDPriv,
                           digest, RIOT_DIGEST_LENGTH,
                           (const uint8_t *)RIOT_LABEL_IDENTITY,
                           lblSize(RIOT_LABEL_IDENTITY));

    // Combine CDI and FWID, result in digest
    RiotCrypt_Hash2(digest, RIOT_DIGEST_LENGTH,
                    digest, RIOT_DIGEST_LENGTH,
                    Fwid, RIOT_DIGEST_LENGTH);

    // Derive Alias key pair from CDI and FWID
    RiotCrypt_DeriveEccKey(&aliasKeyPub,
                           &aliasKeyPriv,
                           digest, RIOT_DIGEST_LENGTH,
                           (const uint8_t *)RIOT_LABEL_ALIAS,
                           lblSize(RIOT_LABEL_ALIAS));

    // Copy DeviceID Public
    length = sizeof(PEM);
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetDEREccPub(&derCtx, deviceIDPub);
    DERtoPEM(&derCtx, PUBLICKEY_TYPE, PEM, &length);
    *DeviceIDPublicEncodedSize = length;
    memcpy(DeviceIDPublicEncoded, PEM, length);

#ifdef DEBUG
    PrintHex(derCtx.Buffer, derCtx.Position);
    PEM[length] = '\0'; // JUST FOR PRINTF
    printf("%s", PEM);
    WriteBinaryFile("DeviceIDPublic.der", derCtx.Buffer, derCtx.Position);
    WriteBinaryFile("DeviceIDPublic.pem", (uint8_t *)PEM, length);
#endif

    // Copy Alias Key Pair
    length = sizeof(PEM);
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetDEREcc(&derCtx, aliasKeyPub, aliasKeyPriv);
    DERtoPEM(&derCtx, ECC_PRIVATEKEY_TYPE, PEM, &length);
    *AliasKeyEncodedSize = length;
    memcpy(AliasKeyEncoded, PEM, length);

#ifdef DEBUG
    PrintHex(derCtx.Buffer, derCtx.Position);
    PEM[length] = '\0'; // JUST FOR PRINTF
    printf("%s", PEM);
    WriteBinaryFile("AliasKey.der", derCtx.Buffer, derCtx.Position);
    WriteBinaryFile("AliasKey.pem", (uint8_t *)PEM, length);
#endif 

    // Build the TBS (to be signed) region of Alias Key Certificate
    DERInitContext(&cerCtx, cerBuffer, DER_MAX_TBS);
    X509GetAliasCertTBS(&cerCtx, &x509AliasTBSData,
                        &aliasKeyPub, &deviceIDPub,
                        Fwid, RIOT_DIGEST_LENGTH);

    // Sign the Alias Key Certificate's TBS region
    RiotCrypt_Sign(&tbsSig, cerCtx.Buffer, cerCtx.Position, &deviceIDPriv);

    // Generate Alias Key Certificate
    X509MakeAliasCert(&cerCtx, &tbsSig);

    // Copy Alias Key Certificate
    length = sizeof(PEM);
    DERtoPEM(&cerCtx, CERT_TYPE, PEM, &length);
    *AliasCertBufSize = length;
    memcpy(AliasCertBuffer, PEM, length);

#ifdef DEBUG
    PrintHex(cerCtx.Buffer, cerCtx.Position);
    PEM[length] = '\0'; // JUST FOR PRINTF
    printf("%s", PEM);
    WriteBinaryFile("AliasCert.cer", cerCtx.Buffer, cerCtx.Position);
    WriteBinaryFile("AliasCert.pem", (uint8_t *)PEM, length);
#endif

    // This reference supports generation of either: a self-signed DeviceID
    // certificate, or a certificate signing request for the DeviceID Key. 
    // In a production device, Alias Key Certificates are normally leaf certs
    // that chain back to a known root CA. This is difficult to represent in
    // simulation since different vendors each have different manufacturing 
    // processes and CAs.
    if (SelfSignedDeviceCert)
    {
        // Build the TBS (to be signed) region of DeviceID Certificate
        DERInitContext(&cerCtx, cerBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&cerCtx, &x509DeviceTBSData, &deviceIDPub);

        // Sign the DeviceID Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, cerCtx.Buffer, cerCtx.Position, &deviceIDPriv);

        // Generate DeviceID Certificate
        X509MakeDeviceCert(&cerCtx, &tbsSig);
    }
    else {
        DERInitContext(&cerCtx, cerBuffer, DER_MAX_TBS);
        X509GetDERCsrTbs(&cerCtx, &x509AliasTBSData, &deviceIDPub);

        // Sign the Alias Key Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, cerCtx.Buffer, cerCtx.Position, &deviceIDPriv);

        // Create CSR for DeviceID
        X509GetDERCsr(&cerCtx, &tbsSig);
    }

    // Copy DeviceID Certificate or CSR
    length = sizeof(PEM);
    DERtoPEM(&cerCtx, CERT_TYPE, PEM, &length);
    *DeviceCertBufSize = length;
    memcpy(DeviceCertBuffer, PEM, length);

#ifdef DEBUG
    WriteBinaryFile("DeviceIDCrt.DER", derCtx.Buffer, derCtx.Position);
    WriteBinaryFile("DeviceIDCrt.PEM", (uint8_t *)PEM, length);
#endif

    return 0;
}

#ifdef DEBUG
void HexConvert(uint8_t* in, int inLen, char* outBuf, int outLen)
    {
        int pos = 0;
        for (int j = 0; j < inLen; j++)
        {
            int err = sprintf_s(outBuf + pos, outLen - j * 2, "%02X", in[j]);
            pos += 2;
            if (err == -1) return;
        }
        return;
    }
void PrintHex(uint8_t* buf, int bufLen)
{
    printf("\n");
    for (int j = 0; j < bufLen; j++)
    {
        //int val = (int) buf[j];
        printf("%02x", buf[j]);
    }
    printf("\n");
    char buffer[2048];
    HexConvert(buf, bufLen, buffer, 2048);
    OutputDebugStringA("\n");
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
    return;
}
void WriteBinaryFile(const char* fileName, uint8_t* buf, int bufLen)
{
    FILE* f;
    errno_t err = fopen_s(&f, fileName, "wb");
    if (err != 0)return;
    int len = (int)fwrite(buf, 1, bufLen, f);
    if (len != bufLen)return;
    int res = fclose(f);
    if (res != 0)return;
    return;
}
void WriteTextFile(const char* fileName, uint8_t* buf, int bufLen, uint8_t append)
{
    FILE* f;
    char* mode = append ? "a+t" : "wt";
    errno_t err = fopen_s(&f, fileName, mode);
    if (err != 0)return;
    int len = (int)fwrite(buf, 1, bufLen, f);
    if (len != bufLen)return;
    int res = fclose(f);
    if (res != 0)return;
    return;
}
#endif
