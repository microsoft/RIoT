/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include "stdafx.h"

// There are lots of ways to force a new CDI value. However, to
// maintain a consistent CDI value accross "boots", the default
// linker option that randomizes base addresses must be disabled.

// For our simulated device, it's fine that these are in the global
// data for the RIoT DLL. On real hardware, these are passed via hardware
// security module or shared data area.
RIOT_ECC_PUBLIC     DeviceIDPub;
RIOT_ECC_PUBLIC     AliasKeyPub;
RIOT_ECC_PRIVATE    AliasKeyPriv;
char                AliasCert[DER_MAX_PEM];
char                DeviceCert[DER_MAX_PEM];
char                r00tCert[DER_MAX_PEM];

// The static data fields that make up the Alias Cert "to be signed" region.
// If the device SubjectCommon is *, then a device-unique GUID is generated.
// If a self-signed DeviceID cert is selected, then the tbs subject is also
// used for the issuer.
RIOT_X509_TBS_DATA x509AliasTBSData = { { 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
                                        "RIoT Core", "MSR_TEST", "US",
                                        "170101000000Z", "370101000000Z",
                                        "*", "MSR_TEST", "US" };

// The static data fields that make up the DeviceID Cert "to be signed" region
RIOT_X509_TBS_DATA x509DeviceTBSData = { { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 },
                                        "RIoT R00t", "MSR_TEST", "US",
                                        "170101000000Z", "370101000000Z",
                                        "RIoT Core", "MSR_TEST", "US" };

// The static data fields that make up the "root signer" Cert
RIOT_X509_TBS_DATA x509RootTBSData = { { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E , 0x6F, 0x70, 0x81 },
                                        "RIoT R00t", "MSR_TEST", "US",
                                        "170101000000Z", "370101000000Z",
                                        "RIoT R00t", "MSR_TEST", "US" };

// Selectors for DeviceID cert handling.  
#define RIOT_ROOT_SIGNED    0x00
#define RIOT_SELF_SIGNED    0x01
#define RIOT_CSR            0x02

#define DEVICE_ID_CERT_TYPE RIOT_ROOT_SIGNED

// The "root" signing key. This is intended for development purposes only.
// This key is used to sign the DeviceID certificate, the certificiate for
// this "root" key represents the "trusted" CA for the developer-mode DPS
// server(s). Again, this is for development purposes only and (obviously)
// provides no meaningful security whatsoever.
BYTE eccRootPubBytes[sizeof(ecc_publickey)] = {
    0xeb, 0x9c, 0xfc, 0xc8, 0x49, 0x94, 0xd3, 0x50, 0xa7, 0x1f, 0x9d, 0xc5,
    0x09, 0x3d, 0xd2, 0xfe, 0xb9, 0x48, 0x97, 0xf4, 0x95, 0xa5, 0x5d, 0xec,
    0xc9, 0x0f, 0x52, 0xa1, 0x26, 0x5a, 0xab, 0x69, 0x00, 0x00, 0x00, 0x00,
    0x7d, 0xce, 0xb1, 0x62, 0x39, 0xf8, 0x3c, 0xd5, 0x9a, 0xad, 0x9e, 0x05,
    0xb1, 0x4f, 0x70, 0xa2, 0xfa, 0xd4, 0xfb, 0x04, 0xe5, 0x37, 0xd2, 0x63,
    0x9a, 0x46, 0x9e, 0xfd, 0xb0, 0x5b, 0x1e, 0xdf, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00 };

BYTE eccRootPrivBytes[sizeof(ecc_privatekey)] = {
    0xe3, 0xe7, 0xc7, 0x13, 0x57, 0x3f, 0xd9, 0xc8, 0xb8, 0xe1, 0xea, 0xf4,
    0x53, 0xf1, 0x56, 0x15, 0x02, 0xf0, 0x71, 0xc0, 0x53, 0x49, 0xc8, 0xda,
    0xe6, 0x26, 0xa9, 0x0b, 0x17, 0x88, 0xe5, 0x70, 0x00, 0x00, 0x00, 0x00 };

// Name and function pointer corresponding to the current FW image
#define FIRMWARE_ENTRY        "FirmwareEntry"
typedef void(__cdecl* fpFirmwareEntry)(
    char             *r00tCert,
    ecc_publickey    *DeviceIDPub,
    char             *DeviceCert,
    ecc_publickey    *AliasKeyPub,
    ecc_privatekey   *AliasKeyPriv,
    char             *AliasKeyCert
    );

// Simulation only: This function finds the in-memory base-offset and size
// of the RIoT .text section. On real hardware RIoT would have knowledge of
// the physical address and size of device firmware.
BOOLEAN RiotGetFWInfo(HINSTANCE fwDLL, DWORD *baseOffset, DWORD *length);

// Sets tbsData->SerialNumber to a quasi-random value derived from seedData
void RiotSetSerialNumber(RIOT_X509_TBS_DATA* tbsData, const uint8_t* seedData, size_t seedLen);

RIOT_API void
RiotStart(
    const BYTE *CDI,
    const uint32_t CDILen,
    const TCHAR *FWImagePath
)
{
    BYTE                derBuffer[DER_MAX_TBS];
    BYTE                cDigest[RIOT_DIGEST_LENGTH];
    BYTE                FWID[RIOT_DIGEST_LENGTH];
    RIOT_ECC_PRIVATE    deviceIDPriv;
    RIOT_ECC_SIGNATURE  tbsSig;
    DERBuilderContext   derCtx;
    fpFirmwareEntry     FirmwareEntry;
    BYTE               *fwImage;
    uint32_t            length, PEMtype;
    DWORD               fwSize, offset, i;
    HINSTANCE           fwDLL;

    // Parameter validation
    if (!(CDI) || (CDILen != SHA256_DIGEST_LENGTH)) {
        return;
    }

    // RIoT Begin
    printf("RIOT: Begin\n");

    // Don't use CDI directly
    RiotCrypt_Hash(cDigest, RIOT_DIGEST_LENGTH, CDI, CDILen);

    // Derive DeviceID key pair from CDI
    RiotCrypt_DeriveEccKey(&DeviceIDPub,
                           &deviceIDPriv,
                           cDigest, RIOT_DIGEST_LENGTH,
                           (const uint8_t *)RIOT_LABEL_IDENTITY,
                           lblSize(RIOT_LABEL_IDENTITY));

    // Set the serial number for DeviceID certificate
    RiotSetSerialNumber(&x509DeviceTBSData, cDigest, RIOT_DIGEST_LENGTH);

    // Output Device Identity Key pair
    printf("RIOT: deviceIDPublic:\n\tx: ");
    for (i = 0; i < ((BIGLEN) - 1); i++) {
        printf("%08X", DeviceIDPub.x.data[i]);
    }
    printf("\n\ty: ");
    for (i = 0; i < ((BIGLEN) - 1); i++) {
        printf("%08X", DeviceIDPub.y.data[i]);
    }
    printf("\nRIOT: deviceIDPrivate:\n\t   ");
    for (i = 0; i < ((BIGLEN)-1); i++) {
        printf("%08X", deviceIDPriv.data[i]);
    }
    printf("\n");

    // Locate firmware image
    fwDLL = LoadLibrary(FWImagePath);
    if (fwDLL == NULL) {
        printf("RIOT: ERROR: Failed to load firmware image.\n");
        return;
    }
    
    // Locate entry point for FW
    FirmwareEntry = (fpFirmwareEntry)GetProcAddress(fwDLL, FIRMWARE_ENTRY);
    if (!FirmwareEntry) {
        printf("RIOT: ERROR: Failed to locate fw start\n");
        return;
    }

    // Get base offset and size of FW image
    if (!RiotGetFWInfo(fwDLL, &offset, &fwSize)) {
        fprintf(stderr, "FW: Failed to locate FW code\n");
        return;
    }

    // Calculate base VA of FW code
    fwImage = (BYTE *)((uint64_t)fwDLL + offset);

    // Measure FW, i.e., calculate FWID
    RiotCrypt_Hash(FWID, RIOT_DIGEST_LENGTH, fwImage, fwSize);

    // Combine CDI and FWID, result in cDigest
    RiotCrypt_Hash2(cDigest, RIOT_DIGEST_LENGTH,
                    cDigest, RIOT_DIGEST_LENGTH,
                    FWID,    RIOT_DIGEST_LENGTH);

    // Derive Alias key pair from CDI and FWID
    RiotCrypt_DeriveEccKey(&AliasKeyPub,
                           &AliasKeyPriv,
                           cDigest, RIOT_DIGEST_LENGTH,
                           (const uint8_t *)RIOT_LABEL_ALIAS,
                           lblSize(RIOT_LABEL_ALIAS));

    // With the Alias Key pair derived, we can now Seed DRBG
    RiotCrypt_SeedDRBG((uint8_t*)&AliasKeyPriv, sizeof(RIOT_ECC_PRIVATE));

    // Set the serial number
    RiotSetSerialNumber(&x509AliasTBSData, cDigest, RIOT_DIGEST_LENGTH);

    // Clean up potentially sensative data
    memset(cDigest, 0x00, RIOT_DIGEST_LENGTH);
    
    // Build the TBS (to be signed) region of Alias Key Certificate
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetAliasCertTBS(&derCtx, &x509AliasTBSData,
                        &AliasKeyPub, &DeviceIDPub,
                        FWID, RIOT_DIGEST_LENGTH);

    // Sign the Alias Key Certificate's TBS region
    RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

    // Generate Alias Key Certificate
    X509MakeAliasCert(&derCtx, &tbsSig);

    // Copy Alias Key Certificate
    length = sizeof(AliasCert);
    DERtoPEM(&derCtx, CERT_TYPE, AliasCert, &length);
    AliasCert[length] = '\0';

    // This reference supports generation of either: a "root"-signed DeviceID
    // certificate, or a certificate signing request for the DeviceID Key. 
    // In a production device, Alias Key Certificates are normally leaf certs
    // that chain back to a known root CA. This is difficult to represent in
    // simulation since different vendors each have different manufacturing 
    // processes and CAs.

    if (DEVICE_ID_CERT_TYPE == RIOT_SELF_SIGNED) {
        // Generating self-signed DeviceID certificate

        x509DeviceTBSData.IssuerCommon  = x509DeviceTBSData.SubjectCommon;
        x509DeviceTBSData.IssuerOrg     = x509DeviceTBSData.IssuerOrg;
        x509DeviceTBSData.IssuerCountry = x509DeviceTBSData.SubjectCountry;

        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&derCtx, &x509DeviceTBSData, &DeviceIDPub, NULL, 0);

        // Sign the DeviceID Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

        // Generate DeviceID Certificate
        X509MakeDeviceCert(&derCtx, &tbsSig);
        PEMtype = CERT_TYPE;
    }
    else if (DEVICE_ID_CERT_TYPE == RIOT_CSR) {
        // Generating CSR
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDERCsrTbs(&derCtx, &x509AliasTBSData, &DeviceIDPub);

        // Sign the Alias Key Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

        // Create CSR for DeviceID
        X509GetDERCsr(&derCtx, &tbsSig);
        PEMtype = CERT_REQ_TYPE;
    }
    else {
        // Generating "root"-signed DeviceID certificate

        uint8_t     rootPubBuffer[65];
        uint32_t    rootPubBufLen = 65;

        RiotCrypt_ExportEccPub((RIOT_ECC_PUBLIC *)eccRootPubBytes, rootPubBuffer, &rootPubBufLen);

        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&derCtx, &x509DeviceTBSData, &DeviceIDPub, rootPubBuffer, rootPubBufLen);

        // Sign the DeviceID Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, (RIOT_ECC_PRIVATE *)eccRootPrivBytes);

        RiotCrypt_Verify(derCtx.Buffer, derCtx.Position, &tbsSig, (RIOT_ECC_PUBLIC *)eccRootPubBytes);

        // Generate DeviceID Certificate
        X509MakeDeviceCert(&derCtx, &tbsSig);
        PEMtype = CERT_TYPE;
    }

    // Copy DeviceID Certificate
    length = sizeof(DeviceCert);
    DERtoPEM(&derCtx, PEMtype, DeviceCert, &length);
    DeviceCert[length] = '\0';

    // Generate "root" CA certficiate
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetRootCertTBS(&derCtx, &x509RootTBSData, (RIOT_ECC_PUBLIC*)eccRootPubBytes);

    // Self-sign the "root" Certificate's TBS region
    RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, (RIOT_ECC_PRIVATE *)eccRootPrivBytes);

    // Generate "root" CA cert
    X509MakeRootCert(&derCtx, &tbsSig);

    // Copy "root" CA Certificate
    length = sizeof(r00tCert);
    DERtoPEM(&derCtx, CERT_TYPE, r00tCert, &length);

    // Transfer control to firmware
    FirmwareEntry(r00tCert, &DeviceIDPub, DeviceCert, &AliasKeyPub, &AliasKeyPriv, AliasCert);

    return;
}

BOOLEAN
RiotGetFWInfo(
    HINSTANCE   fwDLL,
    DWORD      *baseOffset,
    DWORD      *length
)
// This is a quick and dirty function to find the .text (CODE) section of
// the FW image. We don't do anything like this on real hardware because,
// on real hardware, RIoT has the base address and size of the FW are
// as constant values resolved at build/link time.
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fwDLL;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PCHAR)dosHeader + (ULONG)(dosHeader->e_lfanew));
    PIMAGE_OPTIONAL_HEADER optionalHeader = &(ntHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(optionalHeader + 1);
    PIMAGE_FILE_HEADER fileHeader = &(ntHeader->FileHeader);
    ULONG nSections = fileHeader->NumberOfSections, i;

    for (i = 0; i < nSections; i++)
    {
        if (!strcmp((char *)sectionHeader->Name, ".text"))
        {
            *baseOffset = sectionHeader->VirtualAddress;
            *length = sectionHeader->Misc.VirtualSize;
            return TRUE;
        }
        sectionHeader++;
    }
    return FALSE;
}

void
RiotSetSerialNumber(
    RIOT_X509_TBS_DATA  *tbsData, 
    const uint8_t       *seedData,
    size_t               seedLen
)
// Set the tbsData serial number to 8 bytes of data derived from seedData
{
    
    uint8_t hashBuf[RIOT_DIGEST_LENGTH];
    // SHA-1 hash of "DICE SEED" == 6e785006 84941d8f 7880520c 60b8c7e4 3f1a3c00
    uint8_t seedExtender[20] = { 0x6e, 0x78, 0x50, 0x06, 0x84, 0x94, 0x1d, 0x8f, 0x78, 0x80,
                                 0x52, 0x0c, 0x60, 0xb8, 0xc7, 0xe4, 0x3f, 0x1a, 0x3c, 0x00 };

    RiotCrypt_Hash2(hashBuf, sizeof(hashBuf), seedData, seedLen, seedExtender, sizeof(seedExtender));

    // Take first 8 bytes to form serial number
    memcpy(tbsData->SerialNum, hashBuf, RIOT_X509_SNUM_LEN);

    // DER encoded serial number must be positive and the first byte must not be zero
    tbsData->SerialNum[0] &= (uint8_t)0x7f;
    tbsData->SerialNum[0] |= (uint8_t)0x01;

    return;
}