#include "stdafx.h"
//ReIssueCert
PCCERT_CONTEXT ReIssueCert(PCCERT_CONTEXT device,
                           PCCERT_CONTEXT devAuthority,
                           PCCERT_CONTEXT appAuthority)
{
    DWORD retVal = STDFUFILES_NOERROR;
    std::exception_ptr pendingException = NULL;
    BCRYPT_ALG_HANDLE hRng = NULL;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE devAuthorityKey = NULL;
    DWORD dwKeySpec;
    BOOL pfCallerFreeProvOrCryptKey;
    DWORD result;
    PCCERT_CONTEXT newDevice = NULL;
    BCRYPT_KEY_HANDLE appAuthorityKey = NULL;

    try
    {
        if ((retVal = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0)) != 0)
        {
            throw retVal;
        }

        // Create the new device certificate to issue
        CERT_INFO certInfo = { 0 };
        certInfo.dwVersion = CERT_V3;
        certInfo.SerialNumber.cbData = 16;
        std::vector<BYTE> certSerial(certInfo.SerialNumber.cbData, 0);
        certInfo.SerialNumber.pbData = certSerial.data();
        if ((retVal = BCryptGenRandom(hRng, certSerial.data(), certSerial.size(), 0)) != 0)
        {
            throw retVal;
        }
        certSerial[certSerial.size() - 1] |= 0x01;  // Make sure the little endian serial number is not zero
        certSerial[certSerial.size() - 1] &= 0x7f;  // Make sure the little endian serial number is always positive
        certInfo.SignatureAlgorithm.pszObjId = szOID_ECDSA_SHA256;
        certInfo.Issuer.cbData = devAuthority->pCertInfo->Issuer.cbData;
        certInfo.Issuer.pbData = devAuthority->pCertInfo->Issuer.pbData;
        certInfo.Subject.cbData = device->pCertInfo->Subject.cbData;
        certInfo.Subject.pbData = device->pCertInfo->Subject.pbData;
        SYSTEMTIME systemTime;
        GetSystemTime(&systemTime);
        SystemTimeToFileTime(&systemTime, &certInfo.NotBefore);
        systemTime.wYear += 20;
        SystemTimeToFileTime(&systemTime, &certInfo.NotAfter);
        certInfo.SubjectPublicKeyInfo = device->pCertInfo->SubjectPublicKeyInfo;

        std::vector<BYTE> tcpsId;
        certInfo.cExtension = device->pCertInfo->cExtension;
        certInfo.rgExtension = device->pCertInfo->rgExtension;
        if (appAuthority != NULL)
        {
            // Extract the CBOR encoded TCPSID
            for (UINT32 n = 0; n < certInfo.cExtension; n++)
            {
                if (!strcmp(certInfo.rgExtension[n].pszObjId, szTcpsOID))
                {
                    // Export the app authority pub key and convert it to the right format
                    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &appAuthority->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &appAuthorityKey))
                    {
                        throw GetLastError();
                    }
                    if ((retVal = BCryptExportKey(appAuthorityKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &result, 0)) != 0)
                    {
                        throw retVal;
                    }
                    std::vector<BYTE> codeAuthPub(result, 0);
                    if ((retVal = BCryptExportKey(appAuthorityKey, NULL, BCRYPT_ECCPUBLIC_BLOB, codeAuthPub.data(), codeAuthPub.size(), &result, 0)) != 0)
                    {
                        throw retVal;
                    }
                    BCRYPT_ECCKEY_BLOB* keyHdr = (BCRYPT_ECCKEY_BLOB*)codeAuthPub.data();
                    RIOT_ECC_PUBLIC appAuthorityPubKey;
                    BigIntToBigVal(&appAuthorityPubKey.x, &codeAuthPub[sizeof(BCRYPT_ECCKEY_BLOB)], keyHdr->cbKey);
                    BigIntToBigVal(&appAuthorityPubKey.y, &codeAuthPub[sizeof(BCRYPT_ECCKEY_BLOB) + keyHdr->cbKey], keyHdr->cbKey);
                    appAuthorityPubKey.infinity = 0;

                    // Decode the TCPS ID
                    result = 0;
                    std::vector<BYTE> encodedTcpsId(certInfo.rgExtension[n].Value.cbData, 0x00);
                    memcpy(encodedTcpsId.data(), certInfo.rgExtension[n].Value.pbData, certInfo.rgExtension[n].Value.cbData);
                    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_OCTET_STRING, encodedTcpsId.data(), encodedTcpsId.size(), 0, NULL, &result))
                    {
                        throw GetLastError();
                    }
                    std::vector<BYTE> decodedTcpsId(result, 0x00);
                    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_OCTET_STRING, encodedTcpsId.data(), encodedTcpsId.size(), 0, decodedTcpsId.data(), &result))
                    {
                        throw GetLastError();
                    }
                    CRYPT_INTEGER_BLOB* tcpsIdInfo = (CRYPT_INTEGER_BLOB*)decodedTcpsId.data();
                    tcpsId = std::vector<BYTE>(tcpsIdInfo->pbData, &tcpsIdInfo->pbData[tcpsIdInfo->cbData]);

                    // Add the appAuthority to the CBOR encoded data
                    result = 0;
                    if ((retVal = ModifyTCPSDeviceIdentity(tcpsId.data(), tcpsId.size(), NULL, &appAuthorityPubKey, NULL, 0, NULL, 0, (uint32_t*)&result)) != RIOT_BAD_FORMAT)
                    {
                        throw retVal;
                    }
                    std::vector<BYTE> newTcpsId(result, 0x00);
                    if ((retVal = ModifyTCPSDeviceIdentity(tcpsId.data(), tcpsId.size(), NULL, &appAuthorityPubKey, NULL, 0, newTcpsId.data(), newTcpsId.size(), (uint32_t*)&result)) != RIOT_SUCCESS)
                    {
                        throw retVal;
                    }

                    // Log the CBOR
                    WriteToFile(L"DeviceDataSheet.CBOR", newTcpsId, OPEN_ALWAYS);
                    wprintf(L"DeviceDataSheet.CBOR updated.\n");

                    // Encode the TCPS ID
                    decodedTcpsId = std::vector<BYTE>(sizeof(CRYPT_INTEGER_BLOB) + newTcpsId.size(), 0x00);
                    tcpsIdInfo = (CRYPT_INTEGER_BLOB*)decodedTcpsId.data();
                    tcpsIdInfo->pbData = &decodedTcpsId[sizeof(CRYPT_INTEGER_BLOB)];
                    tcpsIdInfo->cbData = newTcpsId.size();
                    memcpy(tcpsIdInfo->pbData, newTcpsId.data(), tcpsIdInfo->cbData);

                    if (!CryptEncodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_OCTET_STRING, decodedTcpsId.data(), NULL, &result))
                    {
                        throw GetLastError();
                    }
                    encodedTcpsId = std::vector<BYTE>(result, 0x00);
                    if (!CryptEncodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_OCTET_STRING, decodedTcpsId.data(), encodedTcpsId.data(), &result))
                    {
                        throw GetLastError();
                    }

                    // Set the new TCPS data blob and continue
                    tcpsId = encodedTcpsId;
                    certInfo.rgExtension[n].Value.pbData = tcpsId.data();
                    certInfo.rgExtension[n].Value.cbData = tcpsId.size();
                    break;
                }
            }
        }
        for (UINT32 n = 0; n < certInfo.cExtension; n++)
        {
            if (!strcmp(certInfo.rgExtension[n].pszObjId, szOID_AUTHORITY_KEY_IDENTIFIER))
            {
                // Find the authority's key identifier
                std::vector<BYTE> authorityKeyId;
                CERT_AUTHORITY_KEY_ID_INFO keyIdInfo = { 0 };
                keyIdInfo.CertSerialNumber.cbData = devAuthority->pCertInfo->SerialNumber.cbData;
                keyIdInfo.CertSerialNumber.pbData = devAuthority->pCertInfo->SerialNumber.pbData;
                keyIdInfo.CertIssuer.cbData = devAuthority->pCertInfo->Issuer.cbData;
                keyIdInfo.CertIssuer.pbData = devAuthority->pCertInfo->Issuer.pbData;

                for (UINT32 m = 0; m < devAuthority->pCertInfo->cExtension; m++)
                {
                    // Replace it with the authorities key identifier
                    if (!strcmp(devAuthority->pCertInfo->rgExtension[m].pszObjId, szOID_SUBJECT_KEY_IDENTIFIER))
                    {
                        CRYPT_DIGEST_BLOB keyId = { 0 };
                        DWORD keyidSize = sizeof(keyId);
                        if (!CryptDecodeObject(X509_ASN_ENCODING,
                            devAuthority->pCertInfo->rgExtension[m].pszObjId,
                            devAuthority->pCertInfo->rgExtension[m].Value.pbData,
                            devAuthority->pCertInfo->rgExtension[m].Value.cbData,
                            CRYPT_DECODE_NOCOPY_FLAG,
                            &keyId, &keyidSize))
                        {
                            throw GetLastError();
                        }
                        authorityKeyId.resize(keyId.cbData);
                        keyIdInfo.KeyId.cbData = (UINT32)authorityKeyId.size();
                        keyIdInfo.KeyId.pbData = authorityKeyId.data();
                        memcpy(keyIdInfo.KeyId.pbData, keyId.pbData, keyIdInfo.KeyId.cbData);
                        break;
                    }
                }
                if (!CryptEncodeObjectEx(X509_ASN_ENCODING,
                    X509_AUTHORITY_KEY_ID,
                    &keyIdInfo,
                    CRYPT_ENCODE_ALLOC_FLAG,
                    NULL,
                    &certInfo.rgExtension[n].Value.pbData,
                    &certInfo.rgExtension[n].Value.cbData))
                {
                    throw GetLastError();
                }
                break;
            }
        }

        // Issue the new certificate
        if (!CryptAcquireCertificatePrivateKey(devAuthority,
            CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            NULL,
            &devAuthorityKey,
            &dwKeySpec,
            &pfCallerFreeProvOrCryptKey))
        {
            throw GetLastError();
        }
        result = 0;
        CRYPT_ALGORITHM_IDENTIFIER certAlgId = { szOID_ECDSA_SHA256,{ 0, NULL } };
        if (!CryptSignAndEncodeCertificate(devAuthorityKey,
            dwKeySpec,
            X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED,
            &certInfo,
            &certAlgId,
            NULL,
            NULL,
            &result))
        {
            throw GetLastError();
        }
        std::vector<BYTE> newEncCert(result, 0);
        if (!CryptSignAndEncodeCertificate(devAuthorityKey,
            dwKeySpec,
            X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED,
            &certInfo,
            &certAlgId,
            NULL,
            newEncCert.data(),
            &result))
        {
            throw GetLastError();
        }
        if ((newDevice = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                      newEncCert.data(),
                                                      newEncCert.size())) == NULL)
        {
            throw GetLastError();
        }
    }
    catch (const std::exception& e)
    {
        UNREFERENCED_PARAMETER(e);
        pendingException = std::current_exception();
    }

    // Cleanup
    if (hRng != NULL)
    {
        BCryptCloseAlgorithmProvider(hRng, 0);
    }

    if (appAuthorityKey != NULL)
    {
        BCryptDestroyKey(appAuthorityKey);
    }

    if ((devAuthorityKey) && (pfCallerFreeProvOrCryptKey))
    {
        if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
        {
            NCryptFreeObject(devAuthorityKey);
        }
        else
        {
            CryptReleaseContext(devAuthorityKey, 0);
        }
    }

    if (pendingException != NULL)
    {
        std::rethrow_exception(pendingException);
    }
    return newDevice;
}

void IssueDeviceTrust(
    std::wstring fileName,
    PCCERT_CONTEXT devAuthCert,
    PCCERT_CONTEXT appAuthCert
)
{
    DWORD retVal = STDFUFILES_NOERROR;
    std::exception_ptr pendingException = NULL;
    std::string dfuFileName;
    HANDLE hDfuFile = INVALID_HANDLE_VALUE;
    WORD pid, vid, bcd;
    BYTE nbImages;
    HANDLE hImage = INVALID_HANDLE_VALUE;
    DWORD result;
    BCRYPT_KEY_HANDLE codeAuth = NULL;
    PCCERT_CONTEXT ssDevCert = NULL;
    BCRYPT_KEY_HANDLE devPub = NULL;
    PCCERT_CONTEXT newDevCert = NULL;

    try
    {
        dfuFileName.resize(fileName.size());
        if (!WideCharToMultiByte(CP_UTF8,
            WC_ERR_INVALID_CHARS,
            fileName.c_str(),
            fileName.size(),
            (LPSTR)dfuFileName.c_str(),
            dfuFileName.size(),
            NULL,
            NULL))
        {
            printf("%s: WideCharToMultiByte failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw GetLastError();
        }

        // Open the image in the DFU file
        if ((retVal = OpenExistingDFUFile((PSTR)dfuFileName.c_str(), &hDfuFile, &pid, &vid, &bcd, &nbImages)) != STDFUFILES_NOERROR)
        {
            printf("%s: OpenExistingDFUFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        if ((retVal = ReadImageFromDFUFile(hDfuFile, 0, &hImage)) != STDFUFILES_NOERROR)
        {
            printf("%s: ReadImageFromDFUFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        std::vector<BYTE> image(GetImageSize(hImage), 0x00);
        DFUIMAGEELEMENT imageElement = { 0, image.size(), image.data() };
        if ((retVal = GetImageElement(hImage, 0, &imageElement)) != STDFUFILES_NOERROR)
        {
            printf("%s: GetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        PBARNACLE_ISSUED_PUBLIC devData = (PBARNACLE_ISSUED_PUBLIC)imageElement.Data;
        if ((retVal = CloseDFUFile(hDfuFile)) != STDFUFILES_NOERROR)
        {
            printf("%s: CloseDFUFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        devData->info.flags |= BARNACLE_ISSUEDFLAG_PROVISIONIED;

        // Are we locking the device down?
        if (appAuthCert != NULL)
        {
            devData->info.flags |= BARNACLE_ISSUEDFLAG_AUTHENTICATED_BOOT | BARNACLE_ISSUEDFLAG_WRITELOCK;
            if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &appAuthCert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &codeAuth))
            {
                throw GetLastError();
            }
            if ((retVal = BCryptExportKey(codeAuth, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &result, 0)) != 0)
            {
                throw retVal;
            }
            std::vector<BYTE> codeAuthPub(result, 0);
            if ((retVal = BCryptExportKey(codeAuth, NULL, BCRYPT_ECCPUBLIC_BLOB, codeAuthPub.data(), codeAuthPub.size(), &result, 0)) != 0)
            {
                throw retVal;
            }
            BCRYPT_ECCKEY_BLOB* keyHdr = (BCRYPT_ECCKEY_BLOB*)codeAuthPub.data();
            DWORD cbKey = keyHdr->cbKey;
            codeAuthPub[sizeof(BCRYPT_ECCKEY_BLOB) - 1] = 0x04;
            RiotCrypt_ImportEccPub(&codeAuthPub[sizeof(BCRYPT_ECCKEY_BLOB) - 1], cbKey * 2 + 1, &devData->info.codeAuthPubKey);
            wprintf(L"CodeAuthorityPub:\n0x");
            for (UINT32 n = 0; n < cbKey * 2 + 1; n++)
            {
                if (!((n + 1) % 22) && (n > 0)) wprintf(L"\n");
                wprintf(L"%02x", codeAuthPub[sizeof(BCRYPT_ECCKEY_BLOB) - 1 + n]);
            }
            wprintf(L"\n");
        }

        // Open the selfsigned device certificate and verify it
        std::string selfsignedCert((char*)&devData->certBag[devData->info.certTable[BARNACLE_ISSUED_DEVICE].start]);
        result = 0;
        if (!CryptStringToBinaryA((LPCSTR)&devData->certBag[devData->info.certTable[BARNACLE_ISSUED_DEVICE].start],
                                    devData->info.certTable[BARNACLE_ISSUED_DEVICE].size,
                                    CRYPT_STRING_BASE64HEADER,
                                    NULL,
                                    &result,
                                    NULL,
                                    NULL))
        {
            retVal = GetLastError();
            throw retVal;
        }
        std::vector<BYTE> rawCert(result, 0);
        if (!CryptStringToBinaryA((LPCSTR)&devData->certBag[devData->info.certTable[BARNACLE_ISSUED_DEVICE].start],
                                    devData->info.certTable[BARNACLE_ISSUED_DEVICE].size,
                                    CRYPT_STRING_BASE64HEADER,
                                    rawCert.data(),
                                    &result,
                                    NULL,
                                    NULL))
        {
            retVal = GetLastError();
            throw retVal;
        }
        if ((ssDevCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            rawCert.data(),
            rawCert.size())) == NULL)
        {
            throw retVal;
        }
        DWORD validityFlags = CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG;
        if (!CertVerifySubjectCertificateContext(ssDevCert, ssDevCert, &validityFlags))
        {
            retVal = GetLastError();
            throw retVal;
        }

        // Export the Device Pubkey and print it
        if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &ssDevCert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &devPub))
        {
            retVal = GetLastError();
            throw retVal;
        }
        if ((retVal = BCryptExportKey(devPub, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &result, 0)))
        {
            throw retVal;
        }
        std::vector<BYTE> pubKey(result, 0x00);
        PBCRYPT_ECCKEY_BLOB pPubKey;
        pPubKey = (PBCRYPT_ECCKEY_BLOB)pubKey.data();
        if ((retVal = BCryptExportKey(devPub, NULL, BCRYPT_ECCPUBLIC_BLOB, pubKey.data(), pubKey.size(), &result, 0)))
        {
            throw retVal;
        }
        wprintf(L"DevicePub:\n0x04");
        for (UINT32 n = 0; n < pPubKey->cbKey * 2; n++)
        {
            if (!((n + 2) % 22) && (n > 0)) wprintf(L"\n");
            wprintf(L"%02x", pubKey[sizeof(BCRYPT_ECCKEY_BLOB) + n]);
        }
        wprintf(L"\n");
        std::vector<byte> devPub(&pubKey[sizeof(BCRYPT_ECCKEY_BLOB)], &pubKey[sizeof(BCRYPT_ECCKEY_BLOB) + pPubKey->cbKey * 2]);
        wprintf(L"DevID: %s\n", ToDevIDWString(devPub, false).c_str());

        newDevCert = ReIssueCert(ssDevCert, devAuthCert, appAuthCert);

        // PEM encode the authority cert
        if (!CryptBinaryToStringA(devAuthCert->pbCertEncoded, devAuthCert->cbCertEncoded, CRYPT_STRING_BASE64HEADER, NULL, &result))
        {
            retVal = GetLastError();
            throw retVal;
        }
        std::string authCertStr(result, '\0');
        if (!CryptBinaryToStringA(devAuthCert->pbCertEncoded, devAuthCert->cbCertEncoded, CRYPT_STRING_BASE64HEADER, (LPSTR)authCertStr.c_str(), &result))
        {
            retVal = GetLastError();
            throw retVal;
        }

        // Store a local copy of the device cert
        if (!CryptBinaryToStringA(newDevCert->pbCertEncoded, newDevCert->cbCertEncoded, CRYPT_STRING_BASE64HEADER, NULL, &result))
        {
            retVal = GetLastError();
            throw retVal;
        }
        std::string devCertStr(result, '\0');
        if (!CryptBinaryToStringA(newDevCert->pbCertEncoded, newDevCert->cbCertEncoded, CRYPT_STRING_BASE64HEADER, (LPSTR)devCertStr.c_str(), &result))
        {
            retVal = GetLastError();
            throw retVal;
        }
        std::wstring certFileName = std::wstring(L"Barnacle-") + ToDevIDWString(devPub, true).c_str() + std::wstring(L".cer");
        WriteToFile(certFileName, devCertStr);
        wprintf(L"%s written.\n", certFileName.c_str());

        // Insert the two certificates in the data table
        memset(devData->certBag, 0x00, sizeof(devData->certBag));
        devData->info.cursor = sizeof(devData->certBag) - 1;
        if (authCertStr.size() + devCertStr.size() > sizeof(devData->certBag))
        {
            throw ERROR_BUFFER_OVERFLOW;
        }
        devData->info.certTable[BARNACLE_ISSUED_ROOT].size = (uint16_t)authCertStr.size();
        devData->info.certTable[BARNACLE_ISSUED_ROOT].start = (uint16_t)(devData->info.cursor - authCertStr.size());
        devData->info.cursor -= authCertStr.size();
        memcpy(&devData->certBag[devData->info.cursor], authCertStr.c_str(), authCertStr.size());
        devData->info.certTable[BARNACLE_ISSUED_DEVICE].size = (uint16_t)devCertStr.size();
        devData->info.certTable[BARNACLE_ISSUED_DEVICE].start = (uint16_t)(devData->info.cursor - devCertStr.size());
        devData->info.cursor -= devCertStr.size();
        memcpy(&devData->certBag[devData->info.cursor], devCertStr.c_str(), devCertStr.size());

        // Write the data table to a new DFU file 
        dfuFileName = dfuFileName.substr(0, dfuFileName.size() - 4) + std::string("-") + ToDevIDString(devPub, true).c_str() + std::string(".dfu");
        if ((retVal = CreateNewDFUFile((PSTR)dfuFileName.c_str(), &hDfuFile, pid, vid, bcd)) != STDFUFILES_NOERROR)
        {
            printf("%s: CreateNewDFUFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }

        if ((retVal = SetImageElement(hImage, 0, false, imageElement)) != STDFUFILES_NOERROR)
        {
            printf("%s: SetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }

        if ((retVal = AppendImageToDFUFile(hDfuFile, hImage)) != STDFUFILES_NOERROR)
        {
            printf("%s: SetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }

        if ((retVal = CloseDFUFile(hDfuFile)) != STDFUFILES_NOERROR)
        {
            printf("%s: CloseDFUFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        printf("%s written.\n", dfuFileName.c_str());
    }
    catch (const std::exception& e)
    {
        UNREFERENCED_PARAMETER(e);
        pendingException = std::current_exception();
    }

    // Cleanup
    if (codeAuth != NULL)
    {
        BCryptDestroyKey(codeAuth);
    }

    if (devPub != NULL)
    {
        BCryptDestroyKey(devPub);
    }

    if (ssDevCert != NULL)
    {
        CertFreeCertificateContext(ssDevCert);
    }

    if (newDevCert != NULL)
    {
        CertFreeCertificateContext(newDevCert);
    }

    if (pendingException != NULL)
    {
        std::rethrow_exception(pendingException);
    }
}

bool RunIssueDeviceTrust(std::unordered_map<std::wstring, std::wstring> param)
{
    bool result = true;
    std::unordered_map<std::wstring, std::wstring>::iterator it;
    std::wstring dfuName(param.find(L"00")->second);
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT hDevAuthCert = NULL;
    PCCERT_CONTEXT hCodeAuthCert = NULL;

    try
    {
        if (((it = param.find(L"-at")) != param.end()) || ((it = param.find(L"-af")) != param.end()))
        {
            std::vector<BYTE> certThumbPrint;
            if ((it = param.find(L"-at")) != param.end())
            {
                // Get NCrypt Handle to certificate private key pointed to by CertThumbPrint
                certThumbPrint = ReadHex(it->second);
            }
            if ((it = param.find(L"-af")) != param.end())
            {
                // Get NCrypt Handle to certificate private key pointed to by Certificate file
                PCCERT_CONTEXT hCert = CertFromFile(it->second);
                certThumbPrint = CertThumbPrint(hCert);
                CertFreeCertificateContext(hCert);
            }
            CRYPT_HASH_BLOB findTP = { certThumbPrint.size(), certThumbPrint.data() };
            if ((hStore = CertOpenSystemStore(NULL, TEXT("MY"))) == NULL)
            {
                printf("%s: CertOpenSystemStore failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw GetLastError();
            }
            if ((hDevAuthCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &findTP, NULL)) == NULL)
            {
                printf("%s: CertFindCertificateInStore failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw GetLastError();
            }
        }
        if (((it = param.find(L"-ct")) != param.end()) || ((it = param.find(L"-cf")) != param.end()))
        {
            std::vector<BYTE> certThumbPrint;
            if ((it = param.find(L"-ct")) != param.end())
            {
                // Get NCrypt Handle to certificate private key pointed to by CertThumbPrint
                certThumbPrint = ReadHex(it->second);
            }
            if ((it = param.find(L"-cf")) != param.end())
            {
                // Get NCrypt Handle to certificate private key pointed to by Certificate file
                PCCERT_CONTEXT hCert = CertFromFile(it->second);
                certThumbPrint = CertThumbPrint(hCert);
                CertFreeCertificateContext(hCert);
            }
            CRYPT_HASH_BLOB findTP = { certThumbPrint.size(), certThumbPrint.data() };
            if ((hStore == NULL) && ((hStore = CertOpenSystemStore(NULL, TEXT("MY"))) == NULL))
            {
                printf("%s: CertOpenSystemStore failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw GetLastError();
            }
            if ((hCodeAuthCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &findTP, NULL)) == NULL)
            {
                printf("%s: CertFindCertificateInStore failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw GetLastError();
            }
        }
        IssueDeviceTrust(dfuName, hDevAuthCert, hCodeAuthCert);
    }
    catch (const std::exception& e)
    {
        UNREFERENCED_PARAMETER(e);
        result = false;
    }
    return result;
}
