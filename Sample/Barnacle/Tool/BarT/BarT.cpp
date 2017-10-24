// BarT.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

void SignAgent(
    std::wstring fileName,
    PCCERT_CONTEXT appAuthCert
)
{
    DWORD retVal = STDFUFILES_NOERROR;
    DWORD dwKeySpec;
    BOOL pfCallerFreeProvOrCryptKey;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE codeAuth = NULL;
    HANDLE hHexFile = INVALID_HANDLE_VALUE;
    HANDLE hDfuFile = INVALID_HANDLE_VALUE;
    DFUIMAGEELEMENT dfuImageElement = { 0 };
    BCRYPT_ALG_HANDLE hSha256 = NULL;
    std::exception_ptr pendingException = NULL;

    try
    {
        if ((retVal = BCryptOpenAlgorithmProvider(&hSha256,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0)) != 0)
        {
            printf("%s: BCryptOpenAlgorithmProvider failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }

        if (!CryptAcquireCertificatePrivateKey(appAuthCert,
            CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            NULL,
            &codeAuth,
            &dwKeySpec,
            &pfCallerFreeProvOrCryptKey))
        {
            printf("%s: CryptAcquireCertificatePrivateKey failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw GetLastError();
        }

        std::string hexFileName;
        hexFileName.resize(fileName.size());
        if (!WideCharToMultiByte(CP_UTF8,
                                 WC_ERR_INVALID_CHARS,
                                 fileName.c_str(),
                                 fileName.size(),
                                 (LPSTR)hexFileName.c_str(),
                                 hexFileName.size(),
                                 NULL,
                                 NULL))
        {
            printf("%s: WideCharToMultiByte failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw GetLastError();
        }

        // Get the agent image
        if ((retVal = ImageFromFile((PSTR)hexFileName.c_str(), &hHexFile, 0)) != STDFUFILES_NOERROR)
        {
            printf("%s: ImageFromFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        std::vector<BYTE> image(GetImageSize(hHexFile), 0x00);
        dfuImageElement.dwDataLength = image.size();
        dfuImageElement.Data = image.data();
        if ((retVal = GetImageElement(hHexFile, 0, &dfuImageElement)) != STDFUFILES_NOERROR)
        {
            printf("%s: GetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        dfuImageElement.dwDataLength = image.size();
        for (DWORD rank = 1; ; rank++)
        {
            DFUIMAGEELEMENT iterator = { 0 };
            if ((retVal = GetImageElement(hHexFile, rank, &iterator)) != STDFUFILES_NOERROR)
            {
                break;
            }
            std::vector<BYTE> fragment(iterator.dwDataLength, 0x00);
            iterator.Data = fragment.data();
            if ((retVal = GetImageElement(hHexFile, rank, &iterator)) != STDFUFILES_NOERROR)
            {
                printf("%s: GetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            memcpy(&image[iterator.dwAddress - dfuImageElement.dwAddress], fragment.data(), fragment.size());
            if ((retVal = DestroyImageElement(hHexFile, rank)) != STDFUFILES_NOERROR)
            {
                printf("%s: DestroyImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
        }

        // Add the information about this image to the header
        PBARNACLE_AGENT_HDR AgentHdr;
        AgentHdr = (PBARNACLE_AGENT_HDR)image.data();
        if ((AgentHdr->sign.hdr.magic != BARNACLEMAGIC) ||
            (AgentHdr->sign.hdr.size != sizeof(BARNACLE_AGENT_HDR)) ||
            (AgentHdr->sign.hdr.version != BARNACLEVERSION))
        {
            printf("%s: Bad agent image (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw ERROR_INVALID_DATA;
        }
        
        AgentHdr->sign.agent.size = image.size() - AgentHdr->sign.hdr.size;
        AgentHdr->sign.agent.issued = GetTimeStamp();
        hexFileName.resize(hexFileName.size() - 4);
        strncpy_s(AgentHdr->sign.agent.name, hexFileName.c_str(), sizeof(AgentHdr->sign.agent.name));
        if ((retVal = BCryptHash(hSha256, NULL, 0, (PBYTE)&image[AgentHdr->sign.hdr.size], AgentHdr->sign.agent.size, AgentHdr->sign.agent.digest, sizeof(AgentHdr->sign.agent.digest))) != 0)
        {
            printf("%s: BCryptHash failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }

        // Sign the header
        if (codeAuth != NULL)
        {
            std::vector<BYTE> hdrDigest(SHA256_DIGEST_LENGTH, 0);
            if ((retVal = BCryptHash(hSha256, NULL, 0, (PBYTE)&AgentHdr->sign, sizeof(AgentHdr->sign), hdrDigest.data(), hdrDigest.size())) != 0)
            {
                printf("%s: BCryptHash failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            std::vector<BYTE> sig(32 * 2, 0);
            DWORD result;
            if ((retVal = NCryptSignHash(codeAuth, NULL, hdrDigest.data(), hdrDigest.size(), sig.data(), sig.size(), &result, 0)) != 0)
            {
                printf("%s: NCryptSignHash failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            memcpy(AgentHdr->signature.r, &sig[0], sizeof(AgentHdr->signature.r));
            memcpy(AgentHdr->signature.s, &sig[sizeof(AgentHdr->signature.r)], sizeof(AgentHdr->signature.s));
/*
            // Check the header signature
            ecc_signature riotSig = { 0 };
            BigIntToBigVal(&riotSig.r, AgentHdr->signature.r, sizeof(AgentHdr->signature.r));
            BigIntToBigVal(&riotSig.s, AgentHdr->signature.s, sizeof(AgentHdr->signature.s));
            if ((retVal = NCryptExportKey(codeAuth, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &result, 0)) != 0)
            {
                printf("%s: NCryptExportKey failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            std::vector<BYTE> codeAuthKeyData(result, 0);
            if ((retVal = NCryptExportKey(codeAuth, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, codeAuthKeyData.data(), codeAuthKeyData.size(), &result, 0)) != 0)
            {
                printf("%s: NCryptExportKey failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            BCRYPT_ECCKEY_BLOB* keyHdr = (BCRYPT_ECCKEY_BLOB*)codeAuthKeyData.data();
            ecc_publickey codeAuthPub = { 0 };
            BigIntToBigVal(&codeAuthPub.x, &codeAuthKeyData[sizeof(BCRYPT_ECCKEY_BLOB)], keyHdr->cbKey);
            BigIntToBigVal(&codeAuthPub.y, &codeAuthKeyData[sizeof(BCRYPT_ECCKEY_BLOB) + keyHdr->cbKey], keyHdr->cbKey);
            if ((retVal = RiotCrypt_Verify((PBYTE)&AgentHdr->sign, sizeof(AgentHdr->sign), &riotSig, &codeAuthPub)) != RIOT_SUCCESS)
            {
                printf("%s: RiotCrypt_Verify failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
*/
        }
        else
        {
            // Unsigned Image
            memset(&AgentHdr->signature, 0x00, sizeof(AgentHdr->signature));
        }

        // Write the image to a DFU
        if ((retVal = SetImageElement(hHexFile, 0, FALSE, dfuImageElement)) != STDFUFILES_NOERROR)
        {
            printf("%s: SetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        if ((retVal = SetImageName(hHexFile, (PSTR)hexFileName.c_str())) != STDFUFILES_NOERROR)
        {
            printf("%s: SetImageName failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        hexFileName.append(".DFU");
        if ((retVal = CreateNewDFUFile((PSTR)hexFileName.c_str(), &hDfuFile, diceDeviceVid, diceDevicePid, diceDeviceVer)) != STDFUFILES_NOERROR)
        {
            printf("%s: CreateNewDFUFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        if ((retVal = AppendImageToDFUFile(hDfuFile, hHexFile)) != STDFUFILES_NOERROR)
        {
            printf("%s: AppendImageToDFUFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        printf("DFU file %s successfully created.\n", hexFileName.c_str());
    }
    catch (const std::exception& e)
    {
        UNREFERENCED_PARAMETER(e);
        pendingException = std::current_exception();
    }

    // Cleanup
    if ((hDfuFile != INVALID_HANDLE_VALUE) && ((retVal = CloseDFUFile(hDfuFile)) != STDFUFILES_NOERROR))
    {
        printf("%s: CloseDFUFile failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
        throw retVal;
    }
    hDfuFile = INVALID_HANDLE_VALUE;

    if ((hHexFile != INVALID_HANDLE_VALUE) && ((retVal = DestroyImage(&hHexFile)) != STDFUFILES_NOERROR))
    {
        printf("%s: DestroyImage failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
        throw retVal;
    }
    hHexFile = INVALID_HANDLE_VALUE;

    if ((codeAuth) && (pfCallerFreeProvOrCryptKey))
    {
        if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
        {
            NCryptFreeObject(codeAuth);
        }
        else
        {
            CryptReleaseContext(codeAuth, 0);
        }
        codeAuth = NULL;
    }

    if (hSha256)
    {
        BCryptCloseAlgorithmProvider(hSha256, 0);
        hSha256 = NULL;
    }

    if (pendingException != NULL)
    {
        std::rethrow_exception(pendingException);
    }
}

bool RunSignAgent(std::unordered_map<std::wstring, std::wstring> param)
{
    bool result = true;
    std::unordered_map<std::wstring, std::wstring>::iterator it;
    std::wstring hexName(param.find(L"00")->second);
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT hCert = NULL;
    UINT32 timeStamp = -1;

    try
    {
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
            if ((hStore = CertOpenSystemStore(NULL, TEXT("MY"))) == NULL)
            {
                printf("%s: CertOpenSystemStore failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw GetLastError();
            }
            if ((hCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &findTP, NULL)) == NULL)
            {
                printf("%s: CertFindCertificateInStore failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw GetLastError();
            }
        }
        SignAgent(hexName, hCert);
    }
    catch (const std::exception& e)
    {
        UNREFERENCED_PARAMETER(e);
        result = false;
    }
    return result;
}

bool RunIssueDeviceTrust(std::unordered_map<std::wstring, std::wstring> param)
{
    bool result = true;
    try
    {

    }
    catch (const std::exception& e)
    {
        UNREFERENCED_PARAMETER(e);
        result = false;
    }
    return result;
}

void PrintHelp(void)
{
    wprintf(L"SIGN [hexFileName] [-ct=CodeAuthCertTP | -cf=CodeAuthCertFile]\n");
    wprintf(L"ISSUE [dfuFileName] [-at=DevAuthCertTP | -af=DevAuthCertFile] { -ct=CodeAuthCertTP | -cf=CodeAuthCertFile }\n");
}

int wmain(int argc, const wchar_t** argv)
{
    bool result = true;
    std::unordered_map<std::wstring, std::wstring> param;
    std::wstring cmd(argv[1]);
    WSTR_TO_LOWER(cmd);

    if (!(result = LoadDfuSe()))
    {
        wprintf(TEXT("STDFUFiles.dll was not found.\n"));
        goto Cleanup;
    }

    for (int n = 2; n < argc; n++)
    {
        std::wstring element(argv[n]);
        size_t divider = element.find('=', 0);
        std::pair<std::wstring, std::wstring> newPair;
        if ((element[0] != '-') && (divider == std::string::npos))
        {
            std::wstring pos(L"  ");
            wsprintf((LPWSTR)pos.c_str(), L"%02d", param.size());
            newPair = std::pair<std::wstring, std::wstring>(pos, element);
        }
        else
        {
            std::wstring tag(element.substr(0, divider));
            WSTR_TO_LOWER(tag);
            newPair = std::pair<std::wstring, std::wstring>(tag, element.substr(divider + 1));
        }
        param.insert(newPair);
    }

    if ((cmd == std::wstring(L"sign")) && (param.size() >= 1))
    {
        if (!(result = RunSignAgent(param)))
        {
            wprintf(TEXT("RunAppSign failed.\n"));
        }
    }
    else if ((cmd == std::wstring(L"issue")) && (param.size() >= 2))
    {
        if (!(result = RunIssueDeviceTrust(param)))
        {
            wprintf(TEXT("RunAppSign failed.\n"));
        }
    }
    else
    {
        PrintHelp();
    }

Cleanup:
    UnloadDfuSe();
    return result ? 0 : -1;
}

