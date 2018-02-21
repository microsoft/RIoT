#include "stdafx.h"
//SignAgent
void SignAgent(
    std::wstring fileName,
    PCCERT_CONTEXT appAuthCert,
    INT32 buildNo
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
    UINT32 agentSize = 0;

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
        agentSize = GetImageSize(hHexFile);
        std::vector<BYTE> image((((agentSize + 0x7ff) / 0x800) * 0x800), 0x00);
        printf("IN-Size: %d (allocated 0x%08x)\n", agentSize, image.size());
        dfuImageElement.Data = image.data();
        if ((retVal = GetImageElement(hHexFile, 0, &dfuImageElement)) != STDFUFILES_NOERROR)
        {
            printf("%s: GetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        printf("IN-Rank[0]: 0x%08x-0x%08x (%d)\n", dfuImageElement.dwAddress, dfuImageElement.dwAddress + dfuImageElement.dwDataLength, dfuImageElement.dwDataLength);
        for (DWORD rank = 1; ; rank++)
        {
            DFUIMAGEELEMENT iterator = { 0 };
            if ((retVal = GetImageElement(hHexFile, rank, &iterator)) != STDFUFILES_NOERROR)
            {
                break;
            }
            printf("IN-Rank[%d]: 0x%08x-0x%08x (%d)\n", rank, iterator.dwAddress, iterator.dwAddress + iterator.dwDataLength, iterator.dwDataLength);
            std::vector<BYTE> fragment(iterator.dwDataLength, 0x00);
            iterator.Data = fragment.data();
            if ((retVal = GetImageElement(hHexFile, rank, &iterator)) != STDFUFILES_NOERROR)
            {
                printf("%s: GetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            memcpy(&image[iterator.dwAddress - dfuImageElement.dwAddress], fragment.data(), fragment.size());
        }
        dfuImageElement.dwDataLength = image.size();

        // Add the information about this image to the header
        PBARNACLE_AGENT_HDR AgentHdr;
        AgentHdr = (PBARNACLE_AGENT_HDR)image.data();
        if ((AgentHdr->s.sign.hdr.magic != BARNACLEMAGIC) ||
            (AgentHdr->s.sign.hdr.size != sizeof(BARNACLE_AGENT_HDR)) ||
            (AgentHdr->s.sign.hdr.version != BARNACLEVERSION))
        {
            printf("%s: Bad agent image (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw ERROR_INVALID_DATA;
        }

        AgentHdr->s.sign.agent.size = agentSize - AgentHdr->s.sign.hdr.size;
        AgentHdr->s.sign.agent.issued = GetTimeStamp();
        if (buildNo > 0)
        {
            AgentHdr->s.sign.agent.version = (AgentHdr->s.sign.agent.version & 0xffff0000) | (UINT16)buildNo;
        }
        hexFileName.resize(hexFileName.size() - 4);
        strncpy_s(AgentHdr->s.sign.agent.name, hexFileName.c_str(), sizeof(AgentHdr->s.sign.agent.name));
        if ((retVal = BCryptHash(hSha256,
            NULL,
            0,
            (PBYTE)&image[AgentHdr->s.sign.hdr.size],
            AgentHdr->s.sign.agent.size,
            AgentHdr->s.sign.agent.digest,
            sizeof(AgentHdr->s.sign.agent.digest))) != 0)
        {
            printf("%s: BCryptHash failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }

        // Report binary info
        printf("Agent:   %s\n", AgentHdr->s.sign.agent.name);
        printf("Size:    %d bytes\n", AgentHdr->s.sign.agent.size);
        printf("Version: %d.%d\n", AgentHdr->s.sign.agent.version >> 16, AgentHdr->s.sign.agent.version & 0x0000ffff);
        printf("Issued:  0x%08x\n", AgentHdr->s.sign.agent.issued);
        printf("Digest:  ");
        for (uint32_t n = 0; n < sizeof(AgentHdr->s.sign.agent.digest); n++) printf("%02x", AgentHdr->s.sign.agent.digest[n]);
        printf("\n");

        // Sign the header
        if (codeAuth != NULL)
        {
            std::vector<BYTE> hdrDigest(BARNACLEDIGESTLEN, 0);
            if ((retVal = BCryptHash(hSha256,
                NULL,
                0,
                (PBYTE)&AgentHdr->s.sign,
                sizeof(AgentHdr->s.sign),
                hdrDigest.data(),
                hdrDigest.size())) != 0)
            {
                printf("%s: BCryptHash failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            std::vector<BYTE> sig(32 * 2, 0);
            DWORD result;
            if ((retVal = NCryptSignHash(codeAuth,
                NULL,
                hdrDigest.data(),
                hdrDigest.size(),
                sig.data(),
                sig.size(),
                &result,
                0)) != 0)
            {
                printf("%s: NCryptSignHash failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            memcpy(AgentHdr->s.signature.r, &sig[0], sizeof(AgentHdr->s.signature.r));
            memcpy(AgentHdr->s.signature.s, &sig[sizeof(AgentHdr->s.signature.r)], sizeof(AgentHdr->s.signature.s));

            // Check the header signature
            ecc_signature riotSig = { 0 };
            BigIntToBigVal(&riotSig.r, AgentHdr->s.signature.r, sizeof(AgentHdr->s.signature.r));
            BigIntToBigVal(&riotSig.s, AgentHdr->s.signature.s, sizeof(AgentHdr->s.signature.s));
            if ((retVal = NCryptExportKey(codeAuth,
                NULL,
                BCRYPT_ECCPUBLIC_BLOB,
                NULL,
                NULL,
                0,
                &result,
                0)) != 0)
            {
                printf("%s: NCryptExportKey failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            std::vector<BYTE> codeAuthKeyData(result, 0);
            if ((retVal = NCryptExportKey(codeAuth,
                NULL,
                BCRYPT_ECCPUBLIC_BLOB,
                NULL,
                codeAuthKeyData.data(),
                codeAuthKeyData.size(),
                &result,
                0)) != 0)
            {
                printf("%s: NCryptExportKey failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }
            BCRYPT_ECCKEY_BLOB* keyHdr = (BCRYPT_ECCKEY_BLOB*)codeAuthKeyData.data();
            RIOT_ECC_PUBLIC codeAuthPub = { 0 };
            BigIntToBigVal(&codeAuthPub.x, &codeAuthKeyData[sizeof(BCRYPT_ECCKEY_BLOB)], keyHdr->cbKey);
            BigIntToBigVal(&codeAuthPub.y, &codeAuthKeyData[sizeof(BCRYPT_ECCKEY_BLOB) + keyHdr->cbKey], keyHdr->cbKey);
            if ((retVal = RIOT_DSAVerify((PBYTE)&AgentHdr->s.sign, sizeof(AgentHdr->s.sign), &riotSig, &codeAuthPub)) != RIOT_SUCCESS)
            {
                printf("%s: RiotCrypt_Verify failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
                throw retVal;
            }

            if ((retVal = BuildTCPSAliasIdentity( &codeAuthPub, hdrDigest.data(), hdrDigest.size(), NULL, 0, (uint32_t*)&result)) != RIOT_BAD_FORMAT)
            {
                throw retVal;
            }
            std::vector<BYTE> tcpsId(result, 0x00);
            if ((retVal = BuildTCPSAliasIdentity( &codeAuthPub, hdrDigest.data(), hdrDigest.size(), tcpsId.data(), tcpsId.size(), (uint32_t*)&result)) != RIOT_SUCCESS)
            {
                throw retVal;
            }

            // Log the CBOR
            WriteToFile(L"ApplicationDataSheet.CBOR", tcpsId, OPEN_ALWAYS);

        }
        else
        {
            // Unsigned Image
            memset(&AgentHdr->s.signature, 0x00, sizeof(AgentHdr->s.signature));
        }

        hHexFile = NULL;
        if ((retVal = CreateImage(&hHexFile, 0)) != STDFUFILES_NOERROR)
        {
            printf("%s: CreateImage failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        if ((retVal = SetImageName(hHexFile, (PSTR)hexFileName.c_str())) != STDFUFILES_NOERROR)
        {
            printf("%s: SetImageName failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        if ((retVal = SetImageElement(hHexFile, 0, TRUE, dfuImageElement)) != STDFUFILES_NOERROR)
        {
            printf("%s: SetImageElement failed (%s@%u).\n", __FUNCTION__, __FILE__, __LINE__);
            throw retVal;
        }
        printf("OUT-Rank[0](%s): 0x%08x-0x%08x (%d)\n", hexFileName.c_str(), dfuImageElement.dwAddress, dfuImageElement.dwAddress + dfuImageElement.dwDataLength, dfuImageElement.dwDataLength);

        std::string verStr(16, '\0');
        verStr.resize(sprintf_s((char*)verStr.c_str(), verStr.size(), "-%d.%d", AgentHdr->s.sign.agent.version >> 16, AgentHdr->s.sign.agent.version & 0x0000ffff));
        hexFileName += verStr;
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
    INT32 buildNo = -1;

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
        if ((it = param.find(L"-bn")) != param.end())
        {
            try
            {
                buildNo = std::stoul(ReadStrFromFile(it->second));
            }
            catch (const std::exception& e)
            {
                UNREFERENCED_PARAMETER(e);
                buildNo = 0;
            }
            WriteToFile(it->second, ++buildNo);
        }
        SignAgent(hexName, hCert, buildNo);
    }
    catch (const std::exception& e)
    {
        UNREFERENCED_PARAMETER(e);
        result = false;
    }
    return result;
}
