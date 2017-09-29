// GenP7B.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

std::vector<BYTE> ReadFromFile(
    std::wstring fileName
)
{
    // http://stackoverflow.com/questions/14841396/stdunique-ptr-deleters-and-the-win32-api
    std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hFile(::CreateFile(fileName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL), &::CloseHandle);
    DWORD bytesRead = 0;
    LARGE_INTEGER fileSize;
    if (hFile.get() == INVALID_HANDLE_VALUE)
    {
        wprintf(L"ERROR: CreateFile failed with 0x%08x.\n", GetLastError());
        throw GetLastError();
    }
    if (!GetFileSizeEx(hFile.get(), &fileSize))
    {
        wprintf(L"ERROR: GetFileSizeEx failed with 0x%08x.\n", GetLastError());
        throw GetLastError();
    }
    wprintf(L"  Size: %llu\n", fileSize.QuadPart);
    std::vector<BYTE> data((int)fileSize.QuadPart);

    if (!ReadFile(hFile.get(), data.data(), (DWORD)data.size(), &bytesRead, NULL))
    {
        wprintf(L"ERROR: ReadFile failed with 0x%08x.\n", GetLastError());
        throw GetLastError();
    }
    return data;
}

PCCERT_CONTEXT CertFromString(std::wstring rawCert)
{
    uint32_t retVal = 0;
    DWORD result;
    std::vector<BYTE> derCert;
    if (CryptStringToBinaryW(rawCert.c_str(), (DWORD)rawCert.length(), CRYPT_STRING_BASE64HEADER, NULL, &result, NULL, NULL))
    {
        derCert.resize(result);
        if (!CryptStringToBinaryW(rawCert.c_str(), (DWORD)rawCert.length(), CRYPT_STRING_BASE64HEADER, derCert.data(), &result, NULL, NULL))
        {
            wprintf(L"ERROR: CryptStringToBinaryW failed with 0x%08x.\n", GetLastError());
            throw GetLastError();
        }
    }
    PCCERT_CONTEXT hCert = NULL;
    if ((hCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derCert.data(), (DWORD)derCert.size())) == NULL)
    {
        wprintf(L"ERROR: CertCreateCertificateContext failed with 0x%08x.\n", GetLastError());
        throw GetLastError();
    }
    return hCert;
}

std::vector<BYTE> CertThumbPrint(PCCERT_CONTEXT hCert)
{
    uint32_t retVal = 0;
    BCRYPT_ALG_HANDLE hSha1 = NULL;
    if ((retVal = BCryptOpenAlgorithmProvider(&hSha1, BCRYPT_SHA1_ALGORITHM, NULL, 0)) != 0)
    {
        wprintf(L"ERROR: BCryptOpenAlgorithmProvider failed with 0x%08x.\n", retVal);
        throw retVal;
    }
    std::vector<BYTE> digest(20, 0);
    if ((retVal = BCryptHash(hSha1, NULL, 0, hCert->pbCertEncoded, hCert->cbCertEncoded, digest.data(), (ULONG)digest.size())) != 0)
    {
        wprintf(L"ERROR: BCryptHash failed with 0x%08x.\n", retVal);
        throw retVal;
    }
    BCryptCloseAlgorithmProvider(hSha1, 0);
    return digest;
}

int wmain(int argc, const wchar_t** argv)
{
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT hCert = NULL;
    int certCtr = 0;

    wprintf(L"Usage: GenP7B [store.p7b] [cert.pem] ...\n");
    wprintf(L"Generate a P7B store from PEM formatted certificates.\n");

    if (argc < 3)
    {
        wprintf(L"ERROR: Bad parameters.\n");
        return 1;
    }

    // Generate the store names
    std::wstring p7bName = std::wstring(argv[1]);
    std::wstring p7cName;
    if (p7bName.substr(p7bName.size() - 4, 4) == std::wstring(L".p7b"))
    {
        p7cName = p7bName.substr(0, p7bName.size() - 1) + std::wstring(L"c");
    }
    else
    {
        p7cName = p7bName + std::wstring(L".p7c");
        p7bName += std::wstring(L".p7b");
    }

    // Wipe the store
    DeleteFileW(p7bName.c_str());
    DeleteFileW(p7cName.c_str());

    // Create the store (Wimdows only allows the extension .p7c)
    if ((hStore = CertOpenStore(CERT_STORE_PROV_FILENAME_W,
                                PKCS_7_ASN_ENCODING,
                                NULL,
                                CERT_STORE_CREATE_NEW_FLAG |
                                CERT_FILE_STORE_COMMIT_ENABLE_FLAG,
                                p7cName.c_str())) == NULL)
    {
        wprintf(L"ERROR: CertOpenStore failed with 0x%08x.\n", GetLastError());
        throw GetLastError();
    }

    // Iterate through the provided list of PEM files 
    for (int n = 2; n < argc; n++)
    {
        // Iterate through wildcards in a provided name
        std::wstring pemName = std::wstring(argv[n]);
        WIN32_FIND_DATAW findData = {0};
        std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::FindClose)> hSearch(::FindFirstFileW(pemName.c_str(), &findData), &::FindClose);

        while(hSearch.get() != INVALID_HANDLE_VALUE)
        {
            std::wstring pemFile = std::wstring(findData.cFileName);
            wprintf(L"Processing: %s\n", pemFile.c_str());

            std::vector<BYTE> pemCertsMb = ReadFromFile(pemFile);
            std::wstring pemCerts(pemCertsMb.size(), '\0');
            pemCerts.resize(MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)pemCertsMb.data(), (int)pemCertsMb.size(), (LPWSTR)pemCerts.c_str(), (int)pemCerts.length()) + 1);

            // Iterate trough the certs in the PEM file
            size_t cursor = 0;
            while (pemCerts.length() > 0)
            {
                // Find the next cert
                std::wstring certStartTag(L"-----BEGIN CERTIFICATE-----");
                std::wstring certEndTag(L"-----END CERTIFICATE-----");
                size_t certStart = pemCerts.find(certStartTag, cursor);
                size_t certEnd = pemCerts.find(certEndTag, cursor) + certEndTag.length();
                if ((certStart == std::wstring::npos) || (certEnd == std::wstring::npos))
                {
                    break;
                }
                std::wstring encCert = pemCerts.substr(certStart, certEnd);
                cursor = certEnd;

                // Open the cert
                hCert = CertFromString(encCert);

                // Get some info from it
                std::wstring x509Name(256, L'\0');
                x509Name.resize(CertNameToStrW(X509_ASN_ENCODING, &hCert->pCertInfo->Subject, CERT_X500_NAME_STR, (LPWSTR)x509Name.c_str(), (DWORD)x509Name.size()));
                wprintf(L"  Subject: %s\n", x509Name.c_str());
                x509Name.resize(256);
                x509Name.resize(CertNameToStrW(X509_ASN_ENCODING, &hCert->pCertInfo->Issuer, CERT_X500_NAME_STR, (LPWSTR)x509Name.c_str(), (DWORD)x509Name.size()));
                wprintf(L"  Issuer: %s\n", x509Name.c_str());
                wprintf(L"  Thunbprint: 0x");
                std::vector<BYTE> thumbPrint = CertThumbPrint(hCert);
                for (UINT n = 0; n < thumbPrint.size(); n++) wprintf(L"%02x", thumbPrint[n]);
                wprintf(L"\n");

                // Add the cert to the store
                if (!CertAddCertificateContextToStore(hStore, hCert, CERT_STORE_ADD_ALWAYS, NULL))
                {
                    wprintf(L"ERROR: CertAddCertificateContextToStore failed with 0x%08x.\n", GetLastError());
                    throw GetLastError();
                }
                certCtr++;
                CertFreeCertificateContext(hCert);
            }

            if (!FindNextFileW(hSearch.get(), &findData))
            {
                break;
            }
        }
    }
    wprintf(L"Added %u certificates in total.\n", certCtr++);

    // Rename the store to ".p7b" so Windows knows how to deal with it.
    if (hStore)
    {
        CertCloseStore(hStore, 0);
    }
    MoveFileW(p7cName.c_str(), p7bName.c_str());

    return 0;
}

