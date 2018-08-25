#include "stdafx.h"

std::vector<BYTE> ReadHex(std::wstring strIn)
{
    std::vector<BYTE> dataOut(strIn.size() / 2);

    for (uint32_t cursor = 0; cursor < dataOut.size(); cursor++)
    {
        dataOut[cursor] = (BYTE)std::stoul(strIn.substr(cursor * 2, 2), NULL, 16);
        //if (swscanf_s(strIn.substr(cursor * 2, 2).c_str(), L"%x", &scannedDigit) != 1)
        //{
        //    throw;
        //}
        // dataOut[cursor] = (BYTE)(scannedDigit & 0x000000FF);
    }
    return dataOut;
}

uint32_t GetTimeStamp(void)
{
    FILETIME now = { 0 };
    LARGE_INTEGER convert = { 0 };

    // Get the current timestamp
    GetSystemTimeAsFileTime(&now);
    convert.LowPart = now.dwLowDateTime;
    convert.HighPart = now.dwHighDateTime;
    convert.QuadPart = (convert.QuadPart - (UINT64)(11644473600000 * 10000)) / 10000000;
    return convert.LowPart;
}

void WriteToFile(std::wstring fileName, std::vector<BYTE> data, DWORD dwCreationDisposition)
{
    // http://stackoverflow.com/questions/14841396/stdunique-ptr-deleters-and-the-win32-api
    std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hFile(::CreateFile(fileName.c_str(), GENERIC_WRITE, 0, NULL, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL, NULL), &::CloseHandle);
    SetFilePointer(hFile.get(), 0, 0, FILE_END);
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile.get(), data.data(), data.size(), &bytesWritten, NULL))
    {
        throw GetLastError();
    }
}

void WriteToFile(std::wstring fileName, std::string data)
{
    // http://stackoverflow.com/questions/14841396/stdunique-ptr-deleters-and-the-win32-api
    std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hFile(::CreateFile(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL), &::CloseHandle);
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile.get(), data.c_str(), data.size(), &bytesWritten, NULL))
    {
        throw GetLastError();
    }
}

void WriteToFile(std::wstring fileName, UINT32 data)
{
    // http://stackoverflow.com/questions/14841396/stdunique-ptr-deleters-and-the-win32-api
    std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hFile(::CreateFile(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL), &::CloseHandle);
    DWORD bytesWritten = 0;
    std::vector<byte> dataOut(16, 0);
    dataOut.resize(sprintf_s((char*)dataOut.data(), dataOut.size(), "%ul", data) - 1);
    if (!WriteFile(hFile.get(), dataOut.data(), dataOut.size(), &bytesWritten, NULL))
    {
        throw GetLastError();
    }
}

std::string ReadStrFromFile(std::wstring fileName)
{
    // http://stackoverflow.com/questions/14841396/stdunique-ptr-deleters-and-the-win32-api
    std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hFile(::CreateFile(fileName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL), &::CloseHandle);
    DWORD bytesRead = 0;
    std::string data(GetFileSize(hFile.get(), NULL), '\0');
    if (!ReadFile(hFile.get(), (LPVOID)data.c_str(), data.size(), &bytesRead, NULL))
    {
        throw GetLastError();
    }
    return data;
}

std::vector<BYTE> ReadFromFile(std::wstring fileName)
{
    // http://stackoverflow.com/questions/14841396/stdunique-ptr-deleters-and-the-win32-api
    std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hFile(::CreateFile(fileName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL), &::CloseHandle);
    DWORD bytesRead = 0;
    std::vector<BYTE> data(GetFileSize(hFile.get(), NULL));
    if (!ReadFile(hFile.get(), data.data(), data.size(), &bytesRead, NULL))
    {
        throw GetLastError();
    }
    return data;
}

FILETIME ConvertWinTimeStamp(UINT32 timeStamp)
{
    LARGE_INTEGER convert = { 0 };
    convert.QuadPart = ((LONGLONG)timeStamp * 10000000) + (LONGLONG)(11644473600000 * 10000);
    FILETIME out = { 0 };
    out.dwLowDateTime = convert.LowPart;
    out.dwHighDateTime = convert.HighPart;
    return out;
}

PCCERT_CONTEXT CertFromFile(std::wstring fileName)
{
    uint32_t retVal = 0;
    std::vector<BYTE> rawCert = ReadFromFile(fileName);
    DWORD result;
    if (CryptStringToBinaryA((LPSTR)rawCert.data(), rawCert.size(), CRYPT_STRING_BASE64HEADER, NULL, &result, NULL, NULL))
    {
        std::vector<BYTE> derCert(result, 0);
        if (!CryptStringToBinaryA((LPSTR)rawCert.data(), rawCert.size(), CRYPT_STRING_BASE64HEADER, derCert.data(), &result, NULL, NULL))
        {
            throw GetLastError();
        }
        rawCert = derCert;
    }
    PCCERT_CONTEXT hCert = NULL;
    if ((hCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, rawCert.data(), rawCert.size())) == NULL)
    {
        throw retVal;
    }
    return hCert;
}

std::vector<BYTE> CertThumbPrint(PCCERT_CONTEXT hCert)
{
    uint32_t retVal = 0;
    BCRYPT_ALG_HANDLE hSha1 = NULL;
    if ((retVal = BCryptOpenAlgorithmProvider(&hSha1, BCRYPT_SHA1_ALGORITHM, NULL, 0)) != 0)
    {
        throw retVal;
    }
    std::vector<BYTE> digest(20, 0);
    if ((retVal = BCryptHash(hSha1, NULL, 0, hCert->pbCertEncoded, hCert->cbCertEncoded, digest.data(), digest.size())) != 0)
    {
        throw retVal;
    }
    BCryptCloseAlgorithmProvider(hSha1, 0);
    return digest;
}

std::wstring ToHexWString(std::vector<BYTE> &byteVector)
{
    std::wstring stringOut((byteVector.size() + 2) * 2, '\0');
    DWORD result = stringOut.size();
    if (!CryptBinaryToStringW(byteVector.data(), byteVector.size(), CRYPT_STRING_HEXRAW, (LPWSTR)stringOut.c_str(), &result))
    {
        throw GetLastError();
    }
    stringOut.resize(stringOut.size() - 4);
    return stringOut;
}

std::string ToHexString(std::vector<BYTE> &byteVector)
{
    std::string stringOut((byteVector.size() + 2) * 2, '\0');
    DWORD result = stringOut.size();
    if (!CryptBinaryToStringA(byteVector.data(), byteVector.size(), CRYPT_STRING_HEXRAW, (LPSTR)stringOut.c_str(), &result))
    {
        throw GetLastError();
    }
    stringOut.resize(stringOut.size() - 4);
    return stringOut;
}

std::wstring ToDevIDWString(std::vector<BYTE> &byteVector, bool uri)
{
    DWORD retVal;
    DWORD result;
    std::vector<BYTE> devID(byteVector.size() / 4, 0);
    for (UINT32 n = 0; n < byteVector.size(); n++)
    {
        devID[n] = byteVector[n] ^ byteVector[byteVector.size() / 4 + n] ^ byteVector[byteVector.size() / 2 + n] ^ byteVector[byteVector.size() / 4 * 3 + n];
    }
    if (!CryptBinaryToStringW(devID.data(), devID.size(), uri ? CRYPT_STRING_BASE64URI : CRYPT_STRING_BASE64, NULL, &result))
    {
        retVal = GetLastError();
        throw retVal;
    }
    std::wstring devIDStr(result, '\0');
    if (!CryptBinaryToStringW(devID.data(), devID.size(), uri ? CRYPT_STRING_BASE64URI : CRYPT_STRING_BASE64, (LPWSTR)devIDStr.c_str(), &result))
    {
        retVal = GetLastError();
        throw retVal;
    }
    devIDStr.resize(devIDStr.size() - 2);
    devIDStr[devIDStr.size() - 1] = L'\0';
    return devIDStr;
}

std::string ToDevIDString(std::vector<BYTE> &byteVector, bool uri)
{
    DWORD retVal;
    DWORD result;
    std::vector<BYTE> devID(byteVector.size() / 4, 0);
    for (UINT32 n = 0; n < byteVector.size(); n++)
    {
        devID[n] = byteVector[n] ^ byteVector[byteVector.size() / 4 + n] ^ byteVector[byteVector.size() / 2 + n] ^ byteVector[byteVector.size() / 4 * 3 + n];
    }
    if (!CryptBinaryToStringA(devID.data(), devID.size(), uri ? CRYPT_STRING_BASE64URI : CRYPT_STRING_BASE64, NULL, &result))
    {
        retVal = GetLastError();
        throw retVal;
    }
    std::string devIDStr(result, '\0');
    if (!CryptBinaryToStringA(devID.data(), devID.size(), uri ? CRYPT_STRING_BASE64URI : CRYPT_STRING_BASE64, (LPSTR)devIDStr.c_str(), &result))
    {
        retVal = GetLastError();
        throw retVal;
    }
    devIDStr.resize(devIDStr.size() - 2);
    devIDStr[devIDStr.size() - 1] = '\0';
    return devIDStr;
}
