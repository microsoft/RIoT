// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define SHA256_DIGEST_LENGTH (32)

#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <Windows.h>
#include <Wincrypt.h>
#include <BCrypt.h>
#include <NCrypt.h>
#include <cyrep/RiotTarget.h>
#include <cyrep/RiotStatus.h>
#include <cyrep/RiotEcc.h>
#include <cyrep/RiotCrypt.h>
#include <tcps/tcpsid.h>
#include <BarnacleTA.h>
#include <Barnacle.h>
#include "DfuSe.h"

#define WSTR_TO_LOWER(__str) for (UINT32 n = 0; n < __str.size(); n++) __str[n] = tolower(__str[n]);
#define WSTR_TO_UPPER(__str) for (UINT32 n = 0; n < __str.size(); n++) __str[n] = toupper(__str[n]);

#define diceDeviceVid 0x0483
#define diceDevicePid 0xDF11
#define diceDeviceVer 0x0200
#define szTcpsOID  "2.23.133.5.4.2"

std::vector<BYTE> ReadHex(std::wstring strIn);
uint32_t GetTimeStamp(void);
FILETIME ConvertWinTimeStamp(UINT32 timeStamp);
PCCERT_CONTEXT CertFromFile(std::wstring fileName);
std::vector<BYTE> CertThumbPrint(PCCERT_CONTEXT hCert);
std::vector<BYTE> ReadHex(std::wstring strIn);
std::vector<BYTE> ReadFromFile(std::wstring fileName);
std::string ReadStrFromFile(std::wstring fileName);
void WriteToFile(std::wstring fileName, std::vector<BYTE> data, DWORD dwCreationDisposition = CREATE_ALWAYS);
void WriteToFile(std::wstring fileName, std::string data);
void WriteToFile(std::wstring fileName, UINT32 data);
std::wstring ToHexWString(std::vector<BYTE> &byteVector);
std::string ToHexString(std::vector<BYTE> &byteVector);
std::wstring ToDevIDWString(std::vector<BYTE> &byteVector, bool uri);
std::string ToDevIDString(std::vector<BYTE> &byteVector, bool uri);

bool RunSignAgent(std::unordered_map<std::wstring, std::wstring> param);
bool RunIssueDeviceTrust(std::unordered_map<std::wstring, std::wstring> param);

// TODO: reference additional headers your program requires here
