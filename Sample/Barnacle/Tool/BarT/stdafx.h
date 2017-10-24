// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include "Windows.h"
#include <Wincrypt.h>
#include <BCrypt.h>
#include <NCrypt.h>
#include "DfuSe.h"
#include "RIoT.h"
#include "BarnacleTA.h"

#define WSTR_TO_LOWER(__str) for (UINT32 n = 0; n < __str.size(); n++) __str[n] = tolower(__str[n]);
#define WSTR_TO_UPPER(__str) for (UINT32 n = 0; n < __str.size(); n++) __str[n] = toupper(__str[n]);

#define diceDeviceVid 0x0483
#define diceDevicePid 0xDF11
#define diceDeviceVer 0x0200

std::vector<BYTE> ReadHex(std::wstring strIn);
uint32_t GetTimeStamp(void);
FILETIME ConvertWinTimeStamp(UINT32 timeStamp);
PCCERT_CONTEXT CertFromFile(std::wstring fileName);
std::vector<BYTE> CertThumbPrint(PCCERT_CONTEXT hCert);
std::vector<BYTE> ReadHex(std::wstring strIn);
std::vector<BYTE> ReadFromFile(std::wstring fileName);
void WriteToFile(std::wstring fileName, std::vector<BYTE> data);

// TODO: reference additional headers your program requires here
