// BarT.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

void PrintHelp(void)
{
    wprintf(L"SIGN [hexFileName] [-ct=CodeAuthCertTP | -cf=CodeAuthCertFile] { -bn=BuildNo.h } \n");
    wprintf(L"ISSUE [dfuFileName] [-at=DevAuthCertTP | -af=DevAuthCertFile] { -ct=CodeAuthCertTP | -cf=CodeAuthCertFile }\n");
}

int wmain(int argc, const wchar_t** argv)
{
    bool result = true;
    std::unordered_map<std::wstring, std::wstring> param;
    std::wstring cmd;

    if (!(result = LoadDfuSe()))
    {
        wprintf(TEXT("STDFUFiles.dll was not found.\n"));
        goto Cleanup;
    }

    if(argc < 2)
    {
        PrintHelp();
        goto Cleanup;
    }

    cmd = std::wstring(argv[1]);
    WSTR_TO_LOWER(cmd);


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

