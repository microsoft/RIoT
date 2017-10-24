#include "stdafx.h"

HINSTANCE hLib = NULL;
STDFUFILES_OpenExistingDFUFile OpenExistingDFUFileFn = NULL;
STDFUFILES_CreateNewDFUFile CreateNewDFUFileFn = NULL;
STDFUFILES_CloseDFUFile CloseDFUFileFn = NULL;
STDFUFILES_AppendImageToDFUFile AppendImageToDFUFileFn = NULL;
STDFUFILES_ReadImageFromDFUFile ReadImageFromDFUFileFn = NULL;
STDFUFILES_ImageFromFile ImageFromFileFn = NULL;
STDFUFILES_ImageToFile ImageToFileFn = NULL;
STDFUFILES_CreateImage CreateImageFn = NULL;
STDFUFILES_CreateImageFromMapping CreateImageFromMappingFn = NULL;
STDFUFILES_DuplicateImage DuplicateImageFn = NULL;
STDFUFILES_FilterImageForOperation FilterImageForOperationFn = NULL;
STDFUFILES_DestroyImageElement DestroyImageElementFn = NULL;
STDFUFILES_DestroyImage DestroyImageFn = NULL;
STDFUFILES_GetImageAlternate GetImageAlternateFn = NULL;
STDFUFILES_GetImageNbElement GetImageNbElementFn = NULL;
STDFUFILES_GetImageName GetImageNameFn = NULL;
STDFUFILES_SetImageName SetImageNameFn = NULL;
STDFUFILES_SetImageElement SetImageElementFn = NULL;
STDFUFILES_GetImageElement GetImageElementFn = NULL;
STDFUFILES_GetImageSize GetImageSizeFn = NULL;

bool LoadDfuSe()
{
    hLib = LoadLibrary(TEXT("STDFUFiles.dll"));
    if (hLib != NULL)
    {
        OpenExistingDFUFileFn = (STDFUFILES_OpenExistingDFUFile)GetProcAddress(hLib, "STDFUFILES_OpenExistingDFUFile");
        CreateNewDFUFileFn = (STDFUFILES_CreateNewDFUFile)GetProcAddress(hLib, "STDFUFILES_CreateNewDFUFile");
        CloseDFUFileFn = (STDFUFILES_CloseDFUFile)GetProcAddress(hLib, "STDFUFILES_CloseDFUFile");
        AppendImageToDFUFileFn = (STDFUFILES_AppendImageToDFUFile)GetProcAddress(hLib, "STDFUFILES_AppendImageToDFUFile");
        ReadImageFromDFUFileFn = (STDFUFILES_ReadImageFromDFUFile)GetProcAddress(hLib, "STDFUFILES_ReadImageFromDFUFile");
        ImageFromFileFn = (STDFUFILES_ImageFromFile)GetProcAddress(hLib, "STDFUFILES_ImageFromFile");
        ImageToFileFn = (STDFUFILES_ImageToFile)GetProcAddress(hLib, "STDFUFILES_ImageToFile");
        CreateImageFn = (STDFUFILES_CreateImage)GetProcAddress(hLib, "STDFUFILES_CreateImage");
        CreateImageFromMappingFn = (STDFUFILES_CreateImageFromMapping)GetProcAddress(hLib, "STDFUFILES_CreateImageFromMapping");
        DuplicateImageFn = (STDFUFILES_DuplicateImage)GetProcAddress(hLib, "STDFUFILES_DuplicateImage");
        FilterImageForOperationFn = (STDFUFILES_FilterImageForOperation)GetProcAddress(hLib, "STDFUFILES_FilterImageForOperation");
        DestroyImageElementFn = (STDFUFILES_DestroyImageElement)GetProcAddress(hLib, "STDFUFILES_DestroyImageElement");
        DestroyImageFn = (STDFUFILES_DestroyImage)GetProcAddress(hLib, "STDFUFILES_DestroyImage");
        GetImageAlternateFn = (STDFUFILES_GetImageAlternate)GetProcAddress(hLib, "STDFUFILES_GetImageAlternate");
        GetImageNbElementFn = (STDFUFILES_GetImageNbElement)GetProcAddress(hLib, "STDFUFILES_GetImageNbElement");
        GetImageNameFn = (STDFUFILES_GetImageName)GetProcAddress(hLib, "STDFUFILES_GetImageName");
        SetImageNameFn = (STDFUFILES_SetImageName)GetProcAddress(hLib, "STDFUFILES_SetImageName");
        SetImageElementFn = (STDFUFILES_SetImageElement)GetProcAddress(hLib, "STDFUFILES_SetImageElement");
        GetImageElementFn = (STDFUFILES_GetImageElement)GetProcAddress(hLib, "STDFUFILES_GetImageElement");
        GetImageSizeFn = (STDFUFILES_GetImageSize)GetProcAddress(hLib, "STDFUFILES_GetImageSize");
        return true;
    }
    else
        return false;
}

bool UnloadDfuSe()
{
    if (hLib != NULL)
    {
        OpenExistingDFUFileFn = NULL;
        CreateNewDFUFileFn = NULL;
        CloseDFUFileFn = NULL;
        AppendImageToDFUFileFn = NULL;
        ReadImageFromDFUFileFn = NULL;
        ImageFromFileFn = NULL;
        ImageToFileFn = NULL;
        CreateImageFn = NULL;
        CreateImageFromMappingFn = NULL;
        DuplicateImageFn = NULL;
        FilterImageForOperationFn = NULL;
        DestroyImageElementFn = NULL;
        DestroyImageFn = NULL;
        GetImageAlternateFn = NULL;
        GetImageNbElementFn = NULL;
        GetImageNameFn = NULL;
        SetImageNameFn = NULL;
        SetImageElementFn = NULL;
        GetImageElementFn = NULL;
        GetImageSizeFn = NULL;
        return FreeLibrary(hLib);
    }
    else
        return false;
}

DWORD OpenExistingDFUFile(PSTR pPathFile, PHANDLE phFile, PWORD pVid, PWORD pPid, PWORD pBcd, PBYTE pNbImages)
{
    if (OpenExistingDFUFileFn)
        return OpenExistingDFUFileFn(pPathFile, phFile, pVid, pPid, pBcd, pNbImages);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD CreateNewDFUFile(PSTR pPathFile, PHANDLE phFile, WORD Vid, WORD Pid, WORD Bcd)
{
    if (CreateNewDFUFileFn)
        return CreateNewDFUFileFn(pPathFile, phFile, Vid, Pid, Bcd);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD CloseDFUFile(HANDLE hFile)
{
    if (CloseDFUFileFn)
        return CloseDFUFileFn(hFile);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD AppendImageToDFUFile(HANDLE hFile, HANDLE Image)
{
    if (AppendImageToDFUFileFn)
        return AppendImageToDFUFileFn(hFile, Image);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD ReadImageFromDFUFile(HANDLE hFile, int Rank, PHANDLE pImage)
{
    if (ReadImageFromDFUFileFn)
        return ReadImageFromDFUFileFn(hFile, Rank, pImage);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD ImageFromFile(PSTR pPathFile, PHANDLE pImage, BYTE nAlternate)
{
    if (ImageFromFileFn)
        return ImageFromFileFn(pPathFile, pImage, nAlternate);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD ImageToFile(PSTR pPathFile, HANDLE Image)
{
    if (ImageToFileFn)
        return ImageToFileFn(pPathFile, Image);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD CreateImage(PHANDLE pHandle, BYTE nAlternate)
{
    if (CreateImageFn)
        return CreateImageFn(pHandle, nAlternate);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD CreateImageFromMapping(PHANDLE pHandle, PMAPPING pMapping)
{
    if (CreateImageFromMappingFn)
        return CreateImageFromMappingFn(pHandle, pMapping);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD DuplicateImage(HANDLE hSource, PHANDLE pDest)
{
    if (DuplicateImageFn)
        return DuplicateImageFn(hSource, pDest);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD FilterImageForOperation(HANDLE Handle, PMAPPING pMapping, DWORD Operation, BOOL bTruncateLeadFFForUpgrade)
{
    if (FilterImageForOperationFn)
        return FilterImageForOperationFn(Handle, pMapping, Operation, bTruncateLeadFFForUpgrade);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD DestroyImageElement(HANDLE Handle, DWORD dwRank)
{
    if (DestroyImageElementFn)
        return DestroyImageElementFn(Handle, dwRank);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD DestroyImage(PHANDLE pHandle)
{
    if (DestroyImageFn)
        return DestroyImageFn(pHandle);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD GetImageAlternate(HANDLE Handle, PBYTE pAlternate)
{
    if (GetImageAlternateFn)
        return GetImageAlternateFn(Handle, pAlternate);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD GetImageNbElement(HANDLE Handle, PDWORD pNbElements)
{
    if (GetImageNbElementFn)
        return GetImageNbElementFn(Handle, pNbElements);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD GetImageName(HANDLE Handle, PSTR Name)
{
    if (GetImageNameFn)
        return GetImageNameFn(Handle, Name);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD SetImageName(HANDLE Handle, PSTR Name)
{
    if (GetImageNameFn)
        return GetImageNameFn(Handle, Name);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD SetImageElement(HANDLE Handle, DWORD dwRank, BOOL bInsert, DFUIMAGEELEMENT Element)
{
    if (SetImageElementFn)
        return SetImageElementFn(Handle, dwRank, bInsert, Element);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD GetImageElement(HANDLE Handle, DWORD dwRank, PDFUIMAGEELEMENT pElement)
{
    if (GetImageElementFn)
        return GetImageElementFn(Handle, dwRank, pElement);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}

DWORD GetImageSize(HANDLE Image)
{
    if (GetImageSizeFn)
        return GetImageSizeFn(Image);
    else
        return STDFUFILES_UNEXPECTEDERROR;
}
