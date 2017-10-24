#pragma once

extern "C"
{
#define STDFUFILES_ERROR_OFFSET             (0x12340000+0x6000)
#define STDFUFILES_NOERROR                  (0x12340000+0x0000)
#define STDFUFILES_BADSUFFIX                (STDFUFILES_ERROR_OFFSET+0x0002)
#define STDFUFILES_UNABLETOOPENFILE         (STDFUFILES_ERROR_OFFSET+0x0003)
#define STDFUFILES_UNABLETOOPENTEMPFILE     (STDFUFILES_ERROR_OFFSET+0x0004)
#define STDFUFILES_BADFORMAT                (STDFUFILES_ERROR_OFFSET+0x0005)
#define STDFUFILES_BADADDRESSRANGE          (STDFUFILES_ERROR_OFFSET+0x0006)
#define STDFUFILES_BADPARAMETER             (STDFUFILES_ERROR_OFFSET+0x0008)
#define STDFUFILES_UNEXPECTEDERROR          (STDFUFILES_ERROR_OFFSET+0x000A)	
#define STDFUFILES_FILEGENERALERROR         (STDFUFILES_ERROR_OFFSET+0x000D)	

typedef struct {
    DWORD dwStartAddress;
    DWORD dwAliasedAddress;
    DWORD dwSectorIndex;
    DWORD dwSectorSize;
    BYTE bSectorType;
    BOOL UseForOperation;
} MAPPINGSECTOR, *PMAPPINGSECTOR;

typedef struct {
    BYTE nAlternate;
    char Name[MAX_PATH];
    DWORD NbSectors;
    PMAPPINGSECTOR pSectors;
} MAPPING, *PMAPPING;

typedef struct {
    DWORD dwAddress;
    DWORD dwDataLength;
    PBYTE Data;
} DFUIMAGEELEMENT, *PDFUIMAGEELEMENT;

typedef DWORD(PASCAL *STDFUFILES_OpenExistingDFUFile)(PSTR pPathFile, PHANDLE phFile, PWORD pVid, PWORD pPid, PWORD pBcd, PBYTE pNbImages);
typedef DWORD(PASCAL *STDFUFILES_CreateNewDFUFile)(PSTR pPathFile, PHANDLE phFile, WORD Vid, WORD Pid, WORD Bcd);
typedef DWORD(PASCAL *STDFUFILES_CloseDFUFile)(HANDLE hFile);
typedef DWORD(PASCAL *STDFUFILES_AppendImageToDFUFile)(HANDLE hFile, HANDLE Image);
typedef DWORD(PASCAL *STDFUFILES_ReadImageFromDFUFile)(HANDLE hFile, int Rank, PHANDLE pImage);
typedef DWORD(PASCAL *STDFUFILES_ImageFromFile)(PSTR pPathFile, PHANDLE pImage, BYTE nAlternate);
typedef DWORD(PASCAL *STDFUFILES_ImageToFile)(PSTR pPathFile, HANDLE Image);
typedef DWORD(PASCAL *STDFUFILES_CreateImage)(PHANDLE pHandle, BYTE nAlternate);
typedef DWORD(PASCAL *STDFUFILES_CreateImageFromMapping)(PHANDLE pHandle, PMAPPING pMapping);
typedef DWORD(PASCAL *STDFUFILES_DuplicateImage)(HANDLE hSource, PHANDLE pDest);
typedef DWORD(PASCAL *STDFUFILES_FilterImageForOperation)(HANDLE Handle, PMAPPING pMapping, DWORD Operation, BOOL bTruncateLeadFFForUpgrade);
typedef DWORD(PASCAL *STDFUFILES_DestroyImageElement)(HANDLE Handle, DWORD dwRank);
typedef DWORD(PASCAL *STDFUFILES_DestroyImage)(PHANDLE pHandle);
typedef DWORD(PASCAL *STDFUFILES_GetImageAlternate)(HANDLE Handle, PBYTE pAlternate);
typedef DWORD(PASCAL *STDFUFILES_GetImageNbElement)(HANDLE Handle, PDWORD pNbElements);
typedef DWORD(PASCAL *STDFUFILES_GetImageName)(HANDLE Handle, PSTR Name);
typedef DWORD(PASCAL *STDFUFILES_SetImageName)(HANDLE Handle, PSTR Name);
typedef DWORD(PASCAL *STDFUFILES_SetImageElement)(HANDLE Handle, DWORD dwRank, BOOL bInsert, DFUIMAGEELEMENT Element);
typedef DWORD(PASCAL *STDFUFILES_GetImageElement)(HANDLE Handle, DWORD dwRank, PDFUIMAGEELEMENT pElement);
typedef DWORD(PASCAL *STDFUFILES_GetImageSize)(HANDLE Image);

bool LoadDfuSe();
bool UnloadDfuSe();
DWORD OpenExistingDFUFile(PSTR pPathFile, PHANDLE phFile, PWORD pVid, PWORD pPid, PWORD pBcd, PBYTE pNbImages);
DWORD CreateNewDFUFile(PSTR pPathFile, PHANDLE phFile, WORD Vid, WORD Pid, WORD Bcd);
DWORD CloseDFUFile(HANDLE hFile);
DWORD AppendImageToDFUFile (HANDLE hFile, HANDLE Image);
DWORD ReadImageFromDFUFile(HANDLE hFile, int Rank, PHANDLE pImage);
DWORD ImageFromFile(PSTR pPathFile, PHANDLE pImage, BYTE nAlternate);
DWORD ImageToFile(PSTR pPathFile, HANDLE Image);
DWORD CreateImage(PHANDLE pHandle, BYTE nAlternate);
DWORD CreateImageFromMapping(PHANDLE pHandle, PMAPPING pMapping);
DWORD DuplicateImage(HANDLE hSource, PHANDLE pDest);
DWORD FilterImageForOperation(HANDLE Handle, PMAPPING pMapping, DWORD Operation, BOOL bTruncateLeadFFForUpgrade);
DWORD DestroyImageElement(HANDLE Handle, DWORD dwRank);
DWORD DestroyImage(PHANDLE pHandle);
DWORD GetImageAlternate(HANDLE Handle, PBYTE pAlternate);
DWORD GetImageNbElement(HANDLE Handle, PDWORD pNbElements);
DWORD GetImageName(HANDLE Handle, PSTR Name);
DWORD SetImageName(HANDLE Handle, PSTR Name);
DWORD SetImageElement(HANDLE Handle, DWORD dwRank, BOOL bInsert, DFUIMAGEELEMENT Element);
DWORD GetImageElement(HANDLE Handle, DWORD dwRank, PDFUIMAGEELEMENT pElement);
DWORD GetImageSize(HANDLE Image);
}
