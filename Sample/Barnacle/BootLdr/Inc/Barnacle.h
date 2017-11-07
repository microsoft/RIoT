/*
 * Barnacle.h
 *
 *  Created on: Oct 18, 2017
 *      Author: stefanth
 */

#ifndef BARNACLE_H_
#define BARNACLE_H_

#define RAMWIPESTART1               (0x20000000)
#define RAMWIPESIZE1                (96 * 0x400)
#define RAMWIPESTART2               (0x10000000 - sizeof(BARNACLE_CERTSTORE) - sizeof(BARNACLE_IDENTITY_PRIVATE))
#define RAMWIPESIZE2                ((32 * 0x400) -  - sizeof(BARNACLE_CERTSTORE) - sizeof(BARNACLE_IDENTITY_PRIVATE))

#define BARNACLE_ISSUEDFLAG_PROVISIONIED       (0x00000001)
#define BARNACLE_ISSUEDFLAG_AUTHENTICATED_BOOT (0x00000002)
#define BARNACLE_ISSUEDFLAG_WRITELOCK          (0x00000004)

#define BARNACLE_ISSUED_ROOT   (1)
#define BARNACLE_ISSUED_DEVICE (2)

typedef struct
{
    uint32_t magic;
    uint32_t flags;
    RIOT_ECC_PUBLIC codeAuthPubKey;
    BARNACLE_CERT_INDEX certTable[2];
    uint32_t cursor;
} BARNACLE_ISSUED_PUBLIC_INFO, *PBARNACLE_ISSUED_PUBLIC_INFO;
typedef struct
{
	BARNACLE_ISSUED_PUBLIC_INFO info;
    uint8_t certBag[0x1000 - sizeof(BARNACLE_ISSUED_PUBLIC_INFO)];
} BARNACLE_ISSUED_PUBLIC, *PBARNACLE_ISSUED_PUBLIC;

typedef struct
{
    uint8_t agentHdrDigest[SHA256_DIGEST_LENGTH];
    uint32_t lastIssued;
    uint32_t lastVersion;
    RIOT_ECC_PUBLIC compoundPubKey;
    RIOT_ECC_PRIVATE compoundPrivKey;
    uint32_t compoundCertSize;
} BARNACLE_CACHED_DATA_INFO, *PBARNACLE_CACHED_DATA_INFO;

typedef struct
{
	BARNACLE_CACHED_DATA_INFO info;
	uint8_t cert[0x800 - sizeof(BARNACLE_CACHED_DATA_INFO)];
} BARNACLE_CACHED_DATA, *PBARNACLE_CACHED_DATA;

extern const BARNACLE_ISSUED_PUBLIC IssuedCerts;
extern const BARNACLE_IDENTITY_PRIVATE FwDeviceId;
extern const BARNACLE_CACHED_DATA FwCache;

char* BarnacleGetDfuStr(void);
bool BarnacleInitialProvision();
void BarnacleDumpCertBag();
bool BarnacleVerifyAgent();

#endif /* BARNACLE_H_ */
