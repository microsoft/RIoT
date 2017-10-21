/*
 * Barnacle.h
 *
 *  Created on: Oct 18, 2017
 *      Author: stefanth
 */

#ifndef BARNACLE_H_
#define BARNACLE_H_

#include "RIoT.h"
#include "RiotCrypt.h"
#include "RiotDerEnc.h"
#include "RiotX509Bldr.h"

#define BARNACLEMAGIC               (0x6d6f6854)
#define BARNACLEVERSION             (0x00010000)
#define BARNACLETIMESTAMP           (0x59e7bd55)
#define AGENTHDRSIZE                (0x200)
#define RAMWIPESTART1               (0x20000000)
#define RAMWIPESIZE1                (96 * 0x400)
#define RAMWIPESTART2               (0x10000000 - sizeof(BARNACLE_CERTSTORE) - sizeof(BARNACLE_IDENTITY_PRIVATE))
#define RAMWIPESIZE2                ((32 * 0x400) -  - sizeof(BARNACLE_CERTSTORE) - sizeof(BARNACLE_IDENTITY_PRIVATE))

typedef union
{
    struct
    {
        struct
        {
            struct
            {
                uint32_t magic;
                uint32_t version;
            } hdr;
            struct
            {
                uint32_t offset;
                uint32_t size;
                uint32_t version;
                uint32_t issued;
                char name[16];
                uint8_t digest[SHA256_DIGEST_LENGTH];
            } agent;
        } sign;
        struct
        {
            uint8_t r[SHA256_DIGEST_LENGTH];
            uint8_t s[SHA256_DIGEST_LENGTH];
        } signature;
    } s;
    uint32_t raw32[AGENTHDRSIZE / sizeof(uint32_t)];
    uint8_t raw8[AGENTHDRSIZE];
} BARNACLE_AGENT_HDR, *PBARNACLE_AGENT_HDR;

typedef struct
{
    uint16_t start;
    uint16_t size;
} BARNACLE_CERT_INDEX, *PBARNACLE_CERT_INDEX;

typedef struct
{
    uint32_t magic;
    RIOT_ECC_PUBLIC codeAuthPubKey;
    BARNACLE_CERT_INDEX certTable[7];
    uint8_t certBag[0x1000 - (sizeof(uint32_t) + sizeof(RIOT_ECC_PUBLIC) + sizeof(BARNACLE_CERT_INDEX) * 7)];
} BARNACLE_ISSUED_PUBLIC, *PBARNACLE_ISSUED_PUBLIC;

typedef struct
{
    uint32_t magic;
    BARNACLE_CERT_INDEX certTable[7];
    uint8_t certBag[0x1000 - (sizeof(uint32_t) + sizeof(BARNACLE_CERT_INDEX) * 7)];
} BARNACLE_CERTSTORE, *PBARNACLE_CERTSTORE;

typedef struct
{
    uint32_t magic;
    RIOT_ECC_PUBLIC pubKey;
    RIOT_ECC_PRIVATE privKey;
    uint8_t unused[0x800 - sizeof(uint32_t) - sizeof(RIOT_ECC_PUBLIC) - sizeof(RIOT_ECC_PRIVATE)];
} BARNACLE_IDENTITY_PRIVATE, *PBARNACLE_IDENTITY_PRIVATE;

typedef struct
{
    uint8_t agentDigest[SHA256_DIGEST_LENGTH];
    RIOT_ECC_PUBLIC compoundPubKey;
    RIOT_ECC_PRIVATE compoundPrivKey;
    BARNACLE_CERT_INDEX certTable[3];
    uint8_t certBag[0x800 - SHA256_DIGEST_LENGTH - sizeof(RIOT_ECC_PUBLIC) - sizeof(RIOT_ECC_PRIVATE) - sizeof(BARNACLE_CERT_INDEX) * 3 ];
} BARNACLE_CACHED_DATA, *PBARNACLE_CACHED_DATA;

extern BARNACLE_IDENTITY_PRIVATE CompoundId;
extern BARNACLE_CERTSTORE CertStore;
extern const BARNACLE_AGENT_HDR AgentHdr;
extern const BARNACLE_ISSUED_PUBLIC IssuedCerts;
extern const BARNACLE_IDENTITY_PRIVATE FwDeviceId;
extern const BARNACLE_CACHED_DATA FwCache;

bool BarnacleInitialProvision();
void BarnacleDumpCertBag();
bool BarnacleVerifyAgent();

#endif /* BARNACLE_H_ */
