/*
 * Barnacle.h
 *
 *  Created on: Oct 18, 2017
 *      Author: stefanth
 */

#ifndef BARNACLETA_H_
#define BARNACLETA_H_

#define NUMELEM(a) (sizeof(a) / sizeof(*a))

#define BARNACLEMAGIC               (0x6d6f6854)
#define BARNACLEVERSION             (0x00010000)
#define BARNACLETIMESTAMP           (0x59e7bd55)
#define BARNACLEDIGESTLEN           (32)

#define BARNACLE_TCPS_ID_BUF_LENGTH ((TCPS_ID_PUBKEY_LENGTH * 2) + TCPS_ID_FWID_LENGTH + 32)


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
                uint32_t size;
            } hdr;
            struct
            {
                char name[16];
                uint32_t version;
                uint32_t size;
                uint32_t issued;
                uint8_t digest[BARNACLEDIGESTLEN];
            } agent;
        } sign;
        struct
        {
            uint8_t r[BARNACLEDIGESTLEN];
            uint8_t s[BARNACLEDIGESTLEN];
        } signature;
    } s;
    uint8_t u8[0x800];
    uint32_t u32[0x200];
} BARNACLE_AGENT_HDR, *PBARNACLE_AGENT_HDR;

typedef struct
{
    uint16_t start;
    uint16_t size;
} BARNACLE_CERT_INDEX, *PBARNACLE_CERT_INDEX;

#define BARNACLE_CERTSTORE_ROOT     (3)
#define BARNACLE_CERTSTORE_DEVICE   (2)
#define BARNACLE_CERTSTORE_AGENT    (1)
#define BARNACLE_CERTSTORE_POLICY   (0)
typedef struct
{
    uint32_t magic;
    RIOT_ECC_PUBLIC devicePubKey;
    BARNACLE_CERT_INDEX certTable[4];
    uint32_t cursor;
} BARNACLE_CERTSTORE_INFO, *PBARNACLE_CERTSTORE_INFO;
typedef struct
{
    BARNACLE_CERTSTORE_INFO info;
    uint8_t certBag[0x1000 - sizeof(BARNACLE_CERTSTORE_INFO)];
} BARNACLE_CERTSTORE, *PBARNACLE_CERTSTORE;

typedef struct
{
    uint32_t magic;
    RIOT_ECC_PUBLIC pubKey;
    RIOT_ECC_PRIVATE privKey;
} BARNACLE_IDENTITY_PRIVATE_INFO, *PBARNACLE_IDENTITY_PRIVATE_INFO;
typedef union
{
    BARNACLE_IDENTITY_PRIVATE_INFO info;
    uint8_t u8[0x800];
    uint32_t u32[0x200];
} BARNACLE_IDENTITY_PRIVATE, *PBARNACLE_IDENTITY_PRIVATE;

extern PBARNACLE_IDENTITY_PRIVATE pCompoundId;
extern PBARNACLE_CERTSTORE pCertStore;
extern const BARNACLE_AGENT_HDR AgentHdr;

void BarnacleTAPrintCertStore(void);
void BarnacleTAGetCompoundID(RIOT_ECC_PUBLIC* key, char* idStr);
bool BarnacleTADerivePolicyIdentity(uint8_t* agentPolicy, uint32_t agentPolicySize);

#endif /* BARNACLETA_H_ */
