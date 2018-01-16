/*
 * Barnacle.c
 *
 *  Created on: Oct 18, 2017
 *      Author: stefanth
 */

#include "main.h"
#include "stm32l4xx_hal.h"
#include <cyrep/RiotTarget.h>
#include <cyrep/RiotStatus.h>
#include <cyrep/RiotSha256.h>
#include <cyrep/RiotEcc.h>
#include <cyrep/RiotCrypt.h>
#include <cyrep/RiotDerEnc.h>
#include <cyrep/RiotX509Bldr.h>
#include <tcps/TcpsId.h>
#include <AgentInfo.h>
#include <BarnacleTA.h>

extern RNG_HandleTypeDef hrng;

#ifndef AGENTPROJECT
#define AGENTNAME         ""
#define AGENTVERSIONMAJOR (0)
#define AGENTVERSIONMINOR (0)
#define AGENTTIMESTAMP    (0)
#define AGENTVERSION      (uint32_t)((AGENTVERSIONMAJOR << 16) | AGENTVERSIONMAJOR)
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
__attribute__((section(".AGENTHDR"))) const BARNACLE_AGENT_HDR AgentHdr = {{{{BARNACLEMAGIC, BARNACLEVERSION, sizeof(BARNACLE_AGENT_HDR)}, {AGENTNAME, AGENTVERSION, 0, AGENTTIMESTAMP, {0}}}, {{0}, {0}}}};
#pragma GCC diagnostic pop

#define RAM2START (0x10000000)
PBARNACLE_IDENTITY_PRIVATE pCompoundId = (const PBARNACLE_IDENTITY_PRIVATE)RAM2START;
PBARNACLE_CERTSTORE pCertStore = (const PBARNACLE_CERTSTORE)(RAM2START + sizeof(BARNACLE_IDENTITY_PRIVATE));

void BarnacleTAPrintCertStore(void)
{
    fprintf(stderr, "CertStore:\r\n");
    for(uint32_t n = 0; n < NUMELEM(pCertStore->info.certTable); n++)
    {
        if(pCertStore->info.certTable[n].size > 0)
        {
            fprintf(stderr, "%s", (char*)&pCertStore->certBag[pCertStore->info.certTable[n].start]);
        }
    }
}

bool BarnacleTADerivePolicyIdentity(uint8_t* agentPolicy, uint32_t agentPolicySize)
{
    bool result = true;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    RIOT_ECC_PUBLIC policyPubKey;
    RIOT_ECC_PRIVATE policyPrivKey;
    RIOT_X509_TBS_DATA x509TBSData = { { 0 },
                                       AgentHdr.s.sign.agent.name, NULL, NULL,
                                       "170101000000Z", "370101000000Z",
                                       "AgentPolicy", NULL, NULL };
    DERBuilderContext derCtx = { 0 };
    uint8_t derBuffer[DER_MAX_TBS] = { 0 };
    uint32_t length = 0;
    RIOT_ECC_SIGNATURE  tbsSig = { 0 };
    uint8_t tcps[BARNACLE_TCPS_ID_BUF_LENGTH];
    uint32_t tcpsLen = 0;

    // Derive the policy compound key
    if(!(result = (RiotCrypt_Hash2(digest,
                                   sizeof(digest),
                                   agentPolicy,
                                   agentPolicySize,
                                   &pCompoundId->info.privKey,
                                   sizeof(pCompoundId->info.privKey)))) == RIOT_SUCCESS)
    {
        dbgPrint("ERROR: RiotCrypt2_Hash failed.\r\n");
        goto Cleanup;
    }
    if(!(result = (RiotCrypt_DeriveEccKey(&policyPubKey,
                                          &policyPrivKey,
                                          digest, sizeof(digest),
                                          (const uint8_t *)RIOT_LABEL_IDENTITY,
                                          lblSize(RIOT_LABEL_IDENTITY)) == RIOT_SUCCESS)))
    {
        dbgPrint("ERROR: RiotCrypt_DeriveEccKey failed.\r\n");
        goto Cleanup;
    }

    // Issue the policy compound cert
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    if(!(result = (RiotCrypt_Kdf(digest,
                                 sizeof(digest),
                                 (uint8_t*)&policyPubKey, sizeof(policyPubKey),
                                 NULL, 0,
                                 (const uint8_t *)RIOT_LABEL_SERIAL,
                                 lblSize(RIOT_LABEL_SERIAL),
                                 sizeof(digest)) == RIOT_SUCCESS)))
    {
        dbgPrint("ERROR: RiotCrypt_Kdf failed.\r\n");
        goto Cleanup;
    }
    digest[0] &= 0x7F; // Ensure that the serial number is positive
    digest[0] |= 0x01; // Ensure that the serial is not null
    memcpy(x509TBSData.SerialNum, digest, sizeof(x509TBSData.SerialNum));

    // Calculate agent policy digest
    if(!(result = (RiotCrypt_Hash(digest,
                                  sizeof(digest),
                                  agentPolicy,
                                  agentPolicySize))) == RIOT_SUCCESS)
    {
        dbgPrint("ERROR: RiotCrypt2_Hash failed.\r\n");
        goto Cleanup;
    }

    if(!(result = (BuildTCPSAliasIdentity(&pCertStore->info.devicePubKey,
                                          (uint8_t*)digest,
                                          sizeof(digest),
                                          tcps,
										  BARNACLE_TCPS_ID_BUF_LENGTH,
                                          &tcpsLen) == RIOT_SUCCESS)))
    {
        dbgPrint("ERROR: BuildTCPSAliasIdentity failed.\r\n");
        goto Cleanup;
    }

    result = (X509GetAliasCertTBS(&derCtx,
                                  &x509TBSData,
                                  (RIOT_ECC_PUBLIC*)&policyPubKey,
                                  (RIOT_ECC_PUBLIC*)&pCompoundId->info.pubKey,
                                  (uint8_t*)digest,
                                  sizeof(digest),
                                  tcps,
                                  tcpsLen,
                                  0) == 0);
    if(!result)
    {
        dbgPrint("ERROR: X509GetAliasCertTBS failed.\r\n");
        goto Cleanup;
    }

    // Sign the agent compound key Certificate's TBS region
    if(!(result = (RiotCrypt_Sign(&tbsSig,
                                  derCtx.Buffer,
                                  derCtx.Position,
                                  &pCompoundId->info.privKey) == RIOT_SUCCESS)))
    {
        dbgPrint("ERROR: RiotCrypt_Sign failed.\r\n");
        goto Cleanup;
    }

    // Generate compound key Certificate
    if(!(result = (X509MakeAliasCert(&derCtx, &tbsSig) == 0)))
    {
        dbgPrint("ERROR: X509MakeAliasCert failed.\r\n");
        goto Cleanup;
    }

    // Copy compound key Certificate into the cert store
    pCertStore->info.certTable[BARNACLE_CERTSTORE_POLICY].start = pCertStore->info.cursor;
    length = sizeof(pCertStore->certBag) - pCertStore->info.cursor;
    if(!(result = (DERtoPEM(&derCtx, R_CERT_TYPE, (char*)&pCertStore->certBag[pCertStore->info.cursor], &length) == 0)))
    {
        dbgPrint("ERROR: DERtoPEM failed.\r\n");
        goto Cleanup;
    }
    pCertStore->info.certTable[BARNACLE_CERTSTORE_POLICY].size = (uint16_t)length;
    pCertStore->info.cursor += length;
    pCertStore->certBag[pCertStore->info.cursor] = '\0';

    // Overwrite the agent compound key
    memcpy(&pCompoundId->info.privKey, &policyPrivKey, sizeof(pCompoundId->info.privKey));
    memcpy(&pCompoundId->info.pubKey, &policyPubKey, sizeof(pCompoundId->info.pubKey));

Cleanup:
    return result;
}
