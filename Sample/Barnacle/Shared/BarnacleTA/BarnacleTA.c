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

#ifndef NDEBUG
uint8_t* pAgentCode = ((uint8_t*)0x0802800);
#define AgentSize  (0xDD800)
#else
uint8_t* pAgentCode = ((uint8_t*)0x0801800);
#define AgentSize  (0xED800)
#endif

#define RAM2START (0x10000000)
PBARNACLE_IDENTITY_PRIVATE pCompoundId = (const PBARNACLE_IDENTITY_PRIVATE)RAM2START;
PBARNACLE_CERTSTORE pCertStore = (const PBARNACLE_CERTSTORE)(RAM2START + sizeof(BARNACLE_IDENTITY_PRIVATE));

void BarnacleTADumpCertStore(void)
{
    swoPrint("CertStore:\r\n");
    for(uint32_t n = 0; n < NUMELEM(pCertStore->info.certTable); n++)
    {
        if(pCertStore->info.certTable[n].size > 0)
        {
            swoPrint("%s", (char*)&pCertStore->certBag[pCertStore->info.certTable[n].start]);
        }
    }
}
