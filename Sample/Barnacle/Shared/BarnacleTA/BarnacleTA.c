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
#include <BarnacleTA.h>

extern RNG_HandleTypeDef hrng;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
__attribute__((section(".AGENTHDR"))) const BARNACLE_AGENT_HDR AgentHdr = {{{{BARNACLEMAGIC, BARNACLEVERSION, sizeof(BARNACLE_AGENT_HDR)}, {AGENTNAME, AGENTVERSION, 0, AGENTTIMESTAMP, {0}}}, {{0}, {0}}}};
#pragma GCC diagnostic pop

#ifndef NDEBUG
uint8_t* pAgentCode = ((uint8_t*)0x0802800);
#define AgentSize  (0xDD800)
//__attribute__((section(".AGENTCODE"))) const uint8_t AgentCode[0xDD800];
#else
uint8_t* pAgentCode = ((uint8_t*)0x0801800);
#define AgentSize  (0xED800)
//__attribute__((section(".AGENTCODE"))) const uint8_t AgentCode[0xED800];
#endif

#define RAM2START (0x10000000)
PBARNACLE_IDENTITY_PRIVATE pCompoundId = (const PBARNACLE_IDENTITY_PRIVATE)RAM2START;
PBARNACLE_CERTSTORE pCertStore = (const PBARNACLE_CERTSTORE)(RAM2START + sizeof(PBARNACLE_IDENTITY_PRIVATE));

bool BarnacleErasePages(void* dest, uint32_t size)
{
    bool result = true;
    uint32_t pageError = 0;
    FLASH_EraseInitTypeDef eraseInfo = {FLASH_TYPEERASE_PAGES,
                                        FLASH_BANK_1,
                                        ((uint32_t)dest - 0x08000000) / 0x800,
                                        (size + 0x7ff) / 0x800};

    // Parameter check
    if(!(result = (((uint32_t)dest >= 0x08000000) &&
                   ((uint32_t)dest < 0x08100000) &&
                   ((uint32_t)dest % 0x800) == 0)))
    {
        goto Cleanup;
    }

    // Open the memory protection
    if(!(result = (HAL_FLASH_Unlock() == HAL_OK)))
    {
        goto Cleanup;
    }

    // Erase the necessary pages
    for(uint32_t m = 0; m < 10; m++)
    {
        if((result = ((HAL_FLASHEx_Erase(&eraseInfo, &pageError) == HAL_OK) && (pageError == 0xffffffff))))
        {
            break;
        }
        swoPrint("WARNING: HAL_FLASHEx_Erase() retry %u.\r\n", (unsigned int)m);
    }

Cleanup:
    HAL_FLASH_Lock();
    return result;
}

bool BarnacleFlashPages(void* dest, void* src, uint32_t size)
{
    bool result = true;

    // Parameter check
    if(!(result = ((((uint32_t)src % sizeof(uint32_t)) == 0))))
    {
        goto Cleanup;
    }

    // Erase the required area
    if(!(result = BarnacleErasePages(dest, size)))
    {
        goto Cleanup;
    }

    // Open the memory protection
    if(!(result = (HAL_FLASH_Unlock() == HAL_OK)))
    {
        goto Cleanup;
    }

    // Flash the src buffer 8 byte at a time and verify
    for(uint32_t n = 0; n < ((size + sizeof(uint64_t) - 1) / sizeof(uint64_t)); n++)
    {
        result = false;
        for(uint32_t m = 0; m < 10; m++)
        {
            uint32_t progPtr = (uint32_t)&(((uint64_t*)dest)[n]);
            uint64_t progData = ((uint64_t*)src)[n];
            if((progData == *((uint64_t*)progPtr)) ||
               ((result = (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, progPtr, progData) == HAL_OK)) &&
                (progData == *((uint64_t*)progPtr))))
            {
                result = true;
                break;
            }
            swoPrint("WARNING: HAL_FLASH_Program() retry %u.\r\n", (unsigned int)m);
        }
        if(result == false)
        {
            goto Cleanup;
        }
    }

Cleanup:
    HAL_FLASH_Lock();
    return result;
}

void BarnacleDumpCertStore(void)
{
    swoPrint("CertStore:\r\n");
    for(uint32_t n = 0; n < NUMELEM(CertStore.info.certTable); n++)
    {
        if(CertStore.info.certTable[n].size > 0)
        {
            swoPrint("%s", (char*)&CertStore.certBag[CertStore.info.certTable[n].start]);
        }
    }
}

void BarnacleGetRandom(void* dest, uint32_t size)
{
    for(uint32_t n = 0; n < size; n += sizeof(uint32_t))
    {
        uint32_t entropy = HAL_RNG_GetRandomNumber(&hrng);
        memcpy(&(((uint8_t*)dest)[n]), (uint8_t*)&entropy, MIN(sizeof(entropy), size - n));
    }
}

bool BarnacleNullCheck(void* dataPtr, uint32_t dataSize)
{
    for(uint32_t n = 0; n < dataSize; n++)
    {
        if(((uint8_t*)dataPtr)[n] != 0x00) return false;
    }
    return true;
}
