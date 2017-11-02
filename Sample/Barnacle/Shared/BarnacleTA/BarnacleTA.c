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

__attribute__((section(".PURW.Private"))) BARNACLE_IDENTITY_PRIVATE CompoundId;
__attribute__((section(".PURW.Public"))) BARNACLE_CERTSTORE CertStore;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
#ifdef AGENTPROJECT
__attribute__((section(".AGENTHDR"))) const BARNACLE_AGENT_HDR AgentHdr = {{{BARNACLEMAGIC, BARNACLEVERSION, sizeof(BARNACLE_AGENT_HDR)}, {AGENTNAME, AGENTVERSION, 0, AGENTTIMESTAMP, {0}}}, {{0}, {0}}, {0}};
#else
__attribute__((section(".AGENTHDR"))) const BARNACLE_AGENT_HDR AgentHdr = {{{BARNACLEMAGIC, BARNACLEVERSION, sizeof(BARNACLE_AGENT_HDR)}, {0}}, {{0}, {0}}, {0}};
#endif
#pragma GCC diagnostic pop
__attribute__((section(".AGENTCODE"))) const uint8_t* AgentCode;

bool BarnacleFlashPages(void* dest, void* src, uint32_t size)
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
                   (((uint32_t)dest % 0x800) == 0) &&
                   (((uint32_t)src % sizeof(uint32_t)) == 0))))
    {
        goto Cleanup;
    }

    // Open the memory protection
    if(!(result = (HAL_FLASH_Unlock() == HAL_OK)))
    {
        goto Cleanup;
    }

    // Erase the necessary pages
    if(!(result = ((HAL_FLASHEx_Erase(&eraseInfo, &pageError) == HAL_OK) ||
                   (pageError != 0xffffffff))))
    {
        goto Cleanup;
    }

    // Flash the src buffer 8 byte at a time and verify
    for(uint32_t n = 0; n < ((size + sizeof(uint64_t) - 1) / sizeof(uint64_t)); n++)
    {
        uint32_t progPtr = (uint32_t)&(((uint64_t*)dest)[n]);
        uint64_t progData = ((uint64_t*)src)[n];
        if((progData != *((uint64_t*)progPtr)) &&
           !(result = (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, progPtr, progData) == HAL_OK)))
        {
            goto Cleanup;
        }
        if(!(result = (progData == *((uint64_t*)progPtr))))
        {
            goto Cleanup;
        }
    }

Cleanup:
    HAL_FLASH_Lock();
    return result;
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

char* BarnacleCertChain()
{
    if(CertStore.magic == BARNACLEMAGIC)
    {
        for(uint32_t n = 0; n < NUMELEM(CertStore.certTable); n++)
        {
            if((CertStore.certTable[n].start != 0) && (CertStore.certTable[n].size != 0))
            {
                return (char*)&CertStore.certBag[CertStore.certTable[n].start];
            }
        }
    }
    return NULL;
}
