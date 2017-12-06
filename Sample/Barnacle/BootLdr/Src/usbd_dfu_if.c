/**
  ******************************************************************************
  * @file           : usbd_dfu_if.c
  * @brief          :
  ******************************************************************************
  *
  * Copyright (c) 2017 STMicroelectronics International N.V. 
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without 
  * modification, are permitted, provided that the following conditions are met:
  *
  * 1. Redistribution of source code must retain the above copyright notice, 
  *    this list of conditions and the following disclaimer.
  * 2. Redistributions in binary form must reproduce the above copyright notice,
  *    this list of conditions and the following disclaimer in the documentation
  *    and/or other materials provided with the distribution.
  * 3. Neither the name of STMicroelectronics nor the names of other 
  *    contributors to this software may be used to endorse or promote products 
  *    derived from this software without specific written permission.
  * 4. This software, including modifications and/or derivative works of this 
  *    software, must execute solely and exclusively on microcontroller or
  *    microprocessor devices manufactured by or for STMicroelectronics.
  * 5. Redistribution and use of this software other than as permitted under 
  *    this license is void and will automatically terminate your rights under 
  *    this license. 
  *
  * THIS SOFTWARE IS PROVIDED BY STMICROELECTRONICS AND CONTRIBUTORS "AS IS" 
  * AND ANY EXPRESS, IMPLIED OR STATUTORY WARRANTIES, INCLUDING, BUT NOT 
  * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
  * PARTICULAR PURPOSE AND NON-INFRINGEMENT OF THIRD PARTY INTELLECTUAL PROPERTY
  * RIGHTS ARE DISCLAIMED TO THE FULLEST EXTENT PERMITTED BY LAW. IN NO EVENT 
  * SHALL STMICROELECTRONICS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
  * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
  * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
  * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  ******************************************************************************
*/

/* Includes ------------------------------------------------------------------*/
#include "usbd_dfu_if.h"
/* USER CODE BEGIN INCLUDE */
#include "stdio.h"
#include "main.h"
#include "stm32l4xx_hal.h"
/* USER CODE END INCLUDE */

/** @addtogroup STM32_USB_OTG_DEVICE_LIBRARY
  * @{
  */
/** @defgroup USBD_DFU 
  * @brief usbd core module
  * @{
  */ 

/** @defgroup USBD_DFU_Private_TypesDefinitions
  * @{
  */ 
/* USER CODE BEGIN PRIVATE_TYPES */
#define FLASH_ERASE_TIME    (uint16_t)50
#define FLASH_PROGRAM_TIME  (uint16_t)50
/* USER CODE END PRIVATE_TYPES */ 
/**
  * @}
  */ 

/** @defgroup USBD_DFU_Private_Defines
  * @{
  */ 
#define FLASH_DESC_STR "@Barnacle   /0x080FE000/02*04Ka"
/* USER CODE BEGIN PRIVATE_DEFINES */
/* USER CODE END PRIVATE_DEFINES */
  
/**
  * @}
  */ 

/** @defgroup USBD_DFU_Private_Macros
  * @{
  */ 
/* USER CODE BEGIN PRIVATE_MACRO */
/* USER CODE END PRIVATE_MACRO */

/**
  * @}
  */ 

/** @defgroup USBD_AUDIO_IF_Private_Variables
  * @{
  */
/* USER CODE BEGIN PRIVATE_VARIABLES */
/* USER CODE END PRIVATE_VARIABLES */

/**
  * @}
  */ 
  
/** @defgroup USBD_DFU_IF_Exported_Variables
  * @{
  */ 
  extern USBD_HandleTypeDef hUsbDeviceFS;
/* USER CODE BEGIN EXPORTED_VARIABLES */
/* USER CODE END EXPORTED_VARIABLES */

/**
  * @}
  */ 
  
/** @defgroup USBD_DFU_Private_FunctionPrototypes
  * @{
  */
static uint16_t MEM_If_Init_FS(void);
static uint16_t MEM_If_Erase_FS (uint32_t Add);
static uint16_t MEM_If_Write_FS (uint8_t *src, uint8_t *dest, uint32_t Len);
static uint8_t *MEM_If_Read_FS  (uint8_t *src, uint8_t *dest, uint32_t Len);
static uint16_t MEM_If_DeInit_FS(void);
static uint16_t MEM_If_GetStatus_FS (uint32_t Add, uint8_t Cmd, uint8_t *buffer);

/* USER CODE BEGIN PRIVATE_FUNCTIONS_DECLARATION */
/* USER CODE END PRIVATE_FUNCTIONS_DECLARATION */

/**
  * @}
  */ 
  
#if defined ( __ICCARM__ ) /*!< IAR Compiler */
  #pragma data_alignment=4   
#endif
__ALIGN_BEGIN USBD_DFU_MediaTypeDef USBD_DFU_fops_FS __ALIGN_END =
{
   (uint8_t*)FLASH_DESC_STR,
    MEM_If_Init_FS,
    MEM_If_DeInit_FS,
    MEM_If_Erase_FS,
    MEM_If_Write_FS,
    MEM_If_Read_FS,
    MEM_If_GetStatus_FS,   
};

/* Private functions ---------------------------------------------------------*/
/**
  * @brief  MEM_If_Init_FS
  *         Memory initialization routine.
  * @param  None
  * @retval 0 if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Init_FS(void)
{ 
  /* USER CODE BEGIN 0 */ 
    uint16_t result = USBD_FAIL;
    if(HAL_FLASH_Unlock() == HAL_OK)
    {
        result = USBD_OK;
    }
    dbgPrint("%c\r\n", (result == USBD_OK) ? 'I' : 'i');
    return result;
  /* USER CODE END 0 */ 
}

/**
  * @brief  MEM_If_DeInit_FS
  *         De-Initializes Memory.
  * @param  None
  * @retval 0 if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_DeInit_FS(void)
{ 
  /* USER CODE BEGIN 1 */ 
    uint16_t result = USBD_FAIL;
    if(HAL_FLASH_Lock() == HAL_OK)
    {
        result = USBD_OK;
    }
    dbgPrint("%c\r\n", (result == USBD_OK) ? 'D' : 'd');
    return result;
  /* USER CODE END 1 */ 
}

/**
  * @brief  MEM_If_Erase_FS
  *         Erase sector.
  * @param  Add: Address of sector to be erased.
  * @retval 0 if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Erase_FS(uint32_t Add)
{
  /* USER CODE BEGIN 2 */ 
    uint16_t result = USBD_FAIL;

    // We allow you to attempt to erase anything you want the important stuff is
    // read only or behind the firewall
    uint32_t pageError = 0;
    FLASH_EraseInitTypeDef eraseInfo = {FLASH_TYPEERASE_PAGES,
                                        FLASH_BANK_1,
                                        ((uint32_t)Add - 0x08000000) / 0x800,
                                        1};
    for(uint32_t n = 0; n < 2; n++)
    {
    	eraseInfo.Page += n; // DFU defines 4k pages
		if((HAL_FLASHEx_Erase(&eraseInfo, &pageError) != HAL_OK) ||
		   (pageError != 0xffffffff))
		{
			goto Cleanup;
		}
    }
	result = USBD_OK;

Cleanup:
    dbgPrint("%c", (result == USBD_OK) ? 'E' : 'e');
    return result;
  /* USER CODE END 2 */ 
}

/**
  * @brief  MEM_If_Write_FS
  *         Memory write routine.
  * @param  src: Pointer to the source buffer. Address to be written to.
  * @param  dest: Pointer to the destination buffer.
  * @param  Len: Number of data to be written (in bytes).
  * @retval 0 if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Write_FS(uint8_t *src, uint8_t *dest, uint32_t Len)
{
  /* USER CODE BEGIN 3 */ 
    uint16_t result = USBD_FAIL;

    for(uint32_t n = 0; n < Len; n += sizeof(uint64_t))
    {
    	if((HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, (uint32_t)&dest[n], *((uint64_t*)&src[n])) != HAL_OK) ||
           (*((uint64_t*)&src[n]) != *((uint64_t*)&dest[n])))
        {
            goto Cleanup;
        }
    }
    result = USBD_OK;

Cleanup:
    dbgPrint("%c", (result == USBD_OK) ? 'W' : 'w');
    return result;
  /* USER CODE END 3 */ 
}

/**
  * @brief  MEM_If_Read_FS
  *         Memory read routine.
  * @param  src: Pointer to the source buffer. Address to be written to.
  * @param  dest: Pointer to the destination buffer.
  * @param  Len: Number of data to be read (in bytes).
  * @retval Pointer to the physical address where data should be read.
  */
uint8_t *MEM_If_Read_FS (uint8_t *src, uint8_t *dest, uint32_t Len)
{
  /* Return a valid address to avoid HardFault */
  /* USER CODE BEGIN 4 */ 

    // We never allow anybody to read our firewalled area
    if(src > (uint8_t*)0x080FF000)
    {
        dbgPrint("r");
        return 0;
    }
    else
    {
        dbgPrint("R");
        return src;
    }
  /* USER CODE END 4 */ 
}

/**
  * @brief  Flash_If_GetStatus_FS
  *         Get status routine.
  * @param  Add: Address to be read from.
  * @param  Cmd: Number of data to be read (in bytes).
  * @param  buffer: used for returning the time necessary for a program or an erase operation
  * @retval 0 if operation is successful
  */
uint16_t MEM_If_GetStatus_FS (uint32_t Add, uint8_t Cmd, uint8_t *buffer)
{
  /* USER CODE BEGIN 5 */ 
  switch (Cmd)
  {
  case DFU_MEDIA_PROGRAM:
      buffer[1] = (uint8_t)FLASH_PROGRAM_TIME;
      buffer[2] = (uint8_t)(FLASH_PROGRAM_TIME << 8);
      buffer[3] = 0;
      break;
  case DFU_MEDIA_ERASE:
      buffer[1] = (uint8_t)FLASH_ERASE_TIME;
      buffer[2] = (uint8_t)(FLASH_ERASE_TIME << 8);
      buffer[3] = 0;
      break;

  default:

    break;
  }
  dbgPrint("S");
  return  (USBD_OK);
  /* USER CODE END 5 */  
}

/* USER CODE BEGIN PRIVATE_FUNCTIONS_IMPLEMENTATION */
/* USER CODE END PRIVATE_FUNCTIONS_IMPLEMENTATION */

/**
  * @}
  */ 

/**
  * @}
  */  
/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/

