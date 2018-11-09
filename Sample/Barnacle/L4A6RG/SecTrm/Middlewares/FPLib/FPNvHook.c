
#ifdef USE_STM32
#include "stm32l4xx_hal.h"
#undef SET_BIT
#undef CLEAR_BIT
#undef AES
#include <stdbool.h>
#include <string.h>
#include <FPPlat.h>
#endif /* STM32 */

#include "Tpm.h"
#include "NvHook.h"
#include "FPNvHook.h"
#include "FPLib.h"


// NV Hook
NV_HOOK_ENTRY NvFunctionTable[] =
{
    {
        FP_SLOTS_MAX,
        NvFpWrite,
        NvFpRead
    },
    {
        1,
        NvDisplayWrite,
        NvDisplayRead
    }
};


NV_HOOK_TABLE NvHookTable =
{
    NV_FPBASE_INDEX,
    NV_FPBASE_INDEX + FP_SLOTS_MAX + 1,
    2,
    NvFunctionTable
};



TPM_RC
NvFpWrite(
    uint32_t index,
    uint8_t* data,
    uint32_t size,
    uint32_t offset
    )
{
    FPR_ERROR_CODE fpResult = FPR_TPMWrite(index, (UINT8*)data, size, offset);

    if ((fpResult == FPR_ERROR_NACK_CAPTURE_CANCELED) ||
        (fpResult == FPR_ERROR_NACK_TIMEOUT))
    {
        return TPM_RC_CANCELED;
    }
    else if (fpResult != FPR_ERROR_ACK_SUCCESS)
    {
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}

TPM_RC
NvFpRead(
    uint32_t index,
    uint8_t* data,
    uint32_t size,
    uint32_t offset
    )
{
    FPR_ERROR_CODE fpResult = FPR_TPMRead(index, (UINT8*)data, size, offset);

    if((fpResult == FPR_ERROR_NACK_CAPTURE_CANCELED) ||
       (fpResult == FPR_ERROR_NACK_TIMEOUT))
    {
        return TPM_RC_CANCELED;
    }
    else if(fpResult != FPR_ERROR_ACK_SUCCESS)
    {
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}

TPM_RC
NvDisplayWrite(
    uint32_t index,
    uint8_t* data,
    uint32_t size,
    uint32_t offset
    )
{
    FPR_ERROR_CODE fpResult = TDisp_Write(data, size, offset);

    if(fpResult != FPR_ERROR_ACK_SUCCESS)
    {
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}

TPM_RC NvDisplayRead(
    uint32_t index,
    uint8_t* data,
    uint32_t size,
    uint32_t offset
    )
{
    FPR_ERROR_CODE fpResult = TDisp_Read(data, size, offset);

    if(fpResult != FPR_ERROR_ACK_SUCCESS)
    {
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}
