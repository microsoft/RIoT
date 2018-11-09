#pragma once

#ifdef __cplusplus
extern "C" {
#endif


//#define NV_FPBASE_INDEX NV_HOOKBASE_INDEX
#define FP_SLOTS_MAX (200)
#define FP_AUTHORIZE_INDEX (NV_FPBASE_INDEX + FP_SLOTS_MAX)
#define FP_DISPLAY_INDEX (FP_AUTHORIZE_INDEX + 1)

//#define FP_SLOTS (2)

TPM_RC NvFpWrite (uint32_t index, uint8_t* data, uint32_t size, uint32_t offset);
TPM_RC NvFpRead (uint32_t index, uint8_t* data, uint32_t size, uint32_t offset);
TPM_RC NvDisplayWrite (uint32_t index, uint8_t* data, uint32_t size, uint32_t offset);
TPM_RC NvDisplayRead (uint32_t index, uint8_t* data, uint32_t size, uint32_t offset);

#ifdef __cplusplus
}
#endif
