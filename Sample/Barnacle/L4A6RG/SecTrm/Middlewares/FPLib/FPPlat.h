#pragma once
#include "FPLib.h"


// Display Definitions
// Cursor
#define ESC_HOME "\x1B[H" /* Move cursor to home (0,0) position */
// Erasing text
#define ESC_EL  "\x1B[0K" /* Clear line from current cursor position to end of line*/
#define ESC_EL1 "\x1B[1K" /* Clear line from beginning to current cursor position */
#define ESC_EL2 "\x1B[2K" /* Clear whole */
// Font color
#define ESC_FONT_BLACK      "\x1B[30m"
#define ESC_FONT_BLUE       "\x1B[31m"
#define ESC_FONT_RED        "\x1B[32m"
#define ESC_FONT_GREEN      "\x1B[33m"
#define ESC_FONT_CYAN       "\x1B[34m"
#define ESC_FONT_MAGENTA    "\x1B[35m"
#define ESC_FONT_YELLOW     "\x1B[36m"
#define ESC_FONT_WHITE      "\x1B[37m"
// Background colors
#define ESC_FONT_BG_BLACK      "\x1B[40m"
#define ESC_FONT_BG_BLUE       "\x1B[41m"
#define ESC_FONT_BG_RED        "\x1B[42m"
#define ESC_FONT_BG_GREEN      "\x1B[43m"
#define ESC_FONT_BG_CYAN       "\x1B[44m"
#define ESC_FONT_BG_MAGENTA    "\x1B[45m"
#define ESC_FONT_BG_YELLOW     "\x1B[46m"
#define ESC_FONT_BG_WHITE      "\x1B[47m"
// Font Size
#define FONT_SIZE_1       "\x1B[51m"
#define FONT_SIZE_2       "\x1B[52m"
#define FONT_SIZE_3       "\x1B[53m"
#define FONT_SIZE_4       "\x1B[54m"
#define FONT_SIZE_5       "\x1B[55m"

#define TEE_Time RTC_TimeTypeDef
#define TEE_GetSystemTime(time) HAL_RTC_GetTime(&hrtc, time, RTC_FORMAT_BIN)
#define FPR_PORT_CONFIG NULL

#define SEC_DEF_TEXT_COLOR      SECDISP_YELLOW
#define SEC_DEF_TEXTBG_COLOR    SECDISP_BLACK
#define SEC_DEF_TEXT_SIZE       3

#if FPLIB_DEBUG
    #define _DMSG(...) fprintf(stderr, __VA_ARGS__)
#else
    #define _DMSG(...)
#endif /* FPLIB_DEBUG */
#define _EMSG(...) fprintf(stderr, __VA_ARGS__)

#define SEC_MSG_INIT(is_force) InitializeSecureDisplay(is_force)
#define SEC_MSG_CLEAR() ClearSecureDisplay();
#define SEC_MSG(...) SetDefaultAttributes(); SecureDisplayPrintf(false, __VA_ARGS__);
#define SEC_STATUS(...) SecureDisplayPrintf(true, __VA_ARGS__);

uint32_t GetTickCount(void);

void InitializeSecureDisplay(bool force);
void ClearSecureDisplay();
void SetDefaultAttributes();
void SecureDisplayPrintf(bool sys, const char *fmt, ...);
void StatusPrintf(unsigned int timeout, const char *fmt, ...);
void UpdateIdleIndicator();
void ClearIdle();
void RefreshStatus(bool force);
void SetStatus(char * statusTxt);
void ClearStatus();
