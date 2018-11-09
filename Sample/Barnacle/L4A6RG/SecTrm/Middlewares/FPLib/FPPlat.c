
#include "stm32l4xx_hal.h"
#include <stdbool.h>
#include <string.h>
#include <FPPlat.h>
#include <stdarg.h>
#include "secdisp_drv.h"
#include "ili9340.h"

extern UART_HandleTypeDef huart3;
#define fp_huart huart3
#define FPR_RDX_SIZE    480

#define STATUS_TXT_MAX              100
#define STATUS_TIMEOUT_MS           7000
#define STATUS_DEFAULT_FONT_COLOR   SECDISP_YELLOW
#define STATUS_DEFAULT_FONT_SIZE    2
#define STATUS_DISPLAY_HEIGHT       20
#define STATUS_DEFAULT_TEXT         "Ready%s"
#define IDLE_INDICATOR_HEIGHT       3
#define IDLE_INDICATOR_COLOR        SECDISP_BLUE

typedef struct _DISP_STATUS {

    char Buff[STATUS_TXT_MAX + 1];
    uint32_t StartTick;
    bool Active;
} DisStatus;

typedef struct _FPR_STATE
{
    UART_HandleTypeDef* huart;
    uint32_t BaudRate;
    bool FprInit;
    bool UARTInit;
    bool FPOpened;
    uint32_t RxRd;
    uint32_t RxWr;
    uint8_t RxBuf[FPR_RDX_SIZE];
} FPRState;

// *DISPLAY DRIVER*
bool g_DisplayReady = false;
struct secdisp_driver g_Secdisp;
extern char displayText[FP_DISPLAY_MAX_TEXT + 1];

DisStatus g_Status = { 0 };
uint16_t idlecount = 0;
uint16_t idlecolor = SECDISP_BLUE;
int16_t x_idle = 0;

void InitializeSecureDisplay(bool force)
{
    TEE_Result res;
    //SECDISP_INFORMATION disp_info;

    if (g_DisplayReady && !force)
    {
        return;
    }

    g_DisplayReady = false;

    HAL_GPIO_WritePin(DSP_RST_GPIO_Port, DSP_RST_Pin, GPIO_PIN_RESET);
    HAL_Delay(50);
    HAL_GPIO_WritePin(DSP_RST_GPIO_Port, DSP_RST_Pin, GPIO_PIN_SET);
    HAL_Delay(50);

    ClearStatus();

    res = ili9340_drv_init(&g_Secdisp);
    if (res != TEE_SUCCESS) {
        _EMSG("secdisp_init failed, status 0x%x", (uint)res);
        return;
    }

    res = g_Secdisp.ops->set_text_attr(&g_Secdisp, SEC_DEF_TEXT_COLOR, SEC_DEF_TEXTBG_COLOR, SEC_DEF_TEXT_SIZE);
    if (res != TEE_SUCCESS) {
        _EMSG("secdisp_set_text_attr failed, status 0x%x", (uint)res);
        return;
    }

    res = g_Secdisp.ops->set_rotation(&g_Secdisp, SECDISP_270);
    if (res != TEE_SUCCESS) {
        _EMSG("secdisp_set_rotation failed, status 0x%x", (uint)res);
        return;
    }

    res = g_Secdisp.ops->clear(&g_Secdisp, SECDISP_BLACK);
    if (res != TEE_SUCCESS) {
        _EMSG("secdisp_clear failed, status 0x%x", (uint)res);
        return;
    }

    memset(displayText, 0x00, sizeof(displayText));

    g_DisplayReady = true;
}

void ClearSecureDisplay()
{
    if (g_DisplayReady) {
        g_Secdisp.ops->clear(&g_Secdisp, SEC_DEF_TEXTBG_COLOR);
        RefreshStatus(true);
    }
}

void CloseDisplay()
{
    ClearSecureDisplay();
    g_DisplayReady = false;
}

void SetDefaultAttributes()
{
    if (g_DisplayReady) g_Secdisp.ops->set_text_attr(&g_Secdisp, SEC_DEF_TEXT_COLOR, SEC_DEF_TEXTBG_COLOR, SEC_DEF_TEXT_SIZE);
}

#define SECDISP_MAX_PRINT_SIZE 1024

void SecureDisplayPrintf(bool sys, const char *fmt, ...)
{
    if (!g_DisplayReady) return;

    TEE_Result status;
    va_list args;
    int ccount;
    static char print_buf[SECDISP_MAX_PRINT_SIZE];

    va_start(args, fmt);
    // BUGBUG: we do not have vsnprintk. Should validate buffer overrun.
    ccount = vsprintf(print_buf, fmt, args);
    va_end(args);

    if (ccount == 0) {
        return;
    }

    if (!sys)
    {
        ClearIdle();
        status = g_Secdisp.ops->write_text(&g_Secdisp, -1, -1, (uint8_t *)print_buf, ccount);
        if (status != TEE_SUCCESS) {
            //TEE_Panic(status);
        }
    }
    else
    {
        SetStatus(print_buf);
    }
}

// Global FP reader state.
FPRState  g_FprState = { &fp_huart, 9600, 0, 0, 0, 0, 0, {0} };

// HUART interrupt handler
void HAL_UART_RxCpltCallback(UART_HandleTypeDef* huart)
{
    // BUGBUG: We can happily overwrite here if we are not reading quickly enough
    if (huart == g_FprState.huart)
    {
        g_FprState.RxWr = (g_FprState.RxWr + 1) % sizeof(g_FprState.RxBuf);
        HAL_UART_Receive_IT(huart, &g_FprState.RxBuf[g_FprState.RxWr], 1);
    }
}

static FPR_ERROR_CODE EnableUART()
{
    g_FprState.huart->Init.BaudRate = g_FprState.BaudRate;
    g_FprState.huart->Init.WordLength = UART_WORDLENGTH_8B;
    g_FprState.huart->Init.StopBits = UART_STOPBITS_1;
    g_FprState.huart->Init.Parity = UART_PARITY_NONE;
    g_FprState.huart->Init.Mode = UART_MODE_TX_RX;
    g_FprState.huart->Init.HwFlowCtl = UART_HWCONTROL_NONE;
    g_FprState.huart->Init.OverSampling = UART_OVERSAMPLING_16;
    g_FprState.huart->Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
    g_FprState.huart->AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
    if (HAL_UART_Init(g_FprState.huart) != HAL_OK)
    {
      Error_Handler();
    }

    //  Enable the UART interrupt
    memset(g_FprState.RxBuf, 0x00, sizeof(g_FprState.RxBuf));
    g_FprState.RxWr = 0;
    g_FprState.RxRd = 0;

    __HAL_UART_ENABLE_IT(g_FprState.huart, UART_IT_RXNE);
    if (HAL_UART_Receive_IT(g_FprState.huart, &g_FprState.RxBuf[0], 1) != HAL_OK)
    {
        return FPR_ERROR_NACK_COMM_ERR;
    }

    g_FprState.UARTInit = true;
    return FPR_ERROR_ACK_SUCCESS;
}

static void DisableUART()
{
    HAL_UART_AbortReceive_IT(g_FprState.huart);
    memset(g_FprState.RxBuf, 0x00, sizeof(g_FprState.RxBuf));
    g_FprState.RxRd = 0;
    g_FprState.RxWr = 0;
    g_FprState.UARTInit = false;
    HAL_UART_DeInit(g_FprState.huart);
}

FPR_ERROR_CODE FPRP_Initialize(bool re_init)
{
    FPR_ERROR_CODE result;
    DEV_INFO_FPR devInfo = { 0 };

    if (g_FprState.FprInit)
    {
        if (!re_init)
        {
            result = FPR_ERROR_ACK_SUCCESS;
            goto Cleanup;
        }
        FPRP_Close();
    }

    if ((result = EnableUART()) != FPR_ERROR_ACK_SUCCESS)
    {
        result = FPR_ERROR_NACK_DEV_ERR;
        goto Cleanup;
    }

    if (g_FprState.BaudRate != 115200)
    {
        result = FPR_ChangeBaudrate(115200);
        if ((result != FPR_ERROR_ACK_SUCCESS) && (result != FPR_ERROR_NACK_TIMEOUT))
        {
            goto Cleanup;
        }
        g_FprState.BaudRate = 115200;

        DisableUART();
        if ((result = EnableUART()) != FPR_ERROR_ACK_SUCCESS)
        {
            result = FPR_ERROR_NACK_DEV_ERR;
            goto Cleanup;
        }
    }

    if ((result = FPR_Open(&devInfo)) != FPR_ERROR_ACK_SUCCESS)
    {
       result = FPR_ERROR_NACK_DEV_ERR;
       goto Cleanup;
    }
    g_FprState.FPOpened = true;

    if ((result = FPR_CMOSLEDControl(false)) != FPR_ERROR_ACK_SUCCESS)
    {
          goto Cleanup;
    }

    g_FprState.FprInit = true;
    result = FPR_ERROR_ACK_SUCCESS;

Cleanup:

    if (result != FPR_ERROR_ACK_SUCCESS)
    {
        FPRP_Close();
    }

    return result;
}

void FPRP_Close(void)
{
    if (g_FprState.FPOpened)
    {
        FPR_Close();
        g_FprState.FPOpened = false;
    }

    if (g_FprState.UARTInit)
    {
        DisableUART();
    }

    g_FprState.FprInit = false;
}

uint32_t FPRP_GetTick(void)
{
    return HAL_GetTick();
}

void FPRP_WriteChar(unsigned char data, int* timeout)
{
    unsigned int startTime = FPRP_GetTick();
    HAL_UART_Transmit(g_FprState.huart, (uint8_t*)&data, sizeof(data), *timeout);
    *timeout -= FPRP_GetTick() - startTime;
}

unsigned char FPRP_ReadChar(int* timeout)
{
    unsigned char data = 0;

   while (*timeout > 0)
   {
       if (g_FprState.RxRd  == g_FprState.RxWr)
       {
           HAL_Delay(1);
           *timeout -= 1;
           continue;
       }
       data = g_FprState.RxBuf[g_FprState.RxRd ];
       g_FprState.RxRd = (g_FprState.RxRd  + 1) % sizeof(g_FprState.RxBuf);
       return data;;
   }
   return data;
}

void FPRP_Sleep(unsigned int durationMsec)
{
    HAL_Delay(durationMsec);
}

void ClearIdle()
{
    if (x_idle != 0) {
        idlecount = 0;
        x_idle = 0;;

        g_Secdisp.ops->fill_rect(&g_Secdisp,
                0,
                g_Secdisp.disp_info->height - SEC_DEF_TEXT_SIZE,
                g_Secdisp.disp_info->width,
                2,
                SEC_DEF_TEXTBG_COLOR
                 );
    }
}

void SetStatus(char * statusTxt)
{
    if (strlen(statusTxt) > STATUS_TXT_MAX) {
        strcpy(g_Status.Buff, "Internal Error");
    }
    else {
        strcpy(g_Status.Buff, statusTxt);
    }


    g_Status.StartTick = HAL_GetTick();
    RefreshStatus(true);
}

void ClearStatus()
{
    g_Status.StartTick = 0;
    sprintf(g_Status.Buff, STATUS_DEFAULT_TEXT, ESC_EL);

    if (g_Status.Active) {
        g_Secdisp.ops->fill_rect(
                &g_Secdisp,
                0,
                g_Secdisp.disp_info->height - STATUS_DISPLAY_HEIGHT,
                g_Secdisp.disp_info->width,
                STATUS_DISPLAY_HEIGHT - IDLE_INDICATOR_HEIGHT,
                SEC_DEF_TEXTBG_COLOR );

        g_Secdisp.ops->set_text_attr(&g_Secdisp, STATUS_DEFAULT_FONT_COLOR, SEC_DEF_TEXTBG_COLOR, STATUS_DEFAULT_FONT_SIZE );
        g_Secdisp.ops->write_text(&g_Secdisp, 1, g_Secdisp.disp_info->height - STATUS_DISPLAY_HEIGHT, (uint8_t *)g_Status.Buff, strlen(g_Status.Buff));
        g_Secdisp.ops->set_text_attr(&g_Secdisp, SEC_DEF_TEXT_COLOR, SEC_DEF_TEXTBG_COLOR, SEC_DEF_TEXT_SIZE );
        g_Status.Active = false;
    }
    return;
}

void RefreshStatus(bool force)
{

    if ((HAL_GetTick() - g_Status.StartTick)  > STATUS_TIMEOUT_MS){
        ClearStatus();
        return;
    }

    // Limit actual prints to when required.
    if (g_Status.Active && !force) {
        return;
    }

    g_Status.Active = true;
    g_Secdisp.ops->set_text_attr(&g_Secdisp, STATUS_DEFAULT_FONT_COLOR, SEC_DEF_TEXTBG_COLOR, STATUS_DEFAULT_FONT_SIZE );
    g_Secdisp.ops->write_text(&g_Secdisp, 1, g_Secdisp.disp_info->height - STATUS_DISPLAY_HEIGHT, (uint8_t *)g_Status.Buff, strlen(g_Status.Buff));
    g_Secdisp.ops->set_text_attr(&g_Secdisp, SEC_DEF_TEXT_COLOR, SEC_DEF_TEXTBG_COLOR, SEC_DEF_TEXT_SIZE );
}

void UpdateIdleIndicator()
{
    if (idlecount < 10000)
    {
        idlecount++;
        return;
    }
    idlecount = 0;

    if (g_DisplayReady)
    {
        RefreshStatus(false);

        if (idlecolor == SECDISP_BLUE)
        {
            g_Secdisp.ops->fill_rect(&g_Secdisp,
                    (g_Secdisp.disp_info->width / 2) + x_idle,
                    g_Secdisp.disp_info->height - IDLE_INDICATOR_HEIGHT,
                    3, 2,
                    idlecolor
                     );

            g_Secdisp.ops->fill_rect(&g_Secdisp,
                    (g_Secdisp.disp_info->width / 2) - x_idle,
                    g_Secdisp.disp_info->height - IDLE_INDICATOR_HEIGHT,
                    3, 2,
                    idlecolor
                     );
        }
        else
        {
            g_Secdisp.ops->fill_rect(&g_Secdisp,
                    x_idle,
                    g_Secdisp.disp_info->height - IDLE_INDICATOR_HEIGHT,
                    3, 2,
                    idlecolor
                     );

            g_Secdisp.ops->fill_rect(&g_Secdisp,
                    g_Secdisp.disp_info->width - x_idle,
                    g_Secdisp.disp_info->height - IDLE_INDICATOR_HEIGHT,
                    3, 2,
                    idlecolor
                     );
        }

        //g_Secdisp.ops->draw_line(&g_Secdisp, x_idle, g_Secdisp.disp_info->height - SEC_DEF_TEXT_SIZE, SEC_DEF_TEXT_SIZE, idlecolor, false );

        //g_Secdisp.ops->draw_line(&g_Secdisp, x_idle, 0 + SEC_DEF_TEXT_SIZE, SEC_DEF_TEXT_SIZE, idlecolor, false );
    }

    if (x_idle < (g_Secdisp.disp_info->width / 2))
        x_idle += SEC_DEF_TEXT_SIZE;
    else
    {
        idlecolor = (idlecolor == IDLE_INDICATOR_COLOR) ? SEC_DEF_TEXTBG_COLOR : IDLE_INDICATOR_COLOR;
        x_idle = 0;
    }
}
