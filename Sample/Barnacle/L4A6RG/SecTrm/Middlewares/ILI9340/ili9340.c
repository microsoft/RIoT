/*
 * ili9340.c
 *
 *  Created on: Aug 17, 2018
 *      Author: stefanth
 */

#include "stm32l4xx_hal.h"
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <ili9340.h>

#include "secdisp_drv.h"
#include "font5x7std.h"

#define ILI9340_DEBUG 0


extern SPI_HandleTypeDef hspi2;

//
//typedef SPI_HandleTypeDef secdisp_driver;


#define tee_time_wait(ms) HAL_Delay(ms)

#if FPLIB_DEBUG
    #define DMSG(...) fprintf(stderr, __VA_ARGS__)
#else
    #define DMSG(...)
#endif /* FPLIB_DEBUG */
#define EMSG(...) fprintf(stderr, __VA_ARGS__)


/*
 * Configuration
 */

/*
 * Display
 */
#define ILI9340_TFTWIDTH  240
#define ILI9340_TFTHEIGHT 320

/*
 * SPI
 * TODO:
 *    Add getting during initialization
 */
#define ILI9340_CFG_SPI_BUS_INDEX 1         /* SPI2 */
#define ILI9340_CFG_SPI_CHANNEL 0           /* Channel 0 */
#define ILI9340_CFG_SPI_MODE PTA_SPI_MODE_0 /* MODE0 */
#define ILI9340_CFG_SPI_SPEED_HZ 12000000   /* SPI speed Hz */

/*
 * Due to hard-wired 4 wire 8-bit interface, DCX is
 * using GPIO3_IO13.
 */
#define GPIO3_IO13  (2 * IMX_GPIO_REGISTER_BITS + 13)

/*
 * Discard buffer size
 */
#define ILI9340_DISCARD_BUFFER_SIZE (32 * 1024)


/*
 * DCX values
 */

 enum ILI9340_DCX_CODES {
    DCX_COMMAND = GPIO_PIN_RESET,
    DCX_DATA = GPIO_PIN_SET
};

/*
 * ILI9340 HW related definitions
 */

#define ILI9340_NO_COMMAND ((uint32_t)-1)

#define ILI9340_NOP     0x00
#define ILI9340_SWRESET 0x01
#define ILI9340_RDDID   0x04
#define ILI9340_RDDST   0x09

#define ILI9340_SLPIN   0x10
#define ILI9340_SLPOUT  0x11
#define ILI9340_PTLON   0x12
#define ILI9340_NORON   0x13

#define ILI9340_RDMODE  0x0A
#define ILI9340_RDMADCTL  0x0B
#define ILI9340_RDPIXFMT  0x0C
#define ILI9340_RDIMGFMT  0x0A
#define ILI9340_RDSELFDIAG  0x0F

#define ILI9340_INVOFF  0x20
#define ILI9340_INVON   0x21
#define ILI9340_GAMMASET 0x26
#define ILI9340_DISPOFF 0x28
#define ILI9340_DISPON  0x29

#define ILI9340_CASET   0x2A
#define ILI9340_PASET   0x2B
#define ILI9340_RAMWR   0x2C
#define ILI9340_RAMRD   0x2E

#define ILI9340_PTLAR   0x30
#define ILI9340_MADCTL  0x36

#define ILI9340_MADCTL_MY  0x80
#define ILI9340_MADCTL_MX  0x40
#define ILI9340_MADCTL_MV  0x20
#define ILI9340_MADCTL_ML  0x10
#define ILI9340_MADCTL_RGB 0x00
#define ILI9340_MADCTL_BGR 0x08
#define ILI9340_MADCTL_MH  0x04

#define ILI9340_PIXFMT  0x3A

#define ILI9340_FRMCTR1 0xB1
#define ILI9340_FRMCTR2 0xB2
#define ILI9340_FRMCTR3 0xB3
#define ILI9340_INVCTR  0xB4
#define ILI9340_DFUNCTR 0xB6

#define ILI9340_PWCTR1  0xC0
#define ILI9340_PWCTR2  0xC1
#define ILI9340_PWCTR3  0xC2
#define ILI9340_PWCTR4  0xC3
#define ILI9340_PWCTR5  0xC4
#define ILI9340_VMCTR1  0xC5
#define ILI9340_VMCTR2  0xC7

#define ILI9340_RDID1   0xDA
#define ILI9340_RDID2   0xDB
#define ILI9340_RDID3   0xDC
#define ILI9340_RDID4   0xDD

#define ILI9340_GMCTRP1 0xE0
#define ILI9340_GMCTRN1 0xE1

// Color definitions
#define ILI9340_BLACK   0x0000
#define ILI9340_BLUE    0x001F
#define ILI9340_RED     0xF800
#define ILI9340_GREEN   0x07E0
#define ILI9340_CYAN    0x07FF
#define ILI9340_MAGENTA 0xF81F
#define ILI9340_YELLOW  0xFFE0
#define ILI9340_WHITE   0xFFFF

/*
 * A command descriptor
 */
#define ILI9340_MAX_COMMAND_PARAMS 16

struct ILI9340_COMMAND {
    uint8_t cmd;
    bool delay_ms;
    uint32_t data_count;
    uint8_t data[ILI9340_MAX_COMMAND_PARAMS];
};

/*
 * Auxiliary macros
 */

#define UNREFERENCED_PARAMETER(p) (p) = (p)

#define FIELD_OFFSET(type, field) ((uint32_t)&(((type *)0)->field))
#define FIELD_SIZE(type, field) (sizeof(((type *)0)->field))

#ifndef ARRAYSIZE
    #define ARRAYSIZE(a) (sizeof(a) / sizeof(a[0]))
#endif // !ARRAYSIZE

#if ILI9340_DEBUG
    #define _DMSG EMSG
#else
    #define _DMSG DMSG
#endif /* ILI9340_DEBUG */

/*
 * ILI9340 interface
 */

//static TEE_Result ili9340_init(struct secdisp_driver* driver);


/*
 * ILI9340 driver globals
 */

/* Display w/h as modified by current rotation */
static int16_t cur_width = ILI9340_TFTWIDTH;
static int16_t cur_height = ILI9340_TFTHEIGHT;
static int16_t cursor_x = 0;
static int16_t cursor_y = 0;
static uint16_t cur_textcolor = 0xFFFF;
static uint16_t cur_textbgcolor = 0xFFFF;
static uint8_t cur_textsize = 1;
//static uint8_t cur_rotation = 0;
/* If set, 'wrap' text at right edge of display */
static bool is_wrap = true;
#if 0
/* If set, use correct CP437 charset (default is off) */
static bool is_cp437 = false;
//GFXfont *gfxFont = NULL;
#endif

static uint16_t line_image[ILI9340_TFTHEIGHT];

/*
 * Color translation table
 */
static uint16_t color_xlt[] = {
    ILI9340_BLACK,   /* SECDISP_BLACK */
    ILI9340_BLUE,    /* SECDISP_BLUE  */
    ILI9340_RED,     /* SECDISP_RED   */
    ILI9340_GREEN,   /* SECDISP_GREEN */
    ILI9340_CYAN,    /* SECDISP_CYAN  */
    ILI9340_MAGENTA, /* SECDISP_MAGEN */
    ILI9340_YELLOW,  /* SECDISP_YELLO */
    ILI9340_WHITE,   /* SECDISP_WHITE */
};


/*
 * SPI PTA interface
 */

static TEE_Result ili9340_send_cmd(uint32_t cmd, bool is_data)
{
    HAL_GPIO_WritePin(DSP_DC_GPIO_Port, DSP_DC_Pin, DCX_COMMAND);
    HAL_StatusTypeDef halResp = HAL_SPI_Transmit(&hspi2, (uint8_t*)&cmd, sizeof(uint8_t), HAL_MAX_DELAY);
    if (halResp != HAL_OK)
    {
        EMSG("SPI send command failed, halResp %d!", halResp);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result ili9340_xchg_data(
        uint8_t* tx,
        uint8_t* rx,
        uint32_t size,
        bool is_command)
{
    HAL_StatusTypeDef halResp;

    if ((tx == NULL) && (rx == NULL)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    HAL_GPIO_WritePin(DSP_DC_GPIO_Port, DSP_DC_Pin, DCX_DATA);

    if (rx == NULL)
    {
        halResp = HAL_SPI_Transmit(&hspi2, tx, size, HAL_MAX_DELAY);

    }
    else if(tx == NULL)
    {
        halResp = HAL_SPI_Receive(&hspi2, rx, size, HAL_MAX_DELAY);
    }
    else
    {
        halResp = HAL_SPI_TransmitReceive(&hspi2, tx, rx, size, HAL_MAX_DELAY);
    }

    if (halResp != HAL_OK)
    {
        EMSG("SPI send command failed, halResp %d!", halResp);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result ili9340_transaction(
    uint32_t cmd,
    uint8_t* tx,
    uint8_t* rx,
    uint32_t count)
{
    TEE_Result status = TEE_ERROR_NOT_IMPLEMENTED;
    bool is_command = false;
    bool is_data = false;

    is_command = cmd != ILI9340_NO_COMMAND;
    is_data = count != 0;

    if (cmd != ILI9340_NO_COMMAND) {
        status = ili9340_send_cmd(cmd, is_data);
        if (status != TEE_SUCCESS) {
            EMSG("ili9340_send_cmd failed, status %d!\n", (int)status);
            return status;
        }
    }

    if (is_data) {
        assert((tx != NULL) || (rx != NULL));
        status = ili9340_xchg_data(tx, rx, count, is_command);
        if (status != TEE_SUCCESS) {
            EMSG("ili9340_xchg_data failed, status %d!\n", (int)status);
            return status;
        }
    }

    return status;
}


/*
 * ILI9340 interface implementation
 */

static TEE_Result ili9340_send_commands(struct ILI9340_COMMAND* cmd_batch, uint32_t count)
{
    struct ILI9340_COMMAND* cmd;
    uint32_t i;
    TEE_Result status;

    cmd = cmd_batch;
    for (i = 0; i < count; ++i, ++cmd) {
        status = ili9340_transaction(cmd->cmd, cmd->data, NULL, cmd->data_count);
        if (status != TEE_SUCCESS) {
            return status;
        }

        if (cmd->delay_ms != 0) {
            tee_time_wait(cmd->delay_ms);
        }
    }

    return  TEE_SUCCESS;
}

static TEE_Result ili9340_init(struct secdisp_driver* driver)
{
    static struct ILI9340_COMMAND init_commands[] = {
        { 0xEF, 0, 3, { 0x03, 0x80, 0x02 } },
        { 0xCF, 0, 3, { 0x00, 0xC1, 0x30 } },
        { 0xED, 0, 4, { 0x64, 0x03, 0x12, 0x81 } },
        { 0xE8, 0, 3, { 0x85, 0x00, 0x78 } },
        { 0xCB, 0, 5, { 0x39, 0x2C, 0x00, 0x34,0x02 } },
        { 0xF7, 0, 1, { 0x20 } },
        { 0xEA, 0, 2, { 0x00, 0x00 } },
        { ILI9340_PWCTR1, 0, 1, { 0x23 } }, /* Power control1 VRH[5:0] */
        { ILI9340_PWCTR2, 0, 1, { 0x10 } }, /* Power control2 SAP[2:0],BT[3:0] */
        { ILI9340_VMCTR1, 0, 2, { 0x3E, 0x28 } }, /* VCM control1   */
        { ILI9340_VMCTR2, 0, 1, { 0x86 } }, /* VCM control2 */
        { ILI9340_MADCTL, 0, 1, { ILI9340_MADCTL_MX | ILI9340_MADCTL_BGR } },
        { ILI9340_PIXFMT, 0, 1,{ 0x55 } }, /* Pixel format */
        { ILI9340_FRMCTR1, 0, 2, { 0x00, 0x18 } }, /* Pixel format */
        { ILI9340_DFUNCTR, 0, 3,{ 0x08, 0x82, 0x27 } }, /* Display Function Control */
        { 0xF2, 0, 1,{ 0x00 } }, /* Display Function Control */
        { ILI9340_GAMMASET, 0, 1, { 0x01 } }, /* Gamma curve selected  */
        { ILI9340_GMCTRP1, 0, 15, { 0x0F, 0x31, 0x2B, 0x0C, 0x0E, 0x08, 0x4E, 0xF1, 0x37, 0x07, 0x10, 0x03, 0x0E, 0x09, 0x00 } }, /* Set Gamma  */
        { ILI9340_GMCTRN1, 0, 15 ,{ 0x00, 0x0E, 0x14, 0x03, 0x11, 0x07, 0x31, 0xC1, 0x48, 0x08, 0x0F, 0x0C, 0x31, 0x36, 0x0F } }, /* Set Gamma  */
        { ILI9340_SLPOUT, 120, 0, }, /* Exit Sleep  */
        { ILI9340_DISPON, 0, 0, }, /* Display on  */
    };
    TEE_Result status;

    UNREFERENCED_PARAMETER(driver);

    status = ili9340_send_commands(init_commands, ARRAYSIZE(init_commands));

#if ILI9340_DEBUG
    if (status == TEE_SUCCESS) {
        uint8_t x;

        ili9340_transaction(ILI9340_RDMODE, NULL, &x, sizeof(uint8_t));
        _DMSG("<<< Display Power Mode: 0x%x\n", x);

        ili9340_transaction(ILI9340_RDMADCTL, NULL, &x, sizeof(uint8_t));
        _DMSG("<<< MADCTL Mode: 0x%x\n", x);

        ili9340_transaction(ILI9340_RDPIXFMT, NULL, &x, sizeof(uint8_t));
        _DMSG("<<< Pixel Format: 0x%x\n", x);

        ili9340_transaction(ILI9340_RDIMGFMT, NULL, &x, sizeof(uint8_t));
        _DMSG("<<< Image Format: 0x%x\n", x);

        ili9340_transaction(ILI9340_RDSELFDIAG, NULL, &x, sizeof(uint8_t));
        _DMSG("<<< Self Diagnostic: 0x%x\n", x);
    }
#endif

    return status;
}

static void ili9340_close(struct secdisp_driver* driver)
{
    UNREFERENCED_PARAMETER(driver);
}

static TEE_Result ili9340_open(struct secdisp_driver* driver)
{
    return ili9340_init(driver);
}

static TEE_Result ili9340_set_addr_window(
    uint16_t x0,
    uint16_t y0,
    uint16_t x1,
    uint16_t y1)
{
    struct ILI9340_COMMAND cmd_batch[] = {
        /* Column address set       x-start              x-end */
        { ILI9340_CASET, 0, 4, { x0 >> 8, x0 & 0xFF, x1 >> 8, x1 & 0xFF } },
        /* Row address set          y-start              y-end */
        { ILI9340_PASET, 0, 4, { y0 >> 8, y0 & 0xFF, y1 >> 8, y1 & 0xFF } },
        /* Write to RAM */
        { ILI9340_RAMWR, 0, 0, },
    };

    return ili9340_send_commands(cmd_batch, ARRAYSIZE(cmd_batch));
}

/*
* ILI9340 graphic functions
*/

static TEE_Result ili9340_draw_pixel(
    struct secdisp_driver *driver,
    int16_t x,
    int16_t y,
    uint16_t color)
{
    TEE_Result status;
    uint16_t ili940_color;

    UNREFERENCED_PARAMETER(driver);

    if ((x < 0) || (x >= cur_width) || (y < 0) || (y >= cur_height)) {
        return TEE_ERROR_EXCESS_DATA;
    }

    status = ili9340_set_addr_window(x, y, x + 1, y + 1);
    if (status != TEE_SUCCESS) {
        EMSG("ili9340_set_addr_window failed, status %d!", (int)status);
        return status;
    }

    ili940_color = color_xlt[color];
    {
        uint8_t color_data[2] = { ili940_color >> 8, ili940_color & 0xFF };

        status = ili9340_transaction(
            ILI9340_NO_COMMAND,
            color_data,
            NULL,
            sizeof(color_data));

        if (status != TEE_SUCCESS) {
            return status;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result ili9340_draw_line(
    struct secdisp_driver *driver,
    int16_t x,
    int16_t y,
    int16_t length,
    uint16_t color,
    bool is_vertical)
{
    TEE_Result status;
    uint16_t ili940_color;
    uint16_t color_ram_val;
    uint16_t i;

    UNREFERENCED_PARAMETER(driver);

    /*
     * Rudimentary clipping
     */
    if ((x >= cur_width) || (y >= cur_height)) {
        return TEE_ERROR_EXCESS_DATA;
    }
    if (is_vertical) {
        if ((y + length - 1) >= cur_height) {
            length = cur_height - y;
        }
        status = ili9340_set_addr_window(x, y, x, y + length - 1);
    } else {
        if ((x + length - 1) >= cur_width) {
            length = cur_width - x;
        }
        status = ili9340_set_addr_window(x, y, x + length - 1, y);
    }

    if (status != TEE_SUCCESS) {
        EMSG("ili9340_set_addr_window failed, status %d!", (int)status);
        return status;
    }

    ili940_color = color_xlt[color];
    color_ram_val = (ili940_color >> 8) | ((ili940_color & 0xFF) << 8);
    for (i = 0; i < length; ++i) {
        line_image[i] = color_ram_val;
    }

    status = ili9340_transaction(
        ILI9340_NO_COMMAND,
        (uint8_t*)line_image,
        NULL,
        length * sizeof(uint16_t));

    return status;
}

static TEE_Result ili9340_fill_rect(
    struct secdisp_driver *driver,
    int16_t x,
    int16_t y,
    int16_t w,
    int16_t h,
    uint16_t color)
{
    TEE_Result status;
    int16_t i;
    uint16_t ili940_color;
    uint16_t color_ram_val;

    UNREFERENCED_PARAMETER(driver);

    /*
     * rudimentary clipping
     */
    if ((x >= cur_width) || (y >= cur_height)) {
        return TEE_ERROR_EXCESS_DATA;
    }
    if ((x + w - 1) >= cur_width) {
        w = cur_width - x;
    }
    if ((y + h - 1) >= cur_height) {
        h = cur_height - y;
    }

    status = ili9340_set_addr_window(x, y, x + w - 1, y + h - 1);
    if (status != TEE_SUCCESS) {
        EMSG("ili9340_set_addr_window failed, status %d!", (int)status);
        return status;
    }

    ili940_color = color_xlt[color];
    color_ram_val = (ili940_color >> 8) | ((ili940_color & 0xFF) << 8);

    for (i = 0; i < w; ++i) {
        line_image[i] = color_ram_val;
    }

    for (y = h; y > 0; y--) {
        status = ili9340_transaction(
            ILI9340_NO_COMMAND,
            (uint8_t*)line_image,
            NULL,
            w * sizeof(uint16_t));

        if (status != TEE_SUCCESS) {
            EMSG("ili9340_transaction failed, status %d!", (int)status);
            return status;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result ili9340_clear(
    struct secdisp_driver *driver,
    uint16_t color)
{
    TEE_Result status;

    status =  ili9340_fill_rect(
            driver,
            0, /* x */
            0, /* y */
            cur_width,  /* w */
            cur_height, /* h */
            color);

    if (status != TEE_SUCCESS) {
        EMSG("ili9340_fill_rect failed, status %d!", (int)status);
        return status;
    }

    cursor_x = 0;
    cursor_y = 0;
    cur_textbgcolor = color;
    return TEE_SUCCESS;
}

static TEE_Result ili9340_set_rotation(
    struct secdisp_driver *driver,
    uint8_t rotation)
{
    uint8_t data;

    switch (rotation) {
    case SECDISP_0:
        data = (ILI9340_MADCTL_MX | ILI9340_MADCTL_BGR);
        cur_width = ILI9340_TFTWIDTH;
        cur_height = ILI9340_TFTHEIGHT;
        break;

    case SECDISP_90:
        data = (ILI9340_MADCTL_MV | ILI9340_MADCTL_BGR);
        cur_width = ILI9340_TFTHEIGHT;
        cur_height = ILI9340_TFTWIDTH;
        break;

    case SECDISP_180:
        data = (ILI9340_MADCTL_MY | ILI9340_MADCTL_BGR);
        cur_width = ILI9340_TFTWIDTH;
        cur_height = ILI9340_TFTHEIGHT;
        break;

    case SECDISP_270:
        data = (ILI9340_MADCTL_MV | ILI9340_MADCTL_MY | ILI9340_MADCTL_MX | ILI9340_MADCTL_BGR);
        cur_width = ILI9340_TFTHEIGHT;
        cur_height = ILI9340_TFTWIDTH;
        break;

    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
	
    driver->disp_info->height = cur_height;
    driver->disp_info->width = cur_width;

    return ili9340_transaction(ILI9340_MADCTL, &data, NULL, 1);
}

static TEE_Result ili9340_invert_display(
    struct secdisp_driver *driver,
    bool is_invert)
{
    UNREFERENCED_PARAMETER(driver);

    return ili9340_send_cmd(is_invert ? ILI9340_INVON : ILI9340_INVOFF, false);
}

TEE_Result ili9340_set_text_attr(
    struct secdisp_driver *driver,
    uint16_t color,
    uint16_t bgcolor,
    uint16_t size)
{
    UNREFERENCED_PARAMETER(driver);

    cur_textcolor = color;
    cur_textbgcolor = bgcolor;
    cur_textsize = size;

    return TEE_SUCCESS;
}

static TEE_Result ili9340_draw_char(
    struct secdisp_driver *driver,
    int16_t x,
    int16_t y,
    uint16_t color,
    uint16_t bgcolor,
    uint16_t size,
    uint8_t c)
{
    if ((x >= cur_width) || (y >= cur_height)) {
        return TEE_SUCCESS;
    }

    for (int8_t i = 0; i < FONT_WIDTH; i++) {
        uint8_t line = font[c * FONT_WIDTH + i];

        for (int8_t j = 0; j < 8; j++, line >>= 1) {
            if (line & 1) {
                if (size == 1)
                    ili9340_draw_pixel(driver, x + i, y + j, color);
                else
                    ili9340_fill_rect(driver, x + i*size, y + j*size, size, size, color);
            }
            else if (bgcolor != color) {
                if (size == 1)
                    ili9340_draw_pixel(driver, x + i, y + j, bgcolor);
                else
                    ili9340_fill_rect(driver, x + i*size, y + j*size, size, size, bgcolor);
            }
        }
    }

    // Continue bgcolor
    for (int8_t j = 0; j < 8; j++) {
        if (size == 1)
            ili9340_draw_pixel(driver, x + FONT_WIDTH, y + j, bgcolor);
        else
            ili9340_fill_rect(driver, x + FONT_WIDTH*size, y + j*size, size, size, bgcolor);
    }

    return TEE_SUCCESS;
}

bool is_alpha(uint8_t c)
{
    return ((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z'));
}

bool is_number(uint8_t c)
{
    return ((c >= '0') && (c <= '9'));
}

static void ili9340_clear_line(
    struct secdisp_driver *driver,
    uint8_t pos)
{
    int16_t start_x;
    int16_t end_x;

    UNREFERENCED_PARAMETER(driver);

    switch (pos) {
    case '0': /* current cursor position to end of line */
        start_x = cursor_x;
        end_x = cur_width;
        break;
    case '1': /* beginning to current cursor position  */
        start_x = 0;
        end_x = cursor_x;
        break;
    case '2': /* whole line  */
        start_x = 0;
        end_x = cur_width;
        break;
    default:
        return;
    }

    while (start_x < end_x) {

        (void)ili9340_draw_char(
            driver,
            start_x, cursor_y,
            cur_textcolor, cur_textbgcolor,
            cur_textsize,
            ' ');

        start_x += cur_textsize * FONT_RECT_WIDTH;
    }
}

static uint16_t ili9340_pars_esc_codes(
    struct secdisp_driver *driver,
    uint8_t *text,
    uint16_t count)
{
    if ((count < 4) || (text[1] != '[')) {
        return 1;
    }

    if (is_alpha(text[2])) {
        /*
        * ^[K or ^[H
        */
        switch (text[2]) {
        case 'H':
            cursor_x = 0;
            cursor_y = 0;
            return 3;
        case 'K':
            ili9340_clear_line(driver, '0');
            return 3;
        default:
            return 1;
        }
    }

    if (is_alpha(text[3])) {
        /*
         * ^[<n>K or ^[<n>m
         */
        switch (text[3]) {
        case 'K':
            ili9340_clear_line(driver, text[2]);
            return 4;
        case 'm':
            return 4;
        default:
            return 1;
        }

    } else if (is_number(text[3])) {
        /*
        * ^[<n1><n2>m
        */
        if (count < 5) {
            return 1;
        }
        if (text[4] == 'm') {
            switch (text[2]) {
            case '3':
                if ((is_number(text[3])) &&
                    (text[3] < '8')) {
                  //
                    // * Foreground coloring
                    // * ^[3<n>m
                  //
                    ili9340_set_text_attr(driver, text[3] - '0', cur_textbgcolor, cur_textsize );
                    return 5;
                }

                // standout not implemented
                return 5;
            case '4':
                if ((is_number(text[3])) &&
                    (text[3] < '8')) {
                   //*
                     //* Background coloring
                     //* ^[4<n>m
                   ///
                    ili9340_set_text_attr(driver, cur_textcolor, text[3] - '0', cur_textsize );
                    return 5;
                }

                // underscore not implemented
                return 5;

            case '5':
                if ((is_number(text[3])) &&
                    (text[3] < '8')) {
                   //*
                     //* Fontsize (custom code)
                     //* ^[5<n>m
                   ///
                    ili9340_set_text_attr(driver, cur_textcolor, cur_textbgcolor, text[3] - '0' );
                    return 5;
                }

                // not implemented
                return 5;
            default:
                return 5;
            }
            return 5;
        }
    }

    return 1;
}

TEE_Result ili9340_write_text(
    struct secdisp_driver *driver,
    int16_t x,
    int16_t y,
    uint8_t *text,
    uint16_t count)
{
    TEE_Result status;

    if (x != -1) {
        if (x < ILI9340_TFTWIDTH) {
            cursor_x = x;
        } else {
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
    if (y != -1) {
        if (y < ILI9340_TFTHEIGHT) {
            cursor_y = y;
        } else {
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    for (uint16_t i = 0; i < count;) {
        uint8_t c = text[i];

        switch (c) {
        case '\r':
            cursor_x = 0;
            break;

        case '\n':
            // Fill the line with any change in bgcolor
            ili9340_clear_line(driver, '0');
            cursor_x = 0;
            cursor_y += cur_textsize * FONT_RECT_HEIGHT;
            break;

        case '\x1B': /* ESC codes */
            i += ili9340_pars_esc_codes(driver, &text[i], count - i);
            continue;

        default:
            if ((cursor_x + cur_textsize * FONT_RECT_WIDTH) > cur_width) {
                if (!is_wrap) {
                    continue;
                }
                // Fill the line with any change in bgcolor
                ili9340_clear_line(driver, '0');
                cursor_x = 0;
                cursor_y += cur_textsize * FONT_RECT_HEIGHT;
            }

            status = ili9340_draw_char(
                driver,
                cursor_x, cursor_y,
                cur_textcolor, cur_textbgcolor,
                cur_textsize,
                c);

            if (status != TEE_SUCCESS) {
                return status;
            }
            cursor_x += cur_textsize * FONT_RECT_WIDTH;
        } /* switch */

        ++i;
    }

    return TEE_SUCCESS;
}

// Height and width can change with rotation actions.
static SECDISP_INFORMATION disp_info = {
    .height = ILI9340_TFTHEIGHT,
    .width = ILI9340_TFTWIDTH,
    .bits_per_pixel = 16,
};

static const struct secdisp_ops ops = {
    .deinit = ili9340_close,
    .clear = ili9340_clear,
    .draw_pixel = ili9340_draw_pixel,
    .draw_line = ili9340_draw_line,
    .fill_rect = ili9340_fill_rect,
    .set_rotation = ili9340_set_rotation,
    .invert_display = ili9340_invert_display,
    .set_text_attr = ili9340_set_text_attr,
    .write_text = ili9340_write_text,
};

TEE_Result ili9340_drv_init(struct secdisp_driver* driver)
{
    TEE_Result status;

    memset(driver, 0, sizeof(*driver));
    status = ili9340_open(driver);

    if (status != TEE_SUCCESS) {
        ili9340_close(driver);
        return status;
    }

    driver->disp_info = &disp_info;
    driver->ops = &ops;
    return TEE_SUCCESS;
}
