/*
 * secdisp_drv.h
 *
 *  Created on: Aug 17, 2018
 *      Author: stefanth
 */

#ifndef __DRIVERS_SECDISP_H
#define __DRIVERS_SECDISP_H

#include <assert.h>
#include <stdbool.h>

/* API Error Codes */
#define TEE_SUCCESS                       0x00000000
#define TEE_ERROR_CORRUPT_OBJECT          0xF0100001
#define TEE_ERROR_CORRUPT_OBJECT_2        0xF0100002
#define TEE_ERROR_STORAGE_NOT_AVAILABLE   0xF0100003
#define TEE_ERROR_STORAGE_NOT_AVAILABLE_2 0xF0100004
#define TEE_ERROR_GENERIC                 0xFFFF0000
#define TEE_ERROR_ACCESS_DENIED           0xFFFF0001
#define TEE_ERROR_CANCEL                  0xFFFF0002
#define TEE_ERROR_ACCESS_CONFLICT         0xFFFF0003
#define TEE_ERROR_EXCESS_DATA             0xFFFF0004
#define TEE_ERROR_BAD_FORMAT              0xFFFF0005
#define TEE_ERROR_BAD_PARAMETERS          0xFFFF0006
#define TEE_ERROR_BAD_STATE               0xFFFF0007
#define TEE_ERROR_ITEM_NOT_FOUND          0xFFFF0008
#define TEE_ERROR_NOT_IMPLEMENTED         0xFFFF0009

typedef uint32_t TEE_Result;

struct secdisp_driver;

struct secdisp_ops {
    void (*deinit)(struct secdisp_driver *driver);

    TEE_Result(*clear)(
        struct secdisp_driver *driver,
        uint16_t color);

    TEE_Result (*draw_pixel)(
        struct secdisp_driver *driver,
        int16_t x,
        int16_t y,
        uint16_t color);

    TEE_Result (*draw_line)(
        struct secdisp_driver *driver,
        int16_t x,
        int16_t y,
        int16_t length,
        uint16_t color,
        bool is_vertical);

    TEE_Result (*fill_rect)(
        struct secdisp_driver *driver,
        int16_t x,
        int16_t y,
        int16_t w,
        int16_t h,
        uint16_t color);

    TEE_Result (*set_rotation)(struct secdisp_driver *driver, uint8_t rotation);
    TEE_Result (*invert_display)(struct secdisp_driver *driver, bool is_invert);
    TEE_Result(*set_text_attr)(
        struct secdisp_driver *driver,
        uint16_t color,
        uint16_t bgcolor,
        uint16_t size);

    TEE_Result(*write_text)(
        struct secdisp_driver *driver,
        int16_t x,
        int16_t y,
        uint8_t *text,
        uint16_t cont);
};

struct secdisp_driver {
    uint32_t status;
    struct _SECDISP_INFORMATION* disp_info;
    const struct secdisp_ops *ops;
};

#endif /*__DRIVERS_SECDISP_H*/
