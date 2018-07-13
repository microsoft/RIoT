#pragma once

#include <cbor.h>

#ifdef __cplusplus
extern "C" {
#endif

//
//  CBOR error macro to maintain an OutOfMemory state
//  when encoding a CBOR object.
//

#define CLEANUP_ENCODER_ERR(_e) \
    err = _e; \
    if (err != CborErrorOutOfMemory && \
       err != CborNoError) \
    { goto Cleanup; }

#define CLEANUP_DECODER_ERR(_e) \
    err = (_e); \
    if (err != CborNoError) \
    { goto Cleanup; }

CborError
cbor_value_ref_byte_string(
    CborValue *Cborstring,
    const uint8_t **Bstr,
    uint32_t *BstrSize,
    CborValue *Next
);

CborError
cbor_value_ref_text_string(
    CborValue *Cborstring,
    const uint8_t **Bstr,
    uint32_t *BstrSize,
    CborValue *Next
);

#ifdef __cplusplus
}
#endif
