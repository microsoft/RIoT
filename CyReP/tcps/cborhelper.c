#include "cbor.h"
#include "cborhelper.h"

//
//  NOTE: These wrappers should go away. tinycbor will expose similar APIs
//    to cbor_value_get_****_string_chunk, with improvments for single-chunk strings
//


CborError
cbor_value_ref_byte_string(
    CborValue *Cborstring,
    const uint8_t **Bstr,
    size_t *BstrSize,
    CborValue *Next
)

/*++

Routine Description:

Returns a pointer to the bstr or text str located at Cborstring.
The caller should NOT free the returned buffer.
Advances the Value to the next cbor object.

--*/

{
    CborError err;
    const uint8_t *ptr;
    size_t len;

    if (Cborstring == NULL ||
        Bstr == NULL ||
        BstrSize == NULL ||
        Next == NULL)
    {
        return CborErrorInternalError;
    }

    *Bstr = NULL;
    *BstrSize = 0;

    if (!cbor_value_is_byte_string( Cborstring )) {
        return CborErrorIllegalType;
    }

    while (true)
    {
        err = cbor_value_get_byte_string_chunk( Cborstring, &ptr, &len, Next );

        if (err != CborNoError) {
            return err;
        }

        if (ptr != NULL) {
            // copy out the pointer. As the data is not chunked this should only happen once.
            assert( *Bstr == NULL );
            *Bstr = ptr;
            *BstrSize = len;
            continue;
        }

        // eof. We should already have a valid str.
        if (*Bstr == NULL) {
            return CborErrorInternalError;
        }
        break;
    }

    return err;
}

CborError
cbor_value_ref_text_string(
    CborValue *Cborstring,
    const char **Str,
    size_t *StrSize,
    CborValue *Next
)
{
    CborError err;
    const char *ptr;
    size_t len;

    if (Cborstring == NULL ||
        Str == NULL ||
        StrSize == NULL ||
        Next == NULL)
    {
        return CborErrorInternalError;
    }

    *Str = NULL;
    *StrSize = 0;

    if (!cbor_value_is_text_string( Cborstring )) {
        return CborErrorIllegalType;
    }

    while (true)
    {
        err = cbor_value_get_text_string_chunk( Cborstring, &ptr, &len, Next );

        if (err != CborNoError) {
            return err;
        }

        if (ptr != NULL) {
            // copy out the pointer. As the data is not chunked this should only happen once.
            assert( *Str == NULL );
            *Str = ptr;
            *StrSize = len;
            continue;
        }

        // eof. We should already have a valid str.
        if (*Str == NULL) {
            return CborErrorInternalError;
        }
        break;
    }

    return err;
}