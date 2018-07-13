#include "cbor.h"
#include "cborhelper.h"
#include "extract_number_p.h"

CborError
cbor_value_ref_byte_string(
    CborValue *Cborstring,
    const uint8_t **Bstr,
    uint32_t *BstrSize,
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
    uint64_t len;

    *Bstr = NULL;
    *BstrSize = 0;

    if (Cborstring == NULL ||
        Bstr == NULL ||
        BstrSize == NULL ||
        Next == NULL)
    {
        return CborErrorInternalError;
    }

    if (!cbor_value_is_byte_string(Cborstring) &&
        !cbor_value_is_text_string(Cborstring)) {
        return CborErrorIllegalType;
    }

    // Utilize the API to validate the value as well as obtaining the size.
    err = cbor_value_get_string_length(Cborstring, BstrSize);

    if (err == CborNoError) {
        ptr = Cborstring->ptr;
        extract_number(&ptr, Cborstring->parser->end, &len);
        if (len > 0) {
            *Bstr = ptr;
        }
        assert(*BstrSize == len);
        err = cbor_value_advance(Next);
    }

    return err;
}

CborError
cbor_value_ref_text_string(
    CborValue *Cborstring,
    const uint8_t **Bstr,
    uint32_t *BstrSize,
    CborValue *Next
)
{
    return cbor_value_ref_byte_string(Cborstring, Bstr, BstrSize, Next);
}