/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include <RiotTarget.h>
#include <RiotStatus.h>
#include <RiotEcc.h>
#include <TcpsId.h>
#include <stdlib.h>
#include <RiotCrypt.h>
#include <cborhelper.h>

//  Stack size of max assertion in a single ID
#define MAX_ASSERTION_COUNT        4


typedef struct _TcpsIdenity {
    TcpsAssertion AssertionArray[MAX_ASSERTION_COUNT];
    uint32_t Used;
} TcpsIdenity;


RIOT_STATUS
pBuildTCPSIdentity(
    TcpsAssertion *Assertions,
    size_t AssertionCount,
    uint8_t *Id,
    uint32_t IdSize,
    uint32_t *Written
)
{
    RIOT_STATUS status = RIOT_FAILURE;
    CborError err;
    CborEncoder encodedId;
    CborEncoder map;
    size_t entryCount = AssertionCount;

    if (AssertionCount == 0 ||
        Assertions == NULL ||
        Written == NULL)
    {
        err = CborUnknownError;
        goto Cleanup;
    }

    memset( Id, 0x0, IdSize );
    cbor_encoder_init( &encodedId, Id, IdSize, 0 );

    CLEANUP_ENCODER_ERR( cbor_encoder_create_map( &encodedId, &map, entryCount ) );

    for (uint32_t i = 0; i < AssertionCount; i++)
    {
        CLEANUP_ENCODER_ERR( cbor_encode_text_stringz( &map, Assertions[i].Name ) );
        if (Assertions[i].DataType == ASSERT_TYPE_BUFFER) 
        {
            CLEANUP_ENCODER_ERR( cbor_encode_byte_string( &map, Assertions[i].Data.Buff.Value, Assertions[i].Data.Buff.Size ) );
        }
        else
        {
            CLEANUP_ENCODER_ERR( cbor_encode_int( &map, Assertions[i].Data.Value ) );
        }
    }

    CLEANUP_ENCODER_ERR( cbor_encoder_close_container( &encodedId, &map ) );

    //
    //  Written will contain the bytes needed on OUTOFMEM
    //

    *Written = (uint32_t)cbor_encoder_get_extra_bytes_needed(&encodedId);
    if (*Written == 0)
    {
        status = RIOT_SUCCESS;
        *Written = (uint32_t)cbor_encoder_get_buffer_size( &encodedId, Id );
    }
    else
    {
        status = RIOT_BAD_FORMAT;
    }

Cleanup:

    return status;
}

CborError
pDecodeAssertionKvP(
    CborValue *KvpValue,
    TcpsAssertion *Assertion
)
{
    CborError err;
    size_t keySize = MAX_ASSERTION_KEY_LEN;

    CLEANUP_DECODER_ERR( cbor_value_get_string_length( KvpValue, &keySize ) );
    if (keySize > MAX_ASSERTION_KEY_LEN) {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }
    CLEANUP_DECODER_ERR( cbor_value_copy_text_string( KvpValue,
                                                      Assertion->Name,
                                                      &keySize, 
                                                      KvpValue ) );

    //
    //  Special case the VERSION. This is the version of the catalog, not a true assertion.
    //  Just store the version on the catalog structure and do not advance the assertion.
    //  N.G: Note that we do not validate the version here as we are just translating structures.
    //

    if (strcmp(TCPS_IDENTITY_MAP_VER, Assertion->Name) == 0) {
        CLEANUP_DECODER_ERR( cbor_value_get_int( KvpValue, &Assertion->Data.Value ) );
        CLEANUP_DECODER_ERR( cbor_value_advance( KvpValue ) );
        Assertion->DataType = ASSERT_TYPE_INT;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR( cbor_value_ref_byte_string( KvpValue,
                                                     &Assertion->Data.Buff.Value,
                                                     (size_t*)&Assertion->Data.Buff.Size,
                                                     KvpValue ) );
    Assertion->DataType = ASSERT_TYPE_BUFFER;

Cleanup:

    return err;
}


CborError
pDecodeTCPSIdentity(
    uint8_t *Id,
    uint32_t IdSize,
    TcpsIdenity *TcpsId
)
{
    CborError       err;
    CborParser      parser;
    CborValue       map;
    CborValue       kvp;
    size_t          len;

    if (TcpsId == NULL) {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }

    err = cbor_parser_init( Id, IdSize, 0, &parser, &map );

    if (err != CborNoError) {
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_map_length( &map, &len ));

    if (len > MAX_ASSERTION_COUNT) {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR( cbor_value_enter_container( &map, &kvp ) );

    for (TcpsId->Used = 0; TcpsId->Used < len; TcpsId->Used++) {
        CLEANUP_DECODER_ERR( pDecodeAssertionKvP( &kvp, &TcpsId->AssertionArray[TcpsId->Used]) );
    }

    CLEANUP_DECODER_ERR( cbor_value_leave_container( &map, &kvp ) );

Cleanup:

    return err;
}


int
pFindAssertion(
    char* Key,
    TcpsAssertion *Assertions,
    uint32_t AssertionCount
)
{
    for (uint32_t i = 0; i < AssertionCount; i++)
    {
        if (strcmp( Assertions[i].Name, Key ) == 0)
        {
            return i;
        }
    }

    return -1;
}


RIOT_STATUS
pAddAssertionBuffer(
    TcpsIdenity *TcpsId,
    char* Key,
    const uint8_t *Value,
    uint32_t ValueSize
)
{
    size_t             index;

    index = pFindAssertion(Key, TcpsId->AssertionArray, TcpsId->Used);
    if (index == -1)
    {
        if (TcpsId->Used == MAX_ASSERTION_COUNT) {
            return RIOT_FAILURE;
        }
        index = TcpsId->Used++;
        memcpy(TcpsId->AssertionArray[index].Name, Key, strlen(Key));
    }
    TcpsId->AssertionArray[index].DataType = ASSERT_TYPE_BUFFER;
    TcpsId->AssertionArray[index].Data.Buff.Value = Value;
    TcpsId->AssertionArray[index].Data.Buff.Size =  ValueSize;

    return RIOT_SUCCESS;
}

RIOT_STATUS
pAddAssertionInteger(
    TcpsIdenity *TcpsId,
    char* Key,
    uint32_t Value
)
{
    size_t             index;

    index = pFindAssertion(Key, TcpsId->AssertionArray, TcpsId->Used);
    if (index == -1)
    {
        if (TcpsId->Used == MAX_ASSERTION_COUNT) {
            return RIOT_FAILURE;
        }
        index = TcpsId->Used++;
        memcpy(TcpsId->AssertionArray[index].Name, Key, strlen(Key));
    }
    TcpsId->AssertionArray[index].DataType = ASSERT_TYPE_INT;
    TcpsId->AssertionArray[index].Data.Value = Value;

    return RIOT_SUCCESS;
}


RIOT_STATUS
pBuildTCPSAssertionTable(
    const RIOT_ECC_PUBLIC *Pub,
    const uint8_t *AuthKeyPub,
    uint32_t AuthKeySize,
    const uint8_t *Fwid,
    uint32_t FwidSize,
    TcpsIdenity *TcpsId,
    uint8_t *Id,
    uint32_t IdSize,
    uint32_t *Written
)
{
    RIOT_STATUS     status;
    uint8_t         encBuffer[65];
    uint32_t        encBufferLen;

    status = pAddAssertionInteger( TcpsId,
                                   TCPS_IDENTITY_MAP_VER,
                                   TCPS_ID_MAP_VER_CURENT );

    if (status != RIOT_SUCCESS) {
        goto Cleanup;
    }

    if (Pub != NULL)
    {
        RiotCrypt_ExportEccPub(Pub, encBuffer, &encBufferLen);
        status = pAddAssertionBuffer( TcpsId, 
                                      TCPS_IDENTITY_MAP_PUBKEY,
                                      encBuffer,
                                      encBufferLen );
        if (status != RIOT_SUCCESS) {
            goto Cleanup;
        }
    }

    if (AuthKeyPub != NULL)
    {
        status = pAddAssertionBuffer( TcpsId,
                                      TCPS_IDENTITY_MAP_AUTH,
                                      AuthKeyPub,
                                      AuthKeySize );
        if (status != RIOT_SUCCESS) {
            goto Cleanup;
        }
    }

    if (FwidSize > 0)
    {
        status = pAddAssertionBuffer( TcpsId,
                                      TCPS_IDENTITY_MAP_FWID,
                                      Fwid,
                                      FwidSize );
        if (status != RIOT_SUCCESS) {
            goto Cleanup;
        }
    }

    status = pBuildTCPSIdentity( TcpsId->AssertionArray,
                                 TcpsId->Used,
                                 Id,
                                 IdSize,
                                 Written );

    if (status != RIOT_SUCCESS) {
        goto Cleanup;
    }

    status = RIOT_SUCCESS;

Cleanup:

    return status;
}


RIOT_STATUS
BuildAliasClaim(
    const uint8_t *AuthKeyPub,
    uint32_t AuthKeySize,
    const uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t *Id,
    uint32_t IdSize,
    uint32_t *Written
)
{
    TcpsIdenity aliasId = { 0 };

    return pBuildTCPSAssertionTable( NULL, 
                                     AuthKeyPub,
                                     AuthKeySize,
                                     Fwid,
                                     FwidSize,
                                     &aliasId,
                                     Id,
                                     IdSize,
                                     Written );
}


RIOT_STATUS
BuildDeviceClaim(
    const RIOT_ECC_PUBLIC *Pub,
    const uint8_t *AuthKeyPub,
    uint32_t AuthKeySize,
    const uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t *Id,
    uint32_t IdSize,
    uint32_t *Written
)
{
    TcpsIdenity deviceId = { 0 };

    return pBuildTCPSAssertionTable( Pub, 
                                     AuthKeyPub,
                                     AuthKeySize,
                                     Fwid,
                                     FwidSize,
                                     &deviceId,
                                     Id,
                                     IdSize,
                                     Written );
}

RIOT_STATUS
ModifyDeviceIdentity(
    uint8_t *ExistingId,
    uint32_t ExistingIdSize,
    RIOT_ECC_PUBLIC *Pub,
    uint8_t *AuthKeyPub,
    uint32_t AuthKeySize,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t *NewId,
    uint32_t NewIdSize,
    uint32_t *Written
)

/*++

Routine Description:

    Modifies an existing TCPS identity blob, by either adding or replaceing idenity
    attributes. Does not allow for removing existing attributes.

    Specifying an attribute will replace an existing value, or add the value. A NULL
    value will be ignored.

Returns:

    On Success:
     - Written: number of bytes written to NewId.

    RIOT_BAD_FORMAT
     - Written: number of bytes required in NewId.

--*/

{
    CborError       err;
    TcpsIdenity     tcpsId = { 0 };

    //
    //  We expect an existing Id that we will modify.
    //

    if (ExistingId == NULL ||
        ExistingIdSize == 0) {
        return RIOT_INVALID_PARAMETER;
    }

    err = pDecodeTCPSIdentity( ExistingId,
                               ExistingIdSize,
                               &tcpsId );

    if (err != CborNoError) {
        return RIOT_FAILURE;
    }

    return pBuildTCPSAssertionTable( Pub, 
                                     AuthKeyPub,
                                     AuthKeySize,
                                     Fwid,
                                     FwidSize,
                                     &tcpsId,
                                     NewId,
                                     NewIdSize,
                                     Written );
}