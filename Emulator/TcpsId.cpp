/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include "TcpsId.h"
#include <cbor.h>
#include <stdlib.h>
#include <RiotCrypt.h>


// Ignore OutOfMemory to allow CBOR to gather size requirements.
#define CLEANUP_ON_BUILD_ERR(_e) \
    err = _e; \
    if(err != CborErrorOutOfMemory && \
       err != CborNoError) \
    { goto Cleanup; }


#define MAX_ALIAS_PROP_COUNT        2
#define MAX_DEVICE_PROP_COUNT       3


void
FreeTCPSId(
    uint8_t *Id
)
{
    if (Id != NULL)
    {
        free( Id );
    }
}

CborError
pBuildTCPSIdentity(
    TcpsAssertion *Assertions,
    uint32_t AssertionCount,
    uint8_t *Id,
    uint32_t IdSize,
    uint32_t *SizeNeeded
)
{
    CborError err;
    CborEncoder encodedId;
    CborEncoder map;
    uint32_t entryCount = AssertionCount;

    if (AssertionCount == 0 ||
        Assertions == NULL ||
        SizeNeeded == NULL)
    {
        err = CborUnknownError;
        goto Cleanup;
    }

    // Always include version
    entryCount++;

    cbor_encoder_init( &encodedId, Id, IdSize, 0 );

    CLEANUP_ON_BUILD_ERR( cbor_encoder_create_map( &encodedId, &map, entryCount ) );

    CLEANUP_ON_BUILD_ERR( cbor_encode_text_stringz( &map, TCPS_IDENTITY_MAP_VER ) );
    CLEANUP_ON_BUILD_ERR( cbor_encode_int( &map, TCPS_ID_MAP_VER_CURENT ) );

    for (uint32_t i = 0; i < AssertionCount; i++)
    {
        CLEANUP_ON_BUILD_ERR( cbor_encode_text_stringz( &map, Assertions[i].Name ) );
        CLEANUP_ON_BUILD_ERR( cbor_encode_byte_string( &map, Assertions[i].Data, Assertions[i].DataSize ) );
    }

    CLEANUP_ON_BUILD_ERR( cbor_encoder_close_container( &encodedId, &map ) );

    *SizeNeeded = (uint32_t) cbor_encoder_get_extra_bytes_needed( &encodedId );

    err = (*SizeNeeded != 0) ? CborErrorOutOfMemory : CborNoError;

Cleanup:

    return err;
}


RIOT_STATUS
pAllocAndBuildIdentity(
    TcpsAssertion *Assertions,
    uint32_t AssertionCount,
    uint8_t **Id,
    uint32_t *IdSize
)
{
    RIOT_STATUS     status = RIOT_FAILURE;
    CborError       err;
    uint8_t         *localId = NULL;
    uint32_t        localIdSize = 0;
    uint32_t        sizeNeeded;

    if (AssertionCount == 0 ||
        Assertions == NULL ||
        Id == NULL ||
        IdSize == NULL )
    {
        status = RIOT_INVALID_PARAMETER;
        goto Cleanup;
    }

    err = pBuildTCPSIdentity( Assertions,
        AssertionCount,
        NULL,
        0,
        &sizeNeeded );
    if (err != CborErrorOutOfMemory)
    {
        goto Cleanup;
    }

    localId = (uint8_t*)malloc( sizeNeeded );
    localIdSize = sizeNeeded;
    memset( localId, 0x00, localIdSize );
    sizeNeeded = 0;

    err = pBuildTCPSIdentity( Assertions,
        AssertionCount,
        localId,
        localIdSize,
        &sizeNeeded );
    if (err != CborNoError)
    {
        goto Cleanup;
    }

    //
    //  Success.
    //  We can now free the incoming buffer if it is already allocated.
    //  Only do this now in order to preserve the callers state on failure.
    //

    status = RIOT_SUCCESS;

    if (*Id != NULL)
    {
        FreeTCPSId( *Id );
    }

    *Id = localId;
    localId = NULL;
    *IdSize = localIdSize;

Cleanup:

    FreeTCPSId( localId );
    return status;
}


RIOT_STATUS
BuildTCPSAliasIdentity(
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **Id,
    uint32_t *IdSize
)
{
    TcpsAssertion   aliasAssertion[MAX_ALIAS_PROP_COUNT];
    uint32_t        count = 0;
    uint8_t         authBuffer[65];
    uint32_t        authBufferLen;

    if (AuthKeyPub != NULL)
    {
        RiotCrypt_ExportEccPub(AuthKeyPub, authBuffer, &authBufferLen);
        aliasAssertion[count].Data = authBuffer;
        aliasAssertion[count].DataSize = authBufferLen;
        aliasAssertion[count].Name = TCPS_IDENTITY_MAP_AUTH;
        count++;
    }

    if (FwidSize > 0)
    {
        aliasAssertion[count].Data = Fwid;
        aliasAssertion[count].DataSize = FwidSize;
        aliasAssertion[count].Name = TCPS_IDENTITY_MAP_FWID;
        count++;
    }

    assert( count <= MAX_ALIAS_PROP_COUNT );

    return pAllocAndBuildIdentity( aliasAssertion,
        count,
        Id,
        IdSize );
}


RIOT_STATUS
BuildTCPSDeviceIdentity(
    RIOT_ECC_PUBLIC *Pub,
    RIOT_ECC_PUBLIC *AuthKeyPub,
    uint8_t *Fwid,
    uint32_t FwidSize,
    uint8_t **Id,
    uint32_t *IdSize
)
{
    TcpsAssertion   aliasAssertion[MAX_DEVICE_PROP_COUNT];
    uint32_t        count = 0;
    uint8_t         encBuffer[65];
    uint32_t        encBufferLen;
    uint8_t         authBuffer[65];
    uint32_t        authBufferLen;

    RiotCrypt_ExportEccPub(Pub, encBuffer, &encBufferLen);
    aliasAssertion[count].Data = encBuffer;
    aliasAssertion[count].DataSize = encBufferLen;
    aliasAssertion[count].Name = TCPS_IDENTITY_MAP_PUBKEY;
    count++;

    if (AuthKeyPub != NULL)
    {
        RiotCrypt_ExportEccPub(AuthKeyPub, authBuffer, &authBufferLen);
        aliasAssertion[count].Data = authBuffer;
        aliasAssertion[count].DataSize = authBufferLen;
        aliasAssertion[count].Name = TCPS_IDENTITY_MAP_AUTH;
        count++;
    }

    if (FwidSize > 0)
    {
        aliasAssertion[count].Data = Fwid;
        aliasAssertion[count].DataSize = FwidSize;
        aliasAssertion[count].Name = TCPS_IDENTITY_MAP_FWID;
        count++;
    }

    assert( count <= MAX_DEVICE_PROP_COUNT );

    return pAllocAndBuildIdentity( aliasAssertion,
        count,
        Id,
        IdSize );
}