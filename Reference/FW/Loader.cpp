/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include "stdafx.h"

// There are lots of ways to force a new FWID value. However, to
// maintain a consistent FWID value accross "boots", the default
// linker option that randomizes base addresses must be disabled.

FW_API void FirmwareEntry(
    char             *r00tCert,
    ecc_publickey    *DeviceIDPub,
    char             *DeviceCert,
    ecc_publickey    *AliasKeyPub,
    ecc_privatekey   *AliasKeyPriv,
    char             *AliasKeyCert
)
{
    UINT32 i;

    printf("FW: Begin.\n");
    printf("FW: AliasKeyPub:\n\tx: ");
    for (i = 0; i < ((BIGLEN)-1); i++) {
        printf("%08X", AliasKeyPub->x.data[i]);
    }
    printf("\n\ty: ");
    for (i = 0; i < ((BIGLEN)-1); i++) {
        printf("%08X", AliasKeyPub->y.data[i]);
    }
    printf("\nFW: AliasKeyPriv:\n\t   ");
    for (i = 0; i < ((BIGLEN)-1); i++) {
        printf("%08X", AliasKeyPriv->data[i]);
    }

    printf("\nFW: r00tCertificate:\n %s", r00tCert);
    printf("\nFW: DeviceCertificate:\n %s", DeviceCert);
    printf("\nFW: AliasKeyCertificate:\n %s", AliasKeyCert);

    i = 5;
    do {
        printf("\rFW: \"Running\" \\");
        Sleep(100);
        printf("\rFW: \"Running\" |");
        Sleep(100);
        printf("\rFW: \"Running\" /");
        Sleep(100);
        printf("\rFW: \"Running\" -");
        Sleep(100);
    } while (i--);
    
    printf("\nFW: Reboot!\n");
    Sleep(300);
	return;
}
