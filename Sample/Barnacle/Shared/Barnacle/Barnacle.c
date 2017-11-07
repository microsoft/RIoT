/*
 * Barnacle.c
 *
 *  Created on: Oct 18, 2017
 *      Author: stefanth
 */

#include "main.h"
#include "stm32l4xx_hal.h"
#include "usbd_dfu_if.h"
#include <cyrep/RiotTarget.h>
#include <cyrep/RiotStatus.h>
#include <cyrep/RiotSha256.h>
#include <cyrep/RiotEcc.h>
#include <cyrep/RiotCrypt.h>
#include <cyrep/RiotDerEnc.h>
#include <cyrep/RiotX509Bldr.h>
#include <BarnacleTA.h>
#include <Barnacle.h>

extern RNG_HandleTypeDef hrng;

__attribute__((section(".PURO"))) const BARNACLE_ISSUED_PUBLIC IssuedCerts;
__attribute__((section(".FWRO"))) const BARNACLE_IDENTITY_PRIVATE FwDeviceId;
__attribute__((section(".FWRW"))) const BARNACLE_CACHED_DATA FwCache;

char dfuString[128] = {0};
char* BarnacleGetDfuStr(void)
{
	uint32_t cursor = 0;
	int32_t agentArea = ((uint32_t)&IssuedCerts - (uint32_t)&AgentHdr) / 4096;
	cursor += sprintf(&dfuString[cursor], "@Barnacle /0x%08x/", (unsigned int)&AgentHdr);
	while(agentArea > 0)
	{
		uint32_t iteration = MIN(agentArea, 99);
		cursor += sprintf(&dfuString[cursor], "%02u*004Kf,", (unsigned int)iteration);
		agentArea -= iteration;
	}
	cursor += sprintf(&dfuString[cursor], "01*04K%c", (IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_WRITELOCK) ? 'a' : 'g');
	return dfuString;
}

bool BarnacleInitialProvision()
{
    bool result = true;
    bool generateCerts = false;

    // Check if the platform identity is already provisioned
    if(FwDeviceId.info.magic != BARNACLEMAGIC)
    {
        uint8_t cdi[SHA256_DIGEST_LENGTH] = {0};
        BARNACLE_IDENTITY_PRIVATE newId = {0};

        // Generate a random device Identity from the hardware RNG
        newId.info.magic = BARNACLEMAGIC;
        BarnacleGetRandom(cdi, sizeof(cdi));
        if(!(result = (RiotCrypt_DeriveEccKey(&newId.info.pubKey,
                                             &newId.info.privKey,
                                             cdi, sizeof(cdi),
                                             (const uint8_t *)RIOT_LABEL_IDENTITY,
                                             lblSize(RIOT_LABEL_IDENTITY)) == RIOT_SUCCESS)))
        {
            swoPrint("ERROR: RiotCrypt_DeriveEccKey failed.\r\n");
            goto Cleanup;
        }

        // Persist the identity
        if(!(result = (BarnacleFlashPages((void*)&FwDeviceId, (void*)&newId, sizeof(newId)))))
        {
            swoPrint("ERROR: BarnacleFlashPages failed.\r\n");
            goto Cleanup;
        }

        generateCerts = true;
    }

    // Check if the platform cert are provisioned
    if(generateCerts ||
       (IssuedCerts.info.magic != BARNACLEMAGIC))
    {
        BARNACLE_ISSUED_PUBLIC newCertBag = {0};
        RIOT_X509_TBS_DATA x509TBSData = { { 0 },
                                           "CyReP Device", "Microsoft", "US",
                                           "170101000000Z", "370101000000Z",
                                           "CyReP Device", "Microsoft", "US" };
        DERBuilderContext derCtx = { 0 };
        uint8_t derBuffer[DER_MAX_TBS] = { 0 };
        uint8_t digest[SHA256_DIGEST_LENGTH] = { 0 };
        uint32_t length = 0;
        RIOT_ECC_SIGNATURE  tbsSig = { 0 };

        // Make sure we don't flash unwritten space in the cert bag
        newCertBag.info.magic = BARNACLEMAGIC;
        memset(newCertBag.certBag, 0xff, sizeof(newCertBag.certBag) - 1);

        // Generating self-signed DeviceID certificate
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        if(!(result = (RiotCrypt_Kdf(digest,
                                     sizeof(digest),
                                     (uint8_t*)&FwDeviceId.info.pubKey, sizeof(FwDeviceId.info.pubKey),
                                     NULL, 0,
                                     (const uint8_t *)RIOT_LABEL_SERIAL,
                                     lblSize(RIOT_LABEL_SERIAL),
                                     sizeof(digest)) == RIOT_SUCCESS)))
        {
            swoPrint("ERROR: RiotCrypt_Kdf failed.\r\n");
            goto Cleanup;
        }
        digest[0] &= 0x7F; // Ensure that the serial number is positive
        digest[0] |= 0x01; // Ensure that the serial is not null
        memcpy(x509TBSData.SerialNum, digest, sizeof(x509TBSData.SerialNum));
        if(!(result = (X509GetDeviceCertTBS(&derCtx,
                                           &x509TBSData,
                                           (RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                           (RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                           1) == 0)))
        {
            swoPrint("ERROR: X509GetDeviceCertTBS failed.\r\n");
            goto Cleanup;
        }

        // Self-sign the certificate and finalize it
        if(!(result = (RiotCrypt_Sign(&tbsSig,
                                      derCtx.Buffer,
                                      derCtx.Position,
                                      (RIOT_ECC_PRIVATE*)&FwDeviceId.info.privKey) == RIOT_SUCCESS)))
        {
            swoPrint("ERROR: RiotCrypt_Sign failed.\r\n");
            goto Cleanup;
        }
        if(!(result = (X509MakeDeviceCert(&derCtx, &tbsSig) == 0)))
        {
            swoPrint("ERROR: X509MakeDeviceCert failed.\r\n");
            goto Cleanup;
        }

        // Produce a PEM formatted output from the DER encoded cert
        length = sizeof(newCertBag.certBag) - newCertBag.info.cursor;
        if(!(result = (DERtoPEM(&derCtx, CERT_TYPE, (char*)&newCertBag.certBag[newCertBag.info.cursor], &length) == 0)))
        {
            swoPrint("ERROR: DERtoPEM failed.\r\n");
            goto Cleanup;
        }
        newCertBag.info.certTable[NUMELEM(newCertBag.info.certTable) - 1].start = newCertBag.info.cursor;
        newCertBag.info.certTable[NUMELEM(newCertBag.info.certTable) - 1].size = (uint16_t)length;
        newCertBag.info.cursor += length;
        newCertBag.certBag[newCertBag.info.cursor++] = '\0';

        // Persist the new certBag in flash
        if(!(result = (BarnacleFlashPages((void*)&IssuedCerts, (void*)&newCertBag, sizeof(newCertBag)))))
        {
            swoPrint("ERROR: BarnacleFlashPages failed.\r\n");
            goto Cleanup;
        }
    }

Cleanup:
    return result;
}

bool BarnacleVerifyAgent()
{
    bool result = true;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    RIOT_ECC_SIGNATURE sig = {0};

    // Sniff the header
    if(!(result = ((AgentHdr.s.sign.hdr.magic == BARNACLEMAGIC) &&
                   (AgentHdr.s.sign.hdr.version <= BARNACLEVERSION))))
    {
        swoPrint("ERROR: Invalid agent present.\r\n");
        goto Cleanup;
    }

    // Make sure the agent code starts where we expect it to start
    if(AgentCode != &((uint8_t*)&AgentHdr)[AgentHdr.s.sign.hdr.size])
    {
        swoPrint("ERROR: Unexpected agent start.\r\n");
        goto Cleanup;
    }

    // Verify the agent code digest against the header
    if(!(result = (RiotCrypt_Hash(digest,
                                  sizeof(digest),
                                  AgentCode,
                                  AgentHdr.s.sign.agent.size) == RIOT_SUCCESS)))
    {
        swoPrint("ERROR: RiotCrypt_Hash failed.\r\n");
        goto Cleanup;
    }
    if(!(result = (memcmp(digest, AgentHdr.s.sign.agent.digest, sizeof(digest)) == 0)))
    {
        swoPrint("ERROR: Agent digest mismatch.\r\n");
        goto Cleanup;
    }

	// Calculate the header signature
	if(!(result = (RiotCrypt_Hash(digest,
								  sizeof(digest),
								  (const void*)&AgentHdr.s.sign,
								  sizeof(AgentHdr.s.sign)) == RIOT_SUCCESS)))
	{
		swoPrint("ERROR: RiotCrypt_Hash failed.\r\n");
		goto Cleanup;
	}

	// If authenticated boot is provisioned and enabled
    if((IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_PROVISIONIED) &&
       (IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_AUTHENTICATED_BOOT) &&
       (!BarnacleNullCheck((void*)&IssuedCerts.info.codeAuthPubKey, sizeof(IssuedCerts.info.codeAuthPubKey))))
    {

		//Re-hydrate the signature
		BigIntToBigVal(&sig.r, AgentHdr.s.signature.r, sizeof(AgentHdr.s.signature.r));
		BigIntToBigVal(&sig.s, AgentHdr.s.signature.s, sizeof(AgentHdr.s.signature.s));
		if(!(result = (RiotCrypt_VerifyDigest(digest,
											   sizeof(digest),
											   &sig,
											   &IssuedCerts.info.codeAuthPubKey) == RIOT_SUCCESS)))
		{
			swoPrint("ERROR: RiotCrypt_Verify failed.\r\n");
			goto Cleanup;
		}
    }

    // Is this the first launch after an update?
    if(memcmp(digest, FwCache.info.agentHdrDigest, sizeof(digest)))
    {
        RIOT_X509_TBS_DATA x509TBSData = { { 0 },
                                           "CyReP Device", "Microsoft", "US",
                                           "170101000000Z", "370101000000Z",
                                           AgentHdr.s.sign.agent.name, NULL, NULL };
        DERBuilderContext derCtx = { 0 };
        uint8_t derBuffer[DER_MAX_TBS] = { 0 };
        uint32_t length = 0;
        RIOT_ECC_SIGNATURE  tbsSig = { 0 };
        BARNACLE_CACHED_DATA cache = {0};

        // Detect rollback attack
        if((FwCache.info.lastVersion >= AgentHdr.s.sign.agent.version) ||
           (FwCache.info.lastIssued >= AgentHdr.s.sign.agent.issued))
        {
    		fprintf(stderr,
    				"ERROR: Roll-back attack detected. Issuance: %u < %u Version: %hu.%hu < %hu.%hu\r\n",
					(unsigned int)FwCache.info.lastIssued, (unsigned int)AgentHdr.s.sign.agent.issued,
					(short unsigned int)FwCache.info.lastVersion >> 16, (short unsigned int)FwCache.info.lastVersion & 0x0000ffff, (short unsigned int)AgentHdr.s.sign.agent.version >> 16, (short unsigned int)AgentHdr.s.sign.agent.version % 0x0000ffff);
    		goto Cleanup;
        }

        memset(cache.cert, 0xff, sizeof(cache.cert));
        memcpy(cache.info.agentHdrDigest, digest, sizeof(digest));

        // Derive the agent compound key
        if(!(result = (RiotCrypt_DeriveEccKey(&cache.info.compoundPubKey,
                                              &cache.info.compoundPrivKey,
                                              digest, sizeof(digest),
                                              (const uint8_t *)RIOT_LABEL_IDENTITY,
                                              lblSize(RIOT_LABEL_IDENTITY)) == RIOT_SUCCESS)))
        {
            swoPrint("ERROR: RiotCrypt_DeriveEccKey failed.\r\n");
            goto Cleanup;
        }

        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        if(!(result = (RiotCrypt_Kdf(digest,
                                     sizeof(digest),
                                     (uint8_t*)&cache.info.compoundPubKey, sizeof(cache.info.compoundPubKey),
                                     NULL, 0,
                                     (const uint8_t *)RIOT_LABEL_SERIAL,
                                     lblSize(RIOT_LABEL_SERIAL),
                                     sizeof(digest)) == RIOT_SUCCESS)))
        {
            swoPrint("ERROR: RiotCrypt_Kdf failed.\r\n");
            goto Cleanup;
        }
        digest[0] &= 0x7F; // Ensure that the serial number is positive
        digest[0] |= 0x01; // Ensure that the serial is not null
        memcpy(x509TBSData.SerialNum, digest, sizeof(x509TBSData.SerialNum));
        if(!(result = (X509GetAliasCertTBS(&derCtx,
                                           &x509TBSData,
                                           (RIOT_ECC_PUBLIC*)&cache.info.compoundPubKey,
                                           (RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                           (uint8_t*)AgentHdr.s.sign.agent.digest,
                                           sizeof(AgentHdr.s.sign.agent.digest),
                                           1) == 0)))
        {
            swoPrint("ERROR: X509GetAliasCertTBS failed.\r\n");
            goto Cleanup;
        }

        // Sign the agent compound key Certificate's TBS region
        if(!(result = (RiotCrypt_Sign(&tbsSig,
                                      derCtx.Buffer,
                                      derCtx.Position,
                                      &FwDeviceId.info.privKey) == RIOT_SUCCESS)))
        {
            swoPrint("ERROR: RiotCrypt_Sign failed.\r\n");
            goto Cleanup;
        }

        // Generate compound key Certificate
        if(!(result = (X509MakeAliasCert(&derCtx, &tbsSig) == 0)))
        {
            swoPrint("ERROR: X509MakeAliasCert failed.\r\n");
            goto Cleanup;
        }

        // Copy compound key Certificate
        length = sizeof(cache.cert);
        if(!(result = (DERtoPEM(&derCtx, CERT_TYPE, (char*)cache.cert, &length) == 0)))
        {
            swoPrint("ERROR: DERtoPEM failed.\r\n");
            goto Cleanup;
        }
        cache.info.compoundCertSize = length;
        cache.cert[cache.info.compoundCertSize] = '\0';

        cache.info.lastIssued = AgentHdr.s.sign.agent.issued;
        cache.info.lastVersion = AgentHdr.s.sign.agent.version;

        // Persist the new certBag in flash
        if(!(result = (BarnacleFlashPages((void*)&FwCache, (void*)&cache, sizeof(cache)))))
        {
            swoPrint("ERROR: BarnacleFlashPages failed.\r\n");
            goto Cleanup;
        }
    }

    // Copy the cached identity and cert to the cert store
    CompoundId.info.magic = BARNACLEMAGIC;
    memcpy(&CompoundId.info.pubKey, &FwCache.info.compoundPubKey, sizeof(CompoundId.info.pubKey));
    memcpy(&CompoundId.info.privKey, &FwCache.info.compoundPrivKey, sizeof(CompoundId.info.privKey));
    memset(&CertStore, 0x00, sizeof(CertStore));
    CertStore.info.magic = BARNACLEMAGIC;

    // Issued Root
    if((CertStore.info.cursor + IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size) >  sizeof(CertStore.certBag))
    {
        swoPrint("ERROR: Certstore overflow BARNACLE_ISSUED_ROOT.\r\n");
        goto Cleanup;
    }
    if((IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_PROVISIONIED) &&
       (IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size != 0))
    {
    	memcpy(&CertStore.certBag[CertStore.info.cursor],
    		   &IssuedCerts.certBag[IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].start],
			   IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size);
    	CertStore.info.certTable[BARNACLE_CERTSTORE_ROOT].start = CertStore.info.cursor;
    	CertStore.info.certTable[BARNACLE_CERTSTORE_ROOT].size = IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size;
    	CertStore.info.cursor += IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size;
    	CertStore.certBag[CertStore.info.cursor++] = '\0';
    }

    // Issued or generated device
    if((CertStore.info.cursor + IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].size) >  sizeof(CertStore.certBag))
    {
        swoPrint("ERROR: Certstore overflow BARNACLE_ISSUED_DEVICE.\r\n");
        goto Cleanup;
    }
	memcpy(&CertStore.certBag[CertStore.info.cursor],
		   &IssuedCerts.certBag[IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].start],
		   IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].size);
	CertStore.info.certTable[BARNACLE_CERTSTORE_DEVICE].start = CertStore.info.cursor;
	CertStore.info.certTable[BARNACLE_CERTSTORE_DEVICE].size = IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].size;
	CertStore.info.cursor += IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].size;
	CertStore.certBag[CertStore.info.cursor++] = '\0';

	// Cached loader
    if((CertStore.info.cursor + FwCache.info.compoundCertSize) >  sizeof(CertStore.certBag))
    {
        swoPrint("ERROR: Certstore overflow BARNACLE_CERTSTORE_LOADER.\r\n");
        goto Cleanup;
    }
	memcpy(&CertStore.certBag[CertStore.info.cursor],
		   FwCache.cert,
		   FwCache.info.compoundCertSize);
	CertStore.info.certTable[BARNACLE_CERTSTORE_LOADER].start = CertStore.info.cursor;
	CertStore.info.certTable[BARNACLE_CERTSTORE_LOADER].size = FwCache.info.compoundCertSize;
	CertStore.info.cursor += FwCache.info.compoundCertSize;
	CertStore.certBag[CertStore.info.cursor++] = '\0';

Cleanup:
    return result;
}
