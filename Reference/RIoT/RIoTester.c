/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */

#include <stdio.h>
#include <string.h>
#include <RiotCrypt.h>

const char *str0 = "abc";
const char *str1 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

// HASH/HMAC
// SHA1 is "internal only" but we verify it here anyway
const uint8_t str0_sha1[SHA1_DIGEST_LENGTH] =   {0xa9, 0x99, 0x3e, 0x36, 
                                                 0x47, 0x06, 0x81, 0x6a,
                                                 0xba, 0x3e, 0x25, 0x71, 
                                                 0x78, 0x50, 0xc2, 0x6c, 
                                                 0x9c, 0xd0, 0xd8, 0x9d};
const uint8_t str0_sha256[RIOT_DIGEST_LENGTH] = {0xba, 0x78, 0x16, 0xbf, 
                                                 0x8f, 0x01, 0xcf, 0xea,
                                                 0x41, 0x41, 0x40, 0xde,
                                                 0x5d, 0xae, 0x22, 0x23,
                                                 0xb0, 0x03, 0x61, 0xa3,
                                                 0x96, 0x17, 0x7a, 0x9c,
                                                 0xb4, 0x10, 0xff, 0x61,
                                                 0xf2, 0x00, 0x15, 0xad};
const uint8_t str1_sha1[SHA1_DIGEST_LENGTH] =   {0x84, 0x98, 0x3E, 0x44,
                                                 0x1C, 0x3B, 0xD2, 0x6E,
                                                 0xBA, 0xAE, 0x4A, 0xA1,
                                                 0xF9, 0x51, 0x29, 0xE5,
                                                 0xE5, 0x46, 0x70, 0xF1};
const uint8_t str1_sha256[RIOT_DIGEST_LENGTH] = {0x24, 0x8D, 0x6A, 0x61,
                                                 0xD2, 0x06, 0x38, 0xB8,
                                                 0xE5, 0xC0, 0x26, 0x93,
                                                 0x0C, 0x3E, 0x60, 0x39,
                                                 0xA3, 0x3C, 0xE4, 0x59,
                                                 0x64, 0xFF, 0x21, 0x67,
                                                 0xF6, 0xEC, 0xED, 0xD4,
                                                 0x19, 0xDB, 0x06, 0xC1};
const uint8_t strc_sha256[RIOT_DIGEST_LENGTH] = {0xAE, 0x1D, 0xC6, 0xDF,
                                                 0xAA, 0x79, 0x81, 0x2E,
                                                 0xB3, 0xF4, 0xD2, 0xB7,
                                                 0xAE, 0xA0, 0x2E, 0xD0,
                                                 0xDE, 0xB3, 0xE8, 0x86,
                                                 0x64, 0x7B, 0xB2, 0xF3,
                                                 0x48, 0x28, 0x19, 0xCA,
                                                 0x53, 0xC8, 0xCB, 0x9D};

// HKDF
const uint8_t hkIKM[22]  = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
const uint8_t hkCtx[13]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
const uint8_t hkInf[10]  = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
const uint8_t hkBTS[42]  = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
                            0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
                            0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
                            0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

// ecc
const uint8_t pubX[RIOT_COORDMAX]   = {0x68, 0xF1, 0x0D, 0x9A, 0xEF, 0x2C, 0x02, 0xF9, 0x3D, 
                                       0x6F, 0x82, 0xB4, 0x34, 0x07, 0x1C, 0x17, 0xD5, 0x2C,
                                       0x75, 0xE4, 0x3C, 0x4D, 0x18, 0x10, 0x10, 0xDC, 0x4B,
                                       0x2B, 0x33, 0x48, 0x2D, 0x80};
const uint8_t pubY[RIOT_COORDMAX]   = {0x9A, 0x5F, 0x2B, 0x3D, 0xF4, 0x2E, 0xA1, 0xE1, 0x5D,
                                       0xD3, 0x66, 0xCA, 0xB5, 0x99, 0x09, 0x58, 0x99, 0x8B,
                                       0x68, 0x79, 0xFA, 0xBC, 0xC9, 0x84, 0xDD, 0x30, 0x23,
                                       0xFC, 0x08, 0xB5, 0x78, 0xF2};
const uint8_t privD[RIOT_COORDMAX]  = {0xF3, 0x0F, 0x86, 0x2B, 0x66, 0xAD, 0x64, 0xF3, 0x40,
                                       0x29, 0x39, 0xC1, 0x11, 0x7C, 0x31, 0xCB, 0x56, 0x19,
                                       0xE6, 0x3E, 0xAE, 0x11, 0xF2, 0xE1, 0x1E, 0xC1, 0x19,
                                       0x9D, 0x90, 0x7F, 0x04, 0x23};

// sign
const uint8_t sigR[RIOT_COORDMAX]   = {0xBC, 0xD2, 0xAC, 0x06, 0xA4, 0x44, 0xCF, 0x23, 0xAD,
                                       0x7F, 0x39, 0xDC, 0xA5, 0xFD, 0x6E, 0xF9, 0x9F, 0x38,
                                       0xC8, 0x36, 0x98, 0x5D, 0xC8, 0x8D, 0xDD, 0x6F, 0x94,
                                       0x90, 0x8B, 0x17, 0x31, 0x91};
const uint8_t sigS[RIOT_COORDMAX]   = {0x52, 0x00, 0x9B, 0x1B, 0xB0, 0x43, 0xC9, 0xA3, 0x22,
                                       0x4A, 0xDF, 0x88, 0x18, 0x2A, 0x0D, 0x9E, 0x02, 0x98,
                                       0xB6, 0x17, 0x44, 0x58, 0xB3, 0x97, 0xF7, 0xDD, 0x79,
                                       0xF3, 0x2B, 0x74, 0x33, 0xEA};

//signdigest
const uint8_t sgdR[RIOT_COORDMAX]   = {0x40, 0x45, 0x42, 0xCF, 0xC5, 0xF6, 0x54, 0xCE, 0xC5,
                                       0xC8, 0x78, 0x55, 0xB6, 0x2C, 0xC2, 0xDA, 0xA6, 0x31,
                                       0x26, 0x8C, 0x14, 0x11, 0x27, 0xC5, 0x5D, 0x84, 0x8F,
                                       0xB1, 0x55, 0x8A, 0xC6, 0xB9};
const uint8_t sgdS[RIOT_COORDMAX]   = {0xCB, 0x5B, 0x70, 0xD7, 0xF0, 0xDE, 0x59, 0xB9, 0xBB,
                                       0xFB, 0xEA, 0xA0, 0xE1, 0x12, 0xAF, 0x19, 0x04, 0x63,
                                       0x29, 0x10, 0x11, 0x5A, 0xBB, 0xBA, 0x08, 0x5A, 0x24,
                                       0xB1, 0x5F, 0xC0, 0x3D, 0xF6};

void tohex(uint8_t *bin, size_t binLen, char *str, size_t strLen);

int
main(void)
{
    uint8_t digest0[RIOT_DIGEST_LENGTH] = { 0 };
    uint8_t digest1[RIOT_DIGEST_LENGTH] = { 0 };
    uint8_t kdfbytes[42] = {0};
    uint8_t *ptr;
    uint32_t i;

    // SHA1 is an "internal only" function but validate it anyway
    mbedtls_sha1_ret((uint8_t *)str0, strlen(str0), digest0);
    mbedtls_sha1_ret((uint8_t *)str1, strlen(str1), digest1);

    if (memcmp(digest0, str0_sha1, SHA1_DIGEST_LENGTH))
        goto error;

    if (memcmp(digest1, str1_sha1, SHA1_DIGEST_LENGTH))
        goto error;

    // RiotCrypt_Hash
    printf("RiotCrypt_Hash: ");
    if(RiotCrypt_Hash(digest0, sizeof(digest0), str0, strlen(str0)))
        goto error;

    if (memcmp(digest0, str0_sha256, RIOT_DIGEST_LENGTH))
        goto error;

    if(RiotCrypt_Hash(digest0, sizeof(digest0), str1, strlen(str1)))
        goto error;

    if (memcmp(digest0, str1_sha256, RIOT_DIGEST_LENGTH))
        goto error;

    printf("\t\tPASSED\n");

    // RiotCrypt_Hash2
    printf("RiotCrypt_Hash2: ");
    if(RiotCrypt_Hash2(digest0, sizeof(digest0), str0, strlen(str0), str1, strlen(str1)))
        goto error;

    if (memcmp(digest0, strc_sha256, RIOT_DIGEST_LENGTH))
        goto error;

    printf("\t\tPASSED\n");

    // RiotCrypt_Hmac
    printf("RiotCrypt_Hmac: ");
    if(RiotCrypt_Hmac(digest0, sizeof(digest0), str0, strlen(str0), (uint8_t *)str1, strlen(str1)))
        goto error;

    if(RiotCrypt_Hmac(digest1, sizeof(digest0), str0, strlen(str0), (uint8_t *)str1, strlen(str1)))
        goto error;

    if (memcmp(digest0, digest1, RIOT_DIGEST_LENGTH))
        goto error;

    printf("\t\tPASSED\n");

    // RiotCrypt_Hmac2
    printf("RiotCrypt_Hmac2: ");
    if(RiotCrypt_Hmac2(digest0, sizeof(digest0), str0, strlen(str0), str0_sha256, sizeof(str0_sha256), (uint8_t *)str1, strlen(str1)))
        goto error;

    if(RiotCrypt_Hmac2(digest1, sizeof(digest0), str0, strlen(str0), str0_sha256, sizeof(str0_sha256), (uint8_t *)str1, strlen(str1)))
        goto error;

    if (memcmp(digest0, digest1, RIOT_DIGEST_LENGTH))
        goto error;

    printf("\t\tPASSED\n");

    // RiotCrypt_Kdf
    printf("RiotCrypt_Kdf: ");
    if(RiotCrypt_Kdf(kdfbytes, sizeof(kdfbytes),
                     hkIKM, sizeof(hkIKM),
                     hkCtx, sizeof(hkCtx), 
                     hkInf, sizeof(hkInf),
                     sizeof(kdfbytes)))
        goto error;

    if (memcmp(kdfbytes, hkBTS, sizeof(hkBTS)))
        goto error;
        
    printf("\t\t\tPASSED\n");

    // RiotCrypt_SeedDRBG
    printf("RiotCrypt_SeedDRBG: ");
    if (RiotCrypt_SeedDRBG(str0_sha256, sizeof(str0_sha256), NULL, 0))
        goto error;

    printf("\t\tPASSED\n");

    // RiotCrypt_Random
    printf("RiotCrypt_Random: ");
    if (RiotCrypt_Random(digest0, sizeof(digest0)))
        goto error;

    printf("\t\tPASSED\n");

    // RiotCrypt_DeriveEccKey

    RIOT_ECC_PUBLIC pub;
    RIOT_ECC_PRIVATE priv;
    uint8_t bin[RIOT_COORDMAX * 2 + 1];
    char str[1024];
    uint32_t len;
    char x[128], y[128], d[128];
    size_t size;
    char *asd = "TESTKE";

    printf("RiotCrypt_DeriveEccKey: ");
    if(RiotCrypt_DeriveEccKey(&pub, &priv, digest0, sizeof(digest0), (uint8_t *)asd, 6))
        goto error;

    if(mbedtls_mpi_size(&pub.X) > RIOT_COORDMAX)
       goto error;
        
    mbedtls_mpi_write_binary(&pub.X, bin, RIOT_COORDMAX);
    if(memcmp(pubX, bin, RIOT_COORDMAX))
       goto error;

    if(mbedtls_mpi_size(&pub.Y) > RIOT_COORDMAX)
       goto error;

    mbedtls_mpi_write_binary(&pub.Y, bin, RIOT_COORDMAX);
    if(memcmp(pubY, bin, RIOT_COORDMAX))
       goto error;

    if(mbedtls_mpi_size(&priv) > RIOT_COORDMAX)
        goto error;

    mbedtls_mpi_write_binary(&priv, bin, RIOT_COORDMAX);
    if(memcmp(privD, bin, RIOT_COORDMAX))
            goto error;

    // Includes '\0'!
    mbedtls_mpi_write_string(&pub.X, 16, x, 128, &size);
    if((size -1) > (RIOT_COORDMAX * 2))
        goto error;

    // Includes '\0'!
    mbedtls_mpi_write_string(&pub.Y, 16, y, 128, &size);
    if((size -1) > (RIOT_COORDMAX * 2))
        goto error;

    // Includes '\0'!
    mbedtls_mpi_write_string(&priv, 16, d, 128, &size);
    if((size -1) > (RIOT_COORDMAX * 2))
        goto error;
    printf("\tPASSED\n");

    size--;

    printf("RiotCrypt_ExportEccPub: ");
    len = sizeof(bin);
    if(RiotCrypt_ExportEccPub(&pub, bin, &len))
        goto error;

    // tag
    if (bin[0] != 0x04)
        goto error;

    // bin output to hex
    tohex(&(bin[1]), RIOT_COORDMAX*2, str, 1024);
    if(memcmp(x, str, size) || memcmp(y, &str[size], size))
        goto error;
    printf("\tPASSED\n");

    RIOT_ECC_SIGNATURE sig0;
    printf("RiotCrypt_Sign: ");
    if(RiotCrypt_Sign(&sig0, str1, strlen(str1), &priv))
        goto error;

    if(mbedtls_mpi_size(&sig0.r) > RIOT_COORDMAX)
        goto error;

    mbedtls_mpi_write_binary(&sig0.r, bin, RIOT_COORDMAX);
    if(memcmp(sigR, bin, RIOT_COORDMAX))
        goto error;

    if(mbedtls_mpi_size(&sig0.s) > RIOT_COORDMAX)
        goto error;

    mbedtls_mpi_write_binary(&sig0.s, bin, RIOT_COORDMAX);
    if(memcmp(sigS, bin, RIOT_COORDMAX))
        goto error;

//  // Includes '\0'!
//  mbedtls_mpi_write_string(&sig0.r, 16, x, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      goto error;
//
//  printf("r: %s\n", x);
//
//  mbedtls_mpi_write_string(&sig0.s, 16, x, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      goto error;
//
//  printf("s: %s\n", x);
    printf("\t\tPASSED\n");

    RIOT_ECC_SIGNATURE sig1;
    printf("RiotCrypt_SignDigest: ");
    if(RiotCrypt_SignDigest(&sig1, str0_sha256, sizeof(str0_sha256), &priv))
        goto error;

    if(mbedtls_mpi_size(&sig1.r) > RIOT_COORDMAX)
        goto error;

    mbedtls_mpi_write_binary(&sig1.r, bin, RIOT_COORDMAX);
    if(memcmp(sgdR, bin, RIOT_COORDMAX))
        goto error;

    if(mbedtls_mpi_size(&sig1.s) > RIOT_COORDMAX)
        goto error;

    mbedtls_mpi_write_binary(&sig1.s, bin, RIOT_COORDMAX);
    if(memcmp(sgdS, bin, RIOT_COORDMAX))
        goto error;

//  // Includes '\0'!
//  mbedtls_mpi_write_string(&sig1.r, 16, x, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      goto error;
//
//  printf("r: %s\n", x);
//
//  mbedtls_mpi_write_string(&sig1.s, 16, x, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      goto error;
//
//  printf("s: %s\n", x);
//
//  mbedtls_mpi_write_string(&pub.Y, 16, y, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      goto error;
    printf("\t\tPASSED\n");

    printf("RiotCrypt_Verify: ");
    if(RiotCrypt_Verify(str1, strlen(str1), &sig0, &pub))
        goto error;

    printf("\t\tPASSED\n");

    printf("RiotCrypt_VerifyDigest: ");
    if(RiotCrypt_VerifyDigest(str0_sha256, sizeof(str0_sha256), &sig1, &pub))
        goto error;
        
    printf("\tPASSED\n");

//  for(uint32_t i = 0; i < sizeof(kdfbytes); i++)
//      printf("%X", kdfbytes[i]);

    printf("RiotCrypt_SymEncryptDecrypt: ");
    char *ptxt = "*             The per-message nonce (or information sufficient to reconstruct\n"
                 "*             it) needs to be communicated with the ciphertext and must be unique.\n"
                 "*             The recommended way to ensure uniqueness is to use a message\n"
                 "*             counter. An alternative is to generate random nonces, but this\n"
                 "*             limits the number of messages that can be securely encrypted:\n"
                 "*             for example, with 96-bit random nonces, you should not encrypt\n"
                 "*             more than 2**32 messages with the same key.\n"; 
    unsigned char out0[1024];
    unsigned char out1[1024];
    uint32_t olen = 1024;
 
    if(RiotCrypt_SymEncryptDecrypt(out0, olen, ptxt, strlen(ptxt) + 1, (uint8_t *)str0_sha256))
        goto error;

//  for(i = 0; i < strlen(ptxt); i++)
//  {
//      if(!(i % 37))
//          printf("\n\t");
//      printf("%02X", out0[i]);
//  }
//  printf("\n");

    if(RiotCrypt_SymEncryptDecrypt(out1, olen, out0, strlen(ptxt) + 1, (uint8_t *)str0_sha256))
        goto error;

//  printf("%s\n", out1);

    if(memcmp(ptxt, out1, (strlen(ptxt) + 1)))
        goto error;

    printf("\tPASSED\n");

    printf("RiotCrypt_EccEncrypt: ");
    RIOT_ECC_PUBLIC eph;
    RIOT_ECC_PUBLIC pub0;
    RIOT_ECC_PUBLIC pub1;
    RIOT_ECC_PRIVATE priv0;
    RIOT_ECC_PRIVATE priv1;
    olen = 1024;

    memset(out0, 0, sizeof(out0));
    memset(out1, 0, sizeof(out1));

    // Derive initial keypair for both parties
    if(RiotCrypt_DeriveEccKey(&pub0, &priv0, str0_sha256, sizeof(str0_sha256), NULL, 0))
        goto error;

    if(RiotCrypt_DeriveEccKey(&pub1, &priv1, str1_sha256, sizeof(str1_sha256), NULL, 0))
        goto error;

    // Sender: Encrypt using shared secret and receiver's public key
    if(RiotCrypt_EccEncrypt(out0, olen, &eph, ptxt, strlen(ptxt) + 1, &pub1))
        goto error;

    printf("\t\tPASSED\n");

//  for(i = 0; i < strlen(ptxt); i++)
//  {
//      if(!(i % 37))
//          fprintf(stderr, "\n\t");
//      fprintf(stderr, "%02X", out0[i]);
//  }
//  fprintf(stderr, "\n");

    printf("RiotCrypt_EccDecrypt: ");
    // Receiver: Decrypt, derived shared secret and own private key
    if(RiotCrypt_EccDecrypt(out1, olen, out0, strlen(ptxt) + 1, &eph, &priv1))
        goto error;

    if(memcmp(ptxt, out1, strlen(ptxt) + 1))
        goto error;

//  printf("%s\n", out1);

    printf("\t\tPASSED\n");

    return 0;
error:
    printf(" ***FAILED***\n");
    return -1;
}


void tohex(uint8_t *bin, size_t binLen, char *str, size_t strLen)
{
    size_t i, j;

    if ((!bin || !str) || ((binLen*2) + 1 > strLen))
        return;

    for(j = 0, i = 0; i < binLen; i++, j+=2)
        sprintf(&(str[j]), "%02X", bin[i]);

    str[j] = '\0';
    return;
}