/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#ifndef _RIOT_H
#define _RIOT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "RiotStatus.h"
#include "RiotCrypt.h"

#define RIOT_SUCCESS(a) (a == (RIOT_OK))

//
// Key derivation labels used by both RIoT Devices and External Infrastructure
//
#define RIOT_LABEL_IDENTITY     "Identity"
#define RIOT_LABEL_ALIAS        "Alias"
#define RIOT_LABEL_PROTECTOR    "Encrypt"
#define RIOT_LABEL_INTEGRITY    "HMAC"
#define RIOT_LABEL_AIK          "AikProtector"
#define RIOT_LABEL_SK           "Sealing"
#define RIOT_LABEL_MK           "Migration"
#define RIOT_LABEL_AK           "Attestation"

 //
 // Macro for label sizes (skip strlen()).
 //
#define lblSize(a)          (sizeof(a) - 1)

//
// Descriptors for RIoT images and entry points. In reality, the way these are
// specified is purely implementation-specific. But, since every implementation
// will need some way to identify components in the RIoT framework, these are
// defined here and not in RiotPlatform. For this user-mode reference device,
// these are strings/filenames.
//
#define RIOT_CORE_IMAGE     L"RiotCore.dll"
#define RIOT_CORE_ENTRY     "RiotStart"
#define RIOT_CORE_INDEX     0x00UL

#define RIOT_LOADER_IMAGE   L"Loader.dll"
#define RIOT_LOADER_ENTRY   "RiotModuleMain"
#define RIOT_LOADER_INDEX   0x01UL

#define RIOT_TEE_IMAGE      L"Tee.dll"
#define RIOT_TEE_ENTRY      "RiotModuleMain"
#define RIOT_TEE_INDEX      0x02UL

typedef enum RIOT_ACTIVE_KEY_CHAIN {
    RIOT_CHAIN_SK = 1,
    RIOT_CHAIN_AK = 2,
    RIOT_CHAIN_MK = 4
} RIOT_ACTIVE_KEY_CHAIN;

//*** RIOT_DYNAMIC_DATA
// Data structure containing data that are generated and modified during each Boot
// Sequence. These data represent secrets of the RIoT controlled modules, and shall
// be kept in protected facilities at all times (e.g. hardware registers or RAM with
// no DMA access).
typedef struct {
    // Current module index. This index is used by the RIoT framework to locate
    // metadata (such as SMD, SKEB) associated with the given mutable Software
    // Module. Note that indices of mutable Software Modules are 1-based
    // (following the notation used by the RIoT spec). Index 0 is reserved for the
    // Invariant Code.
    //
    // REVISIT: Make it zero-based?
    uint16_t  moduleIndex;

    // A combination of RIOT_ACTIVE_KEY_CHAIN flags that specifies, which key
    // derivation chains are are active during this Boot Sequence.
    uint16_t  activeKeyChains;

    // Current module's Sealing Key
    uint8_t    SK[RIOT_KEY_LENGTH];

    // Current module's Migration Key
    uint8_t    MK[RIOT_KEY_LENGTH];

    // Current module's Attestation Key
    uint8_t    AK[RIOT_KEY_LENGTH];
} RIOT_DYNAMIC_DATA;

typedef enum RIOT_BOOT_MODE {
    RIOT_BOOT_UNKNOWN = 0x0UL,  // Boot mode is unknown.
    RIOT_BOOT_INITIAL,          // Initial Boot Sequence
    RIOT_BOOT_SECURE,           // Regular Boot Sequence
    RIOT_BOOT_UPDATE,           // Update Boot Sequence
    RIOT_BOOT_REMEDIATION,      // Remediation Boot Sequence
    RIOT_BOOT_LAST_MODE = RIOT_BOOT_REMEDIATION
} RIOT_BOOT_MODE;

//*** RIOT_FAILURE_INFO
// Implementation specific data strucure containing information necessary for
// Remediation Boot Sequence.
typedef struct {
    // Index of the module that has failed its policy check during the previous
    // Boot Sequence.
    uint8_t failedModule;
} RIOT_FAILURE_INFO;

//*** RIOT_BSD
// Boot Sequence Descriptor (BSD) data structure. It is used by the RIoT framework
// to determine the type of Boot Sequence to execute upon Power-on, and to store
// data necessary for the current and/or next Boot Sequence completion.
typedef struct {
    RIOT_BOOT_MODE      bootMode;
    RIOT_FAILURE_INFO   failureInfo;
} RIOT_BSD;

//*** RIOT_UPDATE_APPROVAL
// A ticket issued by the current version of a Software Module that gives permission
// to update it to another version, and instructs which checks should be done by the
// RIoT framework during update.
typedef struct {
    // Approval type
    uint8_t    approval[RIOT_DIGEST_LENGTH];

    // HMAC over the approval field
    uint8_t    signature[RIOT_HMAC_LENGTH];
} RIOT_UPDATE_APPROVAL;

// Number of Software Modules controlled by the RIoT framework. This is a count
// of the Software Modules in this implementation of the RIoT framewrok that
// include a Software Module Descriptor, i.e., the number of Software Modules
// that can be updated in RIoT. So, even though RIoT Core qualifies as RIoT-
// controlled image, it is single-layer and does not contain an SMD. Therefore,
// is not included in this count.
#define RIOT_NUM_MODULES    2

// TODO: FIX THIS COMMENT
typedef struct {
    // Public part of the AIK.
    RIOT_ECC_PUBLIC     aikPublic;

    // Public part of the Ateestation Authority that issued the AIK
    RIOT_ECC_PUBLIC     aaPublic;

    // Signature made with aaPublic over aikPublic
    RIOT_ECC_SIGNATURE  signature;
} RIOT_MIN_CERT;

//*** RIOT_AIK
// Data structure containing an AIK (Attestation Identity Key) used by RIoT
// Software Modules.
typedef struct {
    // Public part of the AIK.
    RIOT_ECC_PUBLIC     aikPublic;

    // Private part of the AIK. During AIK import this field is encrypted to
    // the Attestation Secret. After successful import it is re-encrypted to
    // the Sealing Key of the interactive Software Module.
    RIOT_ECC_PRIVATE    aikPrivate;

    // Size of the cert data in aikCert in bytes
    uint16_t              aikCertLength;

    // AIK certificate
    uint8_t                aikCert[RIOT_MAX_CERT_LENGTH];
} RIOT_AIK;

//*** RIOT_PERSISTENT_DATA
// Data structure containing data that are preserved across reboots.
typedef struct {
    // Boot Sequence Descriptor
    RIOT_BSD                BSD;

    // Public part of an ECC key uniquely identifying the given Device.
    RIOT_ECC_PUBLIC         DeviceIDPublic;

    // Encrypted private part of an ECC key uniquely identifying the given Device.
    RIOT_ECC_PRIVATE        DeviceIDPrivate;

    // HMAC over DeviceID key pair
    uint8_t                    signature[RIOT_HMAC_LENGTH];

    // Device signatures for the Software Modules
    uint8_t                    DeviceSignature[RIOT_NUM_MODULES][RIOT_HMAC_LENGTH];

    // Update approval tickets
    RIOT_UPDATE_APPROVAL    updateTicket[RIOT_NUM_MODULES];

    // Current AIK with its private part encrypted to the Sealing Key of the
    // Interactive Module.
    RIOT_AIK                AIK;
} RIOT_PERSISTENT_DATA;

#ifdef __cplusplus
}
#endif

#endif
