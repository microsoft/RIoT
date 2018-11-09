#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Generic */
#define UNREFERENCED_PARAMETER(p) (p) = (p)

#define FP_TEMPLATE_SIZE (498)
#define FP_IMAGE_SIZE (52116)
#define FP_RAW_IMAGE_SIZE (19200)
#define FP_DEFAULT_TIMEOUT (200)
#define FP_DISPLAY_MAX_TEXT (256)


#define FP_SLOT_INITIALIZE_TEMPLATE (0x00)
#define FP_SLOT_DELETE_ALL_TEMPLATE (0x01)
#define FP_SLOT_DELETE_TEMPLATE (0x02)
#define FP_SLOT_ENROLL_TEMPLATE (0x03)
#define FP_AUTHORIZE_INITIALIZE (0x00)
#define FP_AUTHORIZE_VERIFY (0x01)
#define FP_AUTHORIZE_TIMEOUT (0x02)

// TODO remove
#define NV_FPBASE_INDEX (0x00008000)
#define FP_SLOTS_MAX (200)
#define FP_AUTHORIZE_INDEX (NV_FPBASE_INDEX + FP_SLOTS_MAX)
#define FP_DISPLAY_INDEX (FP_AUTHORIZE_INDEX + 1)

typedef enum FPR_COMMAND_CODE
{
    FPR_COMMAND_OPEN = 0x01,
    FPR_COMMAND_CLOSE,
    FPR_COMMAND_USBINTERNALCHECK,
    FPR_COMMAND_CHANGEBAUDRATE,
    FPR_COMMAND_SETIAPMODE,
    FPR_COMMAND_CMOSLED = 0x12,
    FPR_COMMAND_GETENROLLCOUNT = 0x20,
    FPR_COMMAND_CHECKENROLLED,
    FPR_COMMAND_ENROLLSTART,
    FPR_COMMAND_ENROLL1,
    FPR_COMMAND_ENROLL2,
    FPR_COMMAND_ENROLL3,
    FPR_COMMAND_ISPRESSFINGER,
    FPR_COMMAND_ACK = 0x30,
    FPR_COMMAND_NACK,
    FPR_COMMAND_DELETEID = 0x40,
    FPR_COMMAND_DELETEALL,
    FPR_COMMAND_VERIFY = 0x50,
    FPR_COMMAND_IDENTIFY,
    FPR_COMMAND_VERIFYTEMPLATE,
    FPR_COMMAND_IDENTIFYTEMPLATE,
    FPR_COMMAND_CAPTUREFINGER = 0x60,
    FPR_COMMAND_MAKETEMPLATE,
    FPR_COMMAND_GETIMAGE,
    FPR_COMMAND_GETRAWIMAGE,
    FPR_COMMAND_GETTEMPLATE = 0x70,
    FPR_COMMAND_SETTEMPLATE,
    FPR_COMMAND_GETDATABASESTART,
    FPR_COMMAND_GETDATABASEEND,
    FPR_COMMAND_UPGRADEFIRMWARE = 0x80,
    FPR_COMMAND_UPGRADECOSDIMAGE,
    FPR_COMMAND_SETSECURITYLEVEL = 0xf0,
    FPR_COMMAND_GETSECURITYLEVEL,
    FPR_COMMAND_INVALID = 0xffff
} FPR_COMMAND_CODE;

typedef struct COMMAND_INFO
{
    FPR_COMMAND_CODE cmd;
    unsigned short dataIn;
    unsigned short dataOut;
} COMMAND_INFO;

typedef struct DEV_INFO_FPR
{
    unsigned int FirmwareVersion;
    unsigned int IsoAreaMaxSize;
    unsigned char SerialNumber[16];
} DEV_INFO_FPR;

typedef enum FPR_ERROR_CODE
{
    FPR_ERROR_ACK_SUCCESS = 0,
    FPR_ERROR_NACK_TIMEOUT = 0x1001,
    FPR_ERROR_NACK_BAUDRATE,
    FPR_ERROR_NACK_POS,
    FPR_ERROR_NACK_IS_NOT_USED,
    FPR_ERROR_NACK_IS_ALREADY_USED,
    FPR_ERROR_NACK_COMM_ERR,
    FPR_ERROR_NACK_VERIFY_FAILED,
    FPR_ERROR_NACK_IDENTIFY_FAILED,
    FPR_ERROR_NACK_DB_IS_FULL,
    FPR_ERROR_NACK_DB_IS_EMPTY,
    FPR_ERROR_NACK_TURN_ERR,
    FPR_ERROR_NACK_BAD_FINGER,
    FPR_ERROR_NACK_ENROLL_FAILED,
    FPR_ERROR_NACK_IS_NOT_SUPPORTED,
    FPR_ERROR_NACK_DEV_ERR,
    FPR_ERROR_NACK_CAPTURE_CANCELED,
    FPR_ERROR_NACK_INVALID_PARAM,
    FPR_ERROR_NACK_FINGER_IS_NOT_PRESSED
} FPR_ERROR_CODE;

typedef enum FPR_STATE_MACHINE
{
    FPR_STATE_MACHINE_START = 0,
    FPR_STATE_MACHINE_ENROLL_FIRST_PRESS,
    FPR_STATE_MACHINE_ENROLL_FIRST_SCAN,
    FPR_STATE_MACHINE_ENROLL_FIRST_LIGHT_OFF,
    FPR_STATE_MACHINE_ENROLL_FIRST_LIGHT_ON = FPR_STATE_MACHINE_ENROLL_FIRST_LIGHT_OFF + 100,
    FPR_STATE_MACHINE_ENROLL_FIRST_REMOVED,
    FPR_STATE_MACHINE_ENROLL_SECOND_PRESS,
    FPR_STATE_MACHINE_ENROLL_SECOND_SCAN,
    FPR_STATE_MACHINE_ENROLL_SECOND_LIGHT_OFF,
    FPR_STATE_MACHINE_ENROLL_SECOND_LIGHT_ON = FPR_STATE_MACHINE_ENROLL_SECOND_LIGHT_OFF + 100,
    FPR_STATE_MACHINE_ENROLL_SECOND_REMOVED,
    FPR_STATE_MACHINE_ENROLL_THIRD_PRESS,
    FPR_STATE_MACHINE_ENROLL_THIRD_SCAN,

    FPR_STATE_MACHINE_VERIFY_PRESS,
    FPR_STATE_MACHINE_VERIFY_SCAN,

    FPR_STATE_MACHINE_IDENTIFY_PRESS,
    FPR_STATE_MACHINE_IDENTIFY_SCAN,

    FPR_STATE_MACHINE_END = 0x7fffffff
} FPR_STATE_MACHINE;

typedef struct FPR_COMMAND_RESPONSE_DATA
{
    unsigned char startCode1;
    unsigned char startCode2;
    unsigned short deviceId;
    unsigned int parameter;
    unsigned short cmd_rsp;
    unsigned short checkSum;
} FPR_COMMAND_RESPONSE_DATA;

typedef union FPR_COMMAND_RESPONSE_PACKET_T
{
    FPR_COMMAND_RESPONSE_DATA s;
    unsigned char raw[sizeof(FPR_COMMAND_RESPONSE_DATA)];
} FPR_COMMAND_RESPONSE_PACKET_T;

// Extern callbacks
void InitializeSecureDipaly(void);
int _plat__IsCanceled(void);

// FPRP APIs
FPR_ERROR_CODE FPRP_Initialize(bool re_init);
void FPRP_Close(void);
void FPRP_WriteChar(unsigned char data, int* timeout);
unsigned char FPRP_ReadChar(int* timeout);
void FPRP_Sleep(unsigned int durationMsec);
uint32_t FPRP_GetTick(void);

// FPR APIs
FPR_ERROR_CODE FPR_Open(DEV_INFO_FPR* info);
FPR_ERROR_CODE FPR_Close(void);
FPR_ERROR_CODE FPR_CMOSLEDControl(unsigned int on);
FPR_ERROR_CODE FPR_ChangeBaudrate(unsigned int baudrate);
FPR_ERROR_CODE FPR_GetEnrollCount(unsigned int* count);
FPR_ERROR_CODE FPR_CheckEnrolled(unsigned int id);
FPR_ERROR_CODE FPR_EnrollStart(unsigned int id, unsigned char noDupChk, unsigned char noSave);
FPR_ERROR_CODE FPR_Enroll(unsigned int no, unsigned char* fpTemplate);
FPR_ERROR_CODE FPR_IsPressFinger(void);
FPR_ERROR_CODE FPR_DeleteId(unsigned int id);
FPR_ERROR_CODE FPR_DeleteAll(void);
FPR_ERROR_CODE FPR_Verify(unsigned int id);
FPR_ERROR_CODE FPR_Identify(unsigned int* id);
FPR_ERROR_CODE FPR_VerifyTemplate(unsigned int id, unsigned char* fpTemplate);
FPR_ERROR_CODE FPR_IdentifyTemplate(unsigned int* id, unsigned char* fpTemplate);
FPR_ERROR_CODE FPR_CaptureFinger(unsigned char bestImage);
FPR_ERROR_CODE FPR_MakeTemplate(unsigned char* fpTemplate);
FPR_ERROR_CODE FPR_GetImage(unsigned char* fpImage);
FPR_ERROR_CODE FPR_GetRawImage(unsigned char* fpRawImage);
FPR_ERROR_CODE FPR_GetTemplate(unsigned int id, unsigned char* fpTemplate);
FPR_ERROR_CODE FPR_SetTemplate(unsigned int id, unsigned char* fpTemplate);
FPR_ERROR_CODE FPR_SetIAPMode(void);
FPR_ERROR_CODE FPR_SetSecurityLevel(unsigned int level);
FPR_ERROR_CODE FPR_GetSecurityLevel(unsigned int* level);

FPR_ERROR_CODE FPR_WaitForFinger(unsigned char pressed, unsigned int cycles);
FPR_ERROR_CODE FPR_EnrollFinger(FPR_STATE_MACHINE* state, unsigned int id, unsigned char noDupChk, unsigned char noSave, unsigned char* fpTemplate);
FPR_ERROR_CODE FPR_VerifyFinger(FPR_STATE_MACHINE* state, unsigned int id);
FPR_ERROR_CODE FPR_IdentifyFinger(FPR_STATE_MACHINE* state, unsigned int* id);

FPR_ERROR_CODE FPR_TPMWrite(uint32_t index, uint8_t* data, uint32_t size, uint32_t offset);
FPR_ERROR_CODE FPR_TPMRead(uint32_t index, uint8_t* data, uint32_t size, uint32_t offset);
FPR_ERROR_CODE TDisp_Write(uint8_t* data, uint32_t size, uint32_t offset);
FPR_ERROR_CODE TDisp_Read(uint8_t* data, uint32_t size, uint32_t offset);

#ifdef __cplusplus
}
#endif
