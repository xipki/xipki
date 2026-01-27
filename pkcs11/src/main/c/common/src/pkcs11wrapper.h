// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

#ifndef PKCS11_WRAPPER_H
#define PKCS11_WRAPPER_H 1

#include "platform.h"
#include "jni.h"
#include <stdlib.h>
#include <string.h>

#define V2_40 0x0228UL // v2.40
#define V3_0  0x0300UL // v3.0
#define V3_2  0x0302UL // v3.2

#define CK_FUNC_LIST_PTR CK_FUNCTION_LIST_3_2_PTR

#define checkMalloc(x) if (x == NULL_PTR) return CKR_JNI_MEM_ERROR
#define MAX_FIND_OBJECTS_COUNT 65536UL
#define MAX_ATTR_VALUE_LEN     65536UL
#define MAX_PAYLOAD_LEN        0x7FFFFFFFUL

// Response Type
#define RESP_Err        1
#define RESP_Simple     2
#define RESP_Long       3

// CKR
#define CKR_JNI_MEM_ERROR          0xFFFFFFFFUL
#define CKR_JNI_OPEN_LIB           0xFFFFFFFEUL
#define CKR_JNI_C_GetFunctionList  0xFFFFFFFDUL
#define CKR_JNI_NO_MODULE          0xFFFFFFFCUL

#define CKR_JNI_BAD_OP             0xFFFFFFFAUL
#define CKR_JNI_BAD_RESP           0xFFFFFFF9UL
#define CKR_JNI_BAD_TEMPLATE       0xFFFFFFF8UL
#define CKR_JNI_BAD_PARAMS         0xFFFFFFF7UL
#define CKR_JNI_BAD_ARG            0xFFFFFFF6UL

// Operations

#define PRESENCE_REQUIRED  0x1UL
#define PRESENCE_OPTIONAL  0x2UL

#define  ATTRS_PRESENCE_SHIFT  8
#define ATTRS2_PRESENCE_SHIFT  9
#define   METH_PRESENCE_SHIFT  10
#define   DATA_PRESENCE_SHIFT  12
#define  DATA2_PRESENCE_SHIFT  14

// attrs:  bit 8
#define ATTRS_R   (PRESENCE_REQUIRED << ATTRS_PRESENCE_SHIFT)

// attrs2: bit 9
#define ATTRS2_R  (PRESENCE_REQUIRED << ATTRS2_PRESENCE_SHIFT)

// mechParams: bits 10-11
#define METH_R  (PRESENCE_REQUIRED << METH_PRESENCE_SHIFT)
#define METH_O  (PRESENCE_OPTIONAL << METH_PRESENCE_SHIFT)

// data: bits 12-13
#define DATA_R  (PRESENCE_REQUIRED << DATA_PRESENCE_SHIFT)
#define DATA_O  (PRESENCE_OPTIONAL << DATA_PRESENCE_SHIFT)

// data: bits 14-15
#define DATA2_R  (PRESENCE_REQUIRED << DATA2_PRESENCE_SHIFT)
#define DATA2_O  (PRESENCE_OPTIONAL << DATA2_PRESENCE_SHIFT)

// v2.x functions
#define OP_C_GetAttributeValueX   1

#define OP_C_Initialize           2
#define OP_C_Finalize             3
#define OP_C_GetInfo              4
//C_GetFunctionList -- will be used in the native code only
#define OP_C_GetSlotList          5
#define OP_C_GetSlotInfo          6
#define OP_C_GetTokenInfo         7
#define OP_C_GetMechanismList     8
#define OP_C_GetMechanismInfo     9
#define OP_C_OpenSession          10
#define OP_C_CloseSession         11
#define OP_C_CloseAllSessions     12
#define OP_C_GetSessionInfo       13
#define OP_C_Login                14
#define OP_C_Logout               15
#define OP_C_CreateObject         16
#define OP_C_CopyObject           17
#define OP_C_DestroyObject        18
#define OP_C_GetAttributeValue    19
#define OP_C_SetAttributeValue    20
#define OP_C_FindObjectsInit      21
#define OP_C_FindObjects          22
#define OP_C_FindObjectsFinal     23
#define OP_C_DigestInit           24
#define OP_C_Digest               25
#define OP_C_DigestUpdate         26
#define OP_C_DigestKey            27
#define OP_C_DigestFinal          28
#define OP_C_SignInit             29
#define OP_C_Sign                 30
#define OP_C_SignUpdate           31
#define OP_C_SignFinal            32
#define OP_C_GenerateKey          33
#define OP_C_GenerateKeyPair      34

#define OP_V2_40_MAX              34
#define OP_V3_0_MIN               35

// version 3.0 functions
//C_GetInterfaceList, will be used in the native code only
//C_GetInterface, will be used in the native code only
#define OP_C_LoginUser            35
#define OP_C_SessionCancel        36

#define OP_V3_0_MAX               35
#define OP_V3_2_MIN               37

// v3.2 functions

#define OP_C_DecapsulateKey       37

#define OP_V3_2_MAX               37

// Mechanism.parameter type
#define MP_NO_MECH                                  0
#define MP_NullParams                               1
#define MP_LongParams                               2
#define MP_ByteArrayParams                          3
#define MP_GCM_PARAMS                               6
#define MP_EDDSA_PARAMS                             11
#define MP_SIGN_ADDITIONAL_CONTEXT                  12
#define MP_HASH_SIGN_ADDITIONAL_CONTEXT             13
#define MP_RSA_PKCS_PSS_PARAMS                      19
#define MP_XEDDSA_PARAMS                            27

// Attribute.value type
#define AV_UNKNOWN     1
#define AV_NULL        2
#define AV_BOOL        3
#define AV_LONG        4
#define AV_DATE        5
#define AV_VERSION     6
#define AV_BYTE_ARRAY  7
#define AV_LONG_ARRAY  8
#define AV_TEMPLATE    9

#define SIZE_LONG  sizeof(CK_ULONG)
#define isOK(rv) rv == CKR_OK
#define isNOK(rv) rv != CKR_OK
#define free_t_null(p) free(p); p = NULL_PTR

#define returnBadParamsIf(x) if(x) { return CKR_JNI_BAD_PARAMS; }

#define returnBadTemplateIf(x) if(x) { return CKR_JNI_BAD_TEMPLATE; }

#define returnBadArgIf(x) if(x) { return CKR_JNI_BAD_ARG; }

#define free_mech(pMech, pBParams) \
  if (pMech != NULL_PTR) { \
    freeCkParam(&(pMech->pParameter), pBParams); \
    free_t_null(pMech); \
  }

// module management
typedef struct ModuleData {
  P11ModuleHandle   hModule;   /* module (DLL) handle */
  CK_FUNC_LIST_PTR  pFuncList; /* Pointer to the PKCS#11 functions */
  CK_ULONG          version;
} ModuleData;

// implemented in platform.c

CK_ULONG p11_open_lib(P11ModuleHandle* phModule, char* libPath);

CK_ULONG p11_close_lib(P11ModuleHandle hModule);

void *p11_get_lib_symbol(P11ModuleHandle hModule, const char *symbol);

// implemented in util.c

void memcpy2(void* dest, CK_ULONG *destOff, void* src, size_t num);

CK_ULONG bytes2long(CK_BYTE_PTR bytes, CK_ULONG *off);

void long2bytes(CK_BYTE_PTR dest, CK_ULONG* off, CK_ULONG src);

void copyVersion(CK_BYTE_PTR dest, CK_ULONG* off, CK_VERSION src);

CK_RV buildLongResp(CK_BYTE_PTR resp, CK_ULONG respLen, CK_ULONG value);

// implemented in mechanism.c
void freeParsedTemplate(CK_ATTRIBUTE_PTR* attrs, CK_ULONG count);

CK_RV parseTemplate(CK_ATTRIBUTE_PTR* attrs, CK_ULONG *count,
                    CK_BYTE_PTR       bytes, CK_ULONG maxOff);

void freeCkParam(CK_VOID_PTR* param, CK_BYTE_PTR pBParams);

CK_RV parseMechParams(CK_VOID_PTR*  pParams, CK_ULONG* paramsLen,
                      CK_BYTE_PTR  pbParams, CK_ULONG  bParamsLen);

// implemented in attribute.c
CK_RV getAttributeValue(CK_FUNC_LIST_PTR funcs,
    CK_BYTE_PTR* pPayload,      CK_ULONG* payloadLen,
    CK_BYTE_PTR  pResp,         CK_ULONG respLen,
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_BYTE_PTR pData,          CK_ULONG dataLen);

CK_RV getAttributeValueOfTemplate(CK_FUNC_LIST_PTR funcs,
    CK_BYTE_PTR* pPayload,      CK_ULONG* payloadLen,
    CK_BYTE_PTR  pResp,         CK_ULONG respLen,
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG attrType);

// implemented in cryptoki.c
CK_RV cryptoki_query(ModuleData* module,
    CK_ULONG       op, CK_BYTE_PTR* pPayload, CK_ULONG* payloadLen,
    CK_BYTE_PTR pResp, CK_ULONG respLen,
    CK_ULONG moduleId, CK_ULONG  id, CK_ULONG id2, CK_ULONG id3, CK_ULONG size,
    CK_BYTE_PTR pData, CK_ULONG dataLen, CK_BYTE_PTR pData2, CK_ULONG data2Len,
    CK_MECHANISM_PTR   pMech, CK_BYTE_PTR pBParams, CK_ULONG BPParamsLen,
    CK_ATTRIBUTE_PTR  pAttrs, CK_ULONG attrsCount,
    CK_ATTRIBUTE_PTR pAttrs2, CK_ULONG attrs2Count);

#endif
