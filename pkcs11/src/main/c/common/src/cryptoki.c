// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

#include "pkcs11wrapper.h"

#define mallocPayload(len) \
  *payloadLen = len; \
  *pPayload = (CK_BYTE_PTR) malloc(*payloadLen); \
  checkMalloc(*pPayload)

/*
 * payloadLen = math.max(1, payloadLen) to ensure *pPayload != NULL,
 * *payLoadLen will be set back to 0 in the next step.
 */
#define PREPARE_OP_WITH_PAYLOAD \
if (isOK(rv)) { \
  for (int i = 0; i < 3 && rv == CKR_OK; i++) { \
    if (i == 0) { \
      if (size < MAX_PAYLOAD_LEN) { \
        *payloadLen = size; \
        continue; \
      } else { \
        *payloadLen = 0; \
        *pPayload = NULL_PTR; \
      } \
    } else { \
      if (*payloadLen == 0) { *payloadLen = 1; } \
      *pPayload = malloc(*payloadLen); \
      if (*pPayload == NULL_PTR) { \
        rv = CKR_JNI_MEM_ERROR; \
        break; \
      } \
    }

#define RETRY_OP_WITH_PAYLOAD \
    if (i == 0) { continue; } \
    else if (i == 1) { \
      if (rv == CKR_BUFFER_TOO_SMALL && *payloadLen < MAX_PAYLOAD_LEN) { \
        free_t_null(*pPayload); \
        rv = CKR_OK; \
      } else { break; } \
    } \
  } \
}

#define buildLongPayload(value) \
  if (isOK(rv)) { \
    mallocPayload(SIZE_LONG); \
    long2bytes(*pPayload, &payloadOff, value); \
  }

CK_RV cryptoki_query(ModuleData* module,
    CK_ULONG       op, CK_BYTE_PTR* pPayload, CK_ULONG* payloadLen,
    CK_BYTE_PTR pResp, CK_ULONG respLen,
    CK_ULONG moduleId, CK_ULONG  id, CK_ULONG id2, CK_ULONG id3, CK_ULONG size,
    CK_BYTE_PTR pData, CK_ULONG dataLen, CK_BYTE_PTR pData2, CK_ULONG data2Len,
    CK_MECHANISM_PTR   pMech, CK_BYTE_PTR pBParams, CK_ULONG BParamsLen,
    CK_ATTRIBUTE_PTR  pAttrs, CK_ULONG attrsCount,
    CK_ATTRIBUTE_PTR pAttrs2, CK_ULONG attrs2Count)
{
  CK_ULONG payloadOff = 0;
  CK_RV rv = CKR_OK;
  CK_FUNC_LIST_PTR funcs = module->pFuncList;

  switch(op) {
    /*********************************
     * Cryptoki v2.x Functions
     *********************************/
    // module management
    case OP_C_Initialize: {
      // flags = id2
      CK_C_INITIALIZE_ARGS initArgs = {
            NULL_PTR, NULL_PTR, NULL_PTR, NULL_PTR, id2, NULL_PTR};
      return funcs->C_Initialize(&initArgs);
    }
    case OP_C_GetInfo: {
      CK_INFO info;
      rv = funcs->C_GetInfo(&info);
      if (isOK(rv)) {
        mallocPayload(2 + 32 + SIZE_LONG + 32 + 2);
        copyVersion(*pPayload, &payloadOff, info.cryptokiVersion);
        memcpy2    (*pPayload, &payloadOff, info.manufacturerID, 32);
        long2bytes (*pPayload, &payloadOff, info.flags);
        memcpy2    (*pPayload, &payloadOff, info.libraryDescription, 32);
        copyVersion(*pPayload, &payloadOff, info.libraryVersion);
      }
      return rv;
    }
    case OP_C_Finalize:
      return funcs->C_Finalize((CK_VOID_PTR) NULL_PTR);
    // slot management
    case OP_C_GetSlotList: {
      CK_BBOOL tokenPresent = id2 != 0; // flags = id2
      CK_ULONG num;
      rv = funcs->C_GetSlotList(tokenPresent, NULL_PTR, &num);
      if (isOK(rv) && num > 0) {
        mallocPayload(num * SIZE_LONG);
        rv = funcs->C_GetSlotList(tokenPresent,
                (CK_SLOT_ID_PTR) *pPayload, &num);
      }
      return rv;
    }
    case OP_C_GetSlotInfo: {
      // slotID = id
      CK_SLOT_INFO info;
      rv = funcs->C_GetSlotInfo(id, &info);
      if (isOK(rv)) {
        mallocPayload(64 + 32 + SIZE_LONG + 2 + 2);
        memcpy2    (*pPayload, &payloadOff, &info, *payloadLen - 4);
        copyVersion(*pPayload, &payloadOff, info.hardwareVersion);
        copyVersion(*pPayload, &payloadOff, info.firmwareVersion);
      }
      return rv;
    }
    case OP_C_GetTokenInfo: {
      // slotID = id
      CK_TOKEN_INFO info;
      rv = funcs->C_GetTokenInfo(id, &info);
      if (isOK(rv)) {
        mallocPayload(2 * 32 + 2 * 16 + 11 * SIZE_LONG + 20);
        memcpy2    (*pPayload, &payloadOff, &info, *payloadLen - 20);
        copyVersion(*pPayload, &payloadOff, info.hardwareVersion);
        copyVersion(*pPayload, &payloadOff, info.firmwareVersion);
        memcpy2    (*pPayload, &payloadOff, info.utcTime, 16);
      }
      return rv;
    }
    case OP_C_GetMechanismList: {
      // slotID = id
      CK_ULONG num;
      rv = funcs->C_GetMechanismList(id, NULL_PTR, &num);
      if (isOK(rv) && num > 0) {
        mallocPayload(num * SIZE_LONG);
        rv = funcs->C_GetMechanismList(id,
                (CK_MECHANISM_TYPE_PTR) *pPayload, &num);
      }
      return rv;
    }
    case OP_C_GetMechanismInfo: {
      // slotID = id, type = id2
      mallocPayload(3 * SIZE_LONG);
      // mechanism = id2
      return funcs->C_GetMechanismInfo(id, id2,
                (CK_MECHANISM_INFO_PTR) *pPayload);
    }
    // session management
    case OP_C_OpenSession: {
      // slotID = id, flags = id2
      CK_SESSION_HANDLE hSession;
      rv = funcs->C_OpenSession(id, id2, NULL_PTR, NULL_PTR, &hSession);
      buildLongPayload(hSession);
      return rv;
    }
    case OP_C_CloseAllSessions:
      // slotID = id
      return funcs->C_CloseAllSessions(id);
    case OP_C_CloseSession:
      // hSession = id
      return funcs->C_CloseSession(id);
    case OP_C_GetSessionInfo: {
      // hSession = id
      mallocPayload(4 * SIZE_LONG);
      return funcs->C_GetSessionInfo(id, (CK_SESSION_INFO_PTR) *pPayload);
    }
    // object management
    case OP_C_CreateObject: {
      // hSession = id, pTemplate = pAttrs
      CK_OBJECT_HANDLE hNewObject;
      rv = funcs->C_CreateObject(id, pAttrs, attrsCount, &hNewObject);
      buildLongPayload(hNewObject);
      return rv;
    }
    case OP_C_CopyObject: {
      // hSession = id, hObject = id2, pTemplate = pAttrs
      CK_OBJECT_HANDLE hNewObject;
      rv = funcs->C_CopyObject(id, id2, pAttrs, attrsCount, &hNewObject);
      buildLongPayload(hNewObject);
      return rv;
    }
    case OP_C_DestroyObject:
      // hSession = id, hObject = id2
      return funcs->C_DestroyObject(id, id2);
    case OP_C_FindObjectsInit:
      // hSession = id, pTemplate = pAttrs
      return funcs->C_FindObjectsInit(id, pAttrs, attrsCount);
    case OP_C_FindObjectsFinal:
      // hSession = id
      return funcs->C_FindObjectsFinal(id);
    case OP_C_FindObjects: {
      // hSession = id, pTemplate = pAttrs, maxObjectCount = size
      CK_ULONG maxObjectCount = size;
      if (maxObjectCount > MAX_FIND_OBJECTS_COUNT) {
        rv = CKR_JNI_BAD_ARG;
      }

      if (isOK(rv)) {
        mallocPayload(maxObjectCount * SIZE_LONG);

        CK_ULONG objectCount;
        rv = funcs->C_FindObjects(id, (CK_OBJECT_HANDLE_PTR) *pPayload,
                maxObjectCount, &objectCount);
        *payloadLen = isOK(rv) ? objectCount * SIZE_LONG : 0;
      }
      return rv;
    }
    // PIN
    case OP_C_Login:
      // hSession = id, userType = id2, pPin = pData
      return funcs->C_Login(id, id2, pData, dataLen);
    case OP_C_Logout:
      // hSession = id
      return funcs->C_Logout(id);
    // attribute value
    case OP_C_GetAttributeValue:
      // hSession = id, hObject = id2
      return getAttributeValue(funcs, pPayload, payloadLen,
            pResp, respLen, id, id2, pData, dataLen);
    case OP_C_GetAttributeValueX:
      // hSession = id, hObject = id2, type = id3
      return getAttributeValueOfTemplate(funcs, pPayload, payloadLen,
            pResp, respLen, id, id2, id3);
    case OP_C_SetAttributeValue:
      // hSession = id, hObject = id2, pTemplate = pAttrs
      return funcs->C_SetAttributeValue(id, id2, pAttrs, attrsCount);
    // one step crypto functions
    case OP_C_GenerateKey: {
      // hSession = id, pTemplate = pAttrs
      CK_OBJECT_HANDLE hKey;
      rv = funcs->C_GenerateKey(id, pMech, pAttrs, attrsCount, &hKey);
      buildLongPayload(hKey);
      return rv;
    }
    case OP_C_GenerateKeyPair: {
      // hSession = id, publicKeyTemplate=pAttrs, privateKeyTemplate=pAttrs2
      CK_OBJECT_HANDLE hPublicKey;
      CK_OBJECT_HANDLE hPrivateKey;
      rv = funcs->C_GenerateKeyPair(id, pMech, pAttrs, attrsCount,
             pAttrs2, attrs2Count, &hPublicKey, &hPrivateKey);
      if (isOK(rv)) {
        mallocPayload(2 * SIZE_LONG);
        long2bytes(*pPayload, &payloadOff, hPublicKey);
        long2bytes(*pPayload, &payloadOff, hPrivateKey);
      }
      return rv;
    }
    // first step functions
    case OP_C_SignInit:
      // hSession = id, hKey = id2
      return funcs->C_SignInit(id, pMech, id2);
    case OP_C_DigestInit:
      // hSession = id
      return funcs->C_DigestInit(id, pMech);
    // intermediate step functions
    case OP_C_DigestUpdate:
      // hSession = id
      return funcs->C_DigestUpdate(id, pData, dataLen);
    case OP_C_DigestKey:
      // hSession = id, hKey = id2
      return funcs->C_DigestKey(id, id2);
    case OP_C_SignUpdate:
      // hSession = id
      return funcs->C_SignUpdate(id, pData, dataLen);
    case OP_C_Sign:
    case OP_C_SignFinal:
    case OP_C_Digest:
    case OP_C_DigestFinal:
      // last step functions
      // hSession = id
      PREPARE_OP_WITH_PAYLOAD;
      if (op == OP_C_Sign) {
        rv = funcs->C_Sign(id, pData, dataLen, *pPayload, payloadLen);
      } else if (op == OP_C_SignFinal) {
        rv = funcs->C_SignFinal(id, *pPayload, payloadLen);
      } else if (op == OP_C_Digest) {
        rv = funcs->C_Digest(id, pData, dataLen, *pPayload, payloadLen);
      } else { // if (op == OP_C_DigestFinal) {
        rv = funcs->C_DigestFinal(id, *pPayload, payloadLen);
      }
      RETRY_OP_WITH_PAYLOAD;
      return rv;
    /*********************************
     * Cryptoki v3.0 Functions
     *********************************/
    case OP_C_LoginUser:
      // hSession = id, userType = id2, pPin = pData, pUsername = pData2
      return funcs->C_LoginUser(id, id2, pData, dataLen, pData2, data2Len);
    case OP_C_SessionCancel:
      // hSession = id, flags = id2
      return funcs->C_SessionCancel(id, id2);
    /*********************************
     * Cryptoki v3.2 Functions
     *********************************/
    case OP_C_DecapsulateKey: {
      // hSession = id, hPrivateKey = id2, pTemplate = pAttrs
      CK_OBJECT_HANDLE hNewKey;
      rv = funcs->C_DecapsulateKey(id, pMech, id2,
              pAttrs, attrsCount, pData, dataLen, &hNewKey);
      buildLongPayload(hNewKey);
      return rv;
    }
    default:
      return CKR_JNI_BAD_OP;
  }

}
