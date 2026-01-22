// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

#include "pkcs11wrapper.h"
#include "org_xipki_pkcs11_wrapper_jni_Libpkcs11.h"
#include <string.h>

/*********************************
 * Macros
 *********************************/
#define jni_release(jData, pData) \
  if (pData != NULL_PTR) { \
    (*env)->ReleasePrimitiveArrayCritical(env, jData, pData, 0); \
  }

#define JNI_RELEASE_BYTE_ARRAYS \
    jni_release(jResp,   pResp); \
    jni_release(jData,   pData); \
    jni_release(jData2,  pData2); \
    jni_release(jParams, pBParams); \
    jni_release(jAttrs,  pAttrsB); \
    jni_release(jAttrs2, pAttrs2B)

/*********************************
 * General Functions
 *********************************/

void memcpy2(void* dest, CK_ULONG *destOff, void* src, size_t num)
{
  memcpy(dest + (*destOff), src, num);
  *destOff += num;
}

CK_ULONG bytes2long(CK_BYTE_PTR bytes, CK_ULONG *off)
{
  CK_ULONG v = *((CK_ULONG *) (bytes + (*off)));
  *off += SIZE_LONG;
  return v;
}

void long2bytes(CK_BYTE_PTR dest, CK_ULONG* off, CK_ULONG src)
{
  memcpy(dest + (*off), &src, SIZE_LONG);
  *off += SIZE_LONG;
}

void copyVersion(CK_BYTE_PTR dest, CK_ULONG* off, CK_VERSION src)
{
  dest[(*off)++] = src.major;
  dest[(*off)++] = src.minor;
}

CK_RV buildLongResp(CK_BYTE_PTR resp, CK_ULONG respLen, CK_ULONG value)
{
  returnBadArgIf(respLen < 1 + SIZE_LONG);
  resp[0] = RESP_Long;
  CK_ULONG off = 1;
  long2bytes(resp, &off, value);
  return CKR_OK;
}

static CK_RV buildErrResp(CK_BYTE_PTR resp, CK_ULONG respLen, CK_ULONG ckr)
{
  returnBadArgIf(respLen < 1 + SIZE_LONG);
  resp[0] = RESP_Err;
  CK_ULONG off = 1;
  long2bytes(resp, &off, ckr);
  return CKR_OK;
}

/* ********************************** *
 *          Module Management         *
 * ********************************** */

#define newModuleListNode(x, id, module) \
  x = (ModuleListNode*) malloc(sizeof(ModuleListNode)); \
  checkMalloc(x); \
  x->id     = id; \
  x->module = module; \
  x->next   = NULL_PTR;

typedef struct ModuleListNode {
  CK_ULONG          id;
  ModuleData*       module;
  struct ModuleListNode* next;
} ModuleListNode;

ModuleListNode* moduleListHead = NULL_PTR;

/*********************************
 * Module management
 *********************************/

static CK_RV put_module(CK_ULONG id, ModuleData *module)
{
  ModuleListNode *current, *newNode;
  if (moduleListHead == NULL_PTR) {
    // this is the first entry
    newModuleListNode(newNode, id, module);
    moduleListHead = newNode;
  } else {
    // override if id exists, otherwise append to the list
    current = moduleListHead;
    while (current->next != NULL_PTR && id != current->id) {
      current = current->next;
    }

    if (current->id == id) {
      // override
      current->module  = module;
    } else {
      // append to the list
      newModuleListNode(newNode, id, module);
      current->next = newNode;
    }
  }

  return CKR_OK;
}

static ModuleData* get_module(CK_ULONG id)
{
  if (moduleListHead == NULL_PTR) {
    return NULL_PTR;
  }

  ModuleListNode *current = moduleListHead;
  while (current != NULL_PTR && id != current->id) {
    current = current->next;
  }

  return current == NULL_PTR ? NULL_PTR : current->module;
}

static CK_RV p11_remove_module(CK_ULONG id)
{
  if (moduleListHead == NULL_PTR) {
    return NULL_PTR;
  }

  ModuleListNode* current = NULL_PTR;
  if (moduleListHead->id == id) {
    current = moduleListHead;
    moduleListHead = moduleListHead->next;
  } else {
    ModuleListNode *previousNode = moduleListHead;
    current = moduleListHead->next;
    while (current != NULL_PTR && id != current->id) {
      previousNode = current;
      current = current->next;
    }

    if (current != NULL_PTR) {
      previousNode->next = current->next;
    }
  }

  if (current == NULL_PTR) {
    return CKR_JNI_NO_MODULE;
  }

  // close the file
  p11_close_lib(current->module->hModule);
  free_t_null(current->module);
  free_t_null(current);
  return CKR_OK;
}

static CK_RV p11_init_module(CK_ULONG mid, char* libPath) {
  ModuleData *module = (ModuleData *) malloc(sizeof(ModuleData));
  CK_RV rv = p11_open_lib(&module->hModule, libPath);
  if (isNOK(rv)) {
    free_t_null(module);
    return rv;
  }

  CK_C_GetFunctionList getFuncList = (CK_C_GetFunctionList)
        p11_get_lib_symbol(module->hModule, "C_GetFunctionList");
  if (getFuncList == NULL_PTR) {
    p11_close_lib(module->hModule);
    free_t_null(module);
    return CKR_JNI_C_GetFunctionList;
  }

  /*
   * Get function pointers to all PKCS #11 functions
   */
  module->version = V2_40; // version 2.40
  rv = (getFuncList)(&(module->pFuncList));

  rv = put_module(mid, module);
  if (isNOK(rv)) {
    p11_close_lib(module->hModule);
    free_t_null(module);
    return rv;
  }

  CK_C_GetInterfaceList getInterfaceList = (CK_C_GetInterfaceList)
        p11_get_lib_symbol(module->hModule, "C_GetInterfaceList");
  if (getInterfaceList == NULL_PTR) {
    return CKR_OK;
  }

  /* we are now in v3.0+ */
  CK_ULONG interfaceLen = 0;
  rv = (getInterfaceList)(NULL_PTR, &interfaceLen);
  if (isNOK(rv)) {
    return CKR_OK;
  }

  CK_INTERFACE_PTR pInterface =
        (CK_INTERFACE_PTR) malloc(interfaceLen * sizeof(CK_INTERFACE));

  rv = (getInterfaceList)(pInterface, &interfaceLen);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    free_t_null(pInterface);
    return CKR_OK;
  }

  for (int i = 0; i < interfaceLen; i++) {
    CK_INTERFACE iface = pInterface[i];
    CK_VERSION *version = (CK_VERSION*) iface.pFunctionList;

    if (!strcmp((const char*) iface.pInterfaceName, "PKCS 11") &&
        version->major == 3) {
      module->pFuncList = iface.pFunctionList;
      module->version = (version->major * 256UL + version->minor);
      break;
    }
  }

  free_t_null(pInterface);
  return CKR_OK;
}

static CK_ULONG p11_getVersion(CK_ULONG moduleId)
{
  ModuleData* module = get_module(moduleId);
  return (module == NULL_PTR) ? 0 : module->version;
}

static void p11_closeLibrary()
{
  if (moduleListHead == NULL_PTR) {
    return;
  }

  ModuleListNode *current = moduleListHead, *nextNode;
  while (current != NULL_PTR) {
    nextNode = current->next;
    p11_close_lib(current->module->hModule);
    free_t_null(current->module);
    free_t_null(current);
    current = nextNode;
  }

  moduleListHead = NULL_PTR;
}

static ModuleData* getModule(CK_ULONG *rv, CK_ULONG mid, CK_ULONG version) {
  ModuleData* module = get_module(mid);
  if (module == NULL_PTR) {
    *rv = CKR_JNI_NO_MODULE;
    return NULL_PTR;
  }

  if (version > module->version) {
    *rv = CKR_FUNCTION_NOT_SUPPORTED;
    return NULL_PTR;
  }

  return module;
}

/*********************************
 * JNI general functions
 *********************************/
static void jByteArrayToC(JNIEnv* env, const jbyteArray jArray,
                          CK_BYTE_PTR* pArray, CK_ULONG *pLen)
{
  *pLen = 0;
  if (jArray != NULL_PTR) {
    *pLen = (*env)->GetArrayLength(env, jArray);
  }

  if (*pLen == 0) {
    *pArray = NULL_PTR;
    return;
  }

  *pArray = (*env)->GetPrimitiveArrayCritical(env, jArray, NULL_PTR);
}

static jbyteArray cByteArrayToJ(JNIEnv* env, CK_BYTE_PTR pArray, CK_ULONG len)
{
  if (pArray == NULL_PTR) {
    return NULL_PTR;
  }

  jbyteArray jArray = (*env)->NewByteArray(env, len);
  if (jArray != NULL_PTR && len > 0) {
    (*env)->SetByteArrayRegion(env, jArray, 0, len, (jbyte*) pArray);
  }
  return jArray;
}

JNIEXPORT jint JNICALL
Java_org_xipki_pkcs11_wrapper_jni_Libpkcs11_getVersion(
    JNIEnv *env, jclass clazz, jint jModuleId)
{
  return p11_getVersion((CK_ULONG) jModuleId);
}

JNIEXPORT jbyte JNICALL
Java_org_xipki_pkcs11_wrapper_jni_Libpkcs11_getArch(JNIEnv *env, jclass clazz)
{
   CK_LONG   v = 0x1122;
   CK_BYTE *pV = (CK_BYTE*) &v;
   CK_BYTE ret = SIZE_LONG;
   if (pV[0] == 0x22) { // little endian
     ret |= 0x80;
   }
  return ret;
}

JNIEXPORT void JNICALL
Java_org_xipki_pkcs11_wrapper_jni_Libpkcs11_initializeLibrary
  (JNIEnv *env, jclass clazz)
{
  // do nothing
}

JNIEXPORT void JNICALL
Java_org_xipki_pkcs11_wrapper_jni_Libpkcs11_closeLibrary
  (JNIEnv *env, jclass clazz)
{
  p11_closeLibrary();
}

JNIEXPORT jlong JNICALL
Java_org_xipki_pkcs11_wrapper_jni_Libpkcs11_initModule
  (JNIEnv *env, jclass clazz, jint jModuleId, jbyteArray jModulePath)
{
  CK_BYTE_PTR pModulePath = NULL_PTR;
  CK_ULONG pathLen = 0;
  jByteArrayToC(env, jModulePath, &pModulePath, &pathLen);
  returnBadArgIf(pModulePath[pathLen - 1] != 0);

  CK_RV rv = p11_init_module((CK_ULONG) jModuleId, (char*) pModulePath);
  jni_release(jModulePath, pModulePath);
  return rv;
}

JNIEXPORT jlong JNICALL
Java_org_xipki_pkcs11_wrapper_jni_Libpkcs11_closeModule
  (JNIEnv *env, jclass clazz, jint jModuleId)
{
  CK_ULONG moduleId = (CK_ULONG) jModuleId;
  return p11_remove_module(moduleId);
}

static CK_RV checkInParams(
    CK_ULONG op, CK_ULONG dataLen, CK_ULONG data2Len,
    CK_BBOOL withMech, CK_BBOOL withAttrs, CK_BBOOL withAttrs2)
{
  // check mechParams
  CK_ULONG presence = (op >> METH_PRESENCE_SHIFT) & 0x3UL;
  if (presence == PRESENCE_REQUIRED) {
    returnBadParamsIf(!withMech)
  } else if (presence != PRESENCE_OPTIONAL) {
    returnBadParamsIf(withMech)
  }

  // check attrs
  presence = (op >> ATTRS_PRESENCE_SHIFT) & 0x1UL;
  if (presence == PRESENCE_REQUIRED) {
    returnBadTemplateIf(!withAttrs);
  } else {
    returnBadTemplateIf(withAttrs);
  }

  // check attrs2
  presence = (op >> ATTRS2_PRESENCE_SHIFT) & 0x1UL;
  if (presence == PRESENCE_REQUIRED) {
    returnBadTemplateIf(!withAttrs2);
  } else {
    returnBadTemplateIf(withAttrs2);
  }

  // check data
  presence = (op >> DATA_PRESENCE_SHIFT) & 0x3UL;
  if (presence == PRESENCE_REQUIRED) {
    returnBadParamsIf(dataLen == 0)
  } else if (presence != PRESENCE_OPTIONAL) {
    returnBadParamsIf(dataLen > 0)
  }

  // check data2
  presence = (op >> DATA2_PRESENCE_SHIFT) & 0x3UL;
  if (presence == PRESENCE_REQUIRED) {
    returnBadParamsIf(data2Len == 0)
  } else if (presence != PRESENCE_OPTIONAL) {
    returnBadParamsIf(data2Len > 0)
  }

  return CKR_OK;
}

JNIEXPORT jbyteArray JNICALL
Java_org_xipki_pkcs11_wrapper_jni_Libpkcs11_query(
    JNIEnv*    env,       jclass clazz, jint jOp,  jbyteArray jResp,
    jint       jModuleId, jlong jId,    jlong jId2, jlong jId3, jint jSize,
    jbyteArray jData,     jbyteArray    jData2,     jlong      jCkm,
    jbyteArray jParams,   jbyteArray    jAttrs,     jbyteArray jAttrs2)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR pResp = NULL_PTR, pData = NULL_PTR, pData2 = NULL_PTR;
  CK_ULONG    respLen = 0,      dataLen = 0,      data2Len = 0;
  CK_BYTE_PTR pBParams = NULL_PTR, pAttrsB = NULL_PTR, pAttrs2B = NULL_PTR;
  CK_ULONG    bParamsLen = 0,      attrsBLen = 0,      attrs2BLen = 0;

  CK_BYTE_PTR pPayload = NULL_PTR;
  CK_ULONG    payloadLen = 0;
  jbyteArray  jPayload = NULL_PTR;

  CK_MECHANISM_PTR pMech  = NULL_PTR;
  CK_ATTRIBUTE_PTR pAttrs = NULL_PTR, pAttrs2 = NULL_PTR;
  CK_ULONG         attrsCount = 0,    attrs2Count = 0;

  CK_ULONG id = (CK_ULONG) jId, id2 = (CK_ULONG) jId2, id3 = (CK_ULONG) jId3;;
  CK_ULONG   op = (CK_ULONG) jOp,   moduleId = (CK_ULONG) jModuleId;
  CK_ULONG size = (CK_ULONG) jSize,      ckm = (CK_ULONG) jCkm;

  jByteArrayToC(env, jResp, &pResp, &respLen);
  pResp[0] = 0; // clear the response type byte

  CK_ULONG coreOp = op & 0xFFUL;
  CK_ULONG opVersion = coreOp <= OP_V2_40_MAX ? V2_40
                     : coreOp >= OP_V3_0_MIN && coreOp <= OP_V3_0_MAX ? V3_0
                     : coreOp >= OP_V3_2_MIN && coreOp <= OP_V3_2_MAX ? V3_2
                     : 0;

  ModuleData* module = NULL_PTR;
  if (opVersion == 0) {
    rv = CKR_FUNCTION_NOT_SUPPORTED;
  } else {
    module = getModule(&rv, moduleId, opVersion);
  }

  if (isNOK(rv)) {
    buildErrResp(pResp, respLen, rv);
    jni_release(jResp, pResp);
    return NULL_PTR;
  }

  jByteArrayToC(env, jData,   &pData,    &dataLen);
  jByteArrayToC(env, jData2,  &pData2,   &data2Len);
  jByteArrayToC(env, jParams, &pBParams, &bParamsLen);
  jByteArrayToC(env, jAttrs,  &pAttrsB,  &attrsBLen);
  jByteArrayToC(env, jAttrs2, &pAttrs2B, &attrs2BLen);

  CK_BYTE mechParamsType = bParamsLen > 0 ? pBParams[0] : MP_NO_MECH;

  if (isOK(rv)) {
    CK_BBOOL withMech = mechParamsType != MP_NO_MECH;
    rv = checkInParams(op, dataLen, data2Len, withMech,
            attrsBLen > 0, attrs2BLen > 0);
  }

  if (isNOK(rv)) {
    JNI_RELEASE_BYTE_ARRAYS;
    buildErrResp(pResp, respLen, rv);
    return NULL_PTR;
  }

  if (bParamsLen > 0) {
    pMech = (CK_MECHANISM_PTR) malloc(sizeof(CK_MECHANISM));
    if (pMech == NULL_PTR) {
      rv = CKR_JNI_MEM_ERROR;
    } else {
      pMech->mechanism = ckm;
      rv = parseMechParams(&(pMech->pParameter), &(pMech->ulParameterLen),
              pBParams, bParamsLen);
    }
  }

  if (isOK(rv) && attrsBLen > 0) {
    rv = parseTemplate(&pAttrs, &attrsCount, pAttrsB, attrsBLen);
  }

  if (isOK(rv) && attrs2BLen > 0) {
    rv = parseTemplate(&pAttrs2, &attrs2Count, pAttrs2B, attrs2BLen);
  }

  if (isOK(rv)) {
    rv = cryptoki_query(
           module, coreOp, &pPayload, &payloadLen, pResp, respLen, moduleId,
           id, id2, id3, size, pData, dataLen, pData2, data2Len, pMech,
           pBParams, bParamsLen, pAttrs, attrsCount, pAttrs2, attrs2Count);
  }

  if (isOK(rv)) {
    jPayload = cByteArrayToJ(env, pPayload, payloadLen);
    if (pResp[0] == 0) {
      pResp[0] = RESP_Simple;
    }
  } else {
    buildErrResp(pResp, respLen, rv);
  }

  free_t_null(pPayload);

  JNI_RELEASE_BYTE_ARRAYS;

  if (pMech != NULL_PTR) {
    free_mech(pMech, pBParams);
  }

  if (pAttrs != NULL_PTR && attrsCount > 0) {
    freeParsedTemplate(&pAttrs, attrsCount);
  }

  if (pAttrs2 != NULL_PTR && attrs2Count > 0) {
    freeParsedTemplate(&pAttrs2, attrs2Count);
  }

  return jPayload;
}
