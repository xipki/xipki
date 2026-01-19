// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

#include "pkcs11wrapper.h"

/*********************************
 * Mechanism
 *********************************/

#define mallocParams(name, type) \
  type* name = (type*) malloc(sizeof(type)); \
  checkMalloc(name); \
  *paramsLen = sizeof(type); \
  *pParams = name

#define longField(valueField) \
  returnBadParamsIf(off + SIZE_LONG > maxOff); \
  valueField = bytes2long(pbParams, &off)

#define boolField(valueField) \
  returnBadParamsIf(off + 1 > maxOff); \
  valueField = pbParams[off++] == 0 ? CK_FALSE : CK_TRUE

#define byteField(valueField) \
  returnBadParamsIf(off + 1 > maxOff); \
  valueField = pbParams[off++]

#define byteArrayField(valueField, lenField) \
  returnBadParamsIf(off + SIZE_LONG > maxOff); \
  lenField = bytes2long(pbParams, &off); \
  returnBadParamsIf(off + lenField > maxOff); \
  valueField = (lenField == 0) ? NULL_PTR : (CK_BYTE_PTR)(pbParams + off); \
  off += lenField

#define byteArrayFieldPointLen(valueField, lenField) \
  returnBadParamsIf(off + SIZE_LONG > maxOff); \
  lenField = (CK_ULONG_PTR) (pbParams + off); \
  off += SIZE_LONG; \
  returnBadParamsIf(off + *(lenField) > maxOff); \
  valueField = (*(lenField) == 0) ? NULL_PTR : (CK_BYTE_PTR)(pbParams + off); \
  off += *(lenField)

#define byteArrayFieldNoLen(valueField) \
{ \
  returnBadTemplateIf(off + SIZE_LONG > maxOff); \
  CK_ULONG lenField = bytes2long(pbParams, &off); \
  returnBadParamsIf(off + lenField > maxOff); \
  valueField = (lenField == 0) ? NULL_PTR : (CK_BYTE_PTR)(pbParams + off); \
  off += lenField; \
}

#define byteArrayFieldFixLen(valueField, len) \
{ \
  returnBadParamsIf(off + SIZE_LONG > maxOff); \
  CK_ULONG lenField = bytes2long(pbParams, &off); \
  returnBadParamsIf(lenField != len || off + lenField > maxOff); \
  valueField = (lenField == 0) ? NULL_PTR : (CK_BYTE_PTR)(pbParams + off); \
  off += lenField; \
}

#define copyByteArrayField(valueField, len) \
  returnBadTemplateIf(off + SIZE_LONG > maxOff); \
  CK_ULONG lenField = bytes2long(pbParams, &off); \
  returnBadTemplateIf(lenField != len || off + lenField > maxOff); \
  memcpy(valueField, pbParams + off, lenField); \
  off += lenField

void freeCkParam(CK_VOID_PTR* param, CK_BYTE_PTR pBParams)
{
  if (param == NULL_PTR|| *param == NULL_PTR) {
    return;
  }

  CK_BYTE paramType = pBParams[0];
  switch(paramType) {
    case MP_NullParams:
    case MP_LongParams:
    case MP_ByteArrayParams:
      break;
    default:
      free_t_null(*param);
  }
}

CK_RV parseMechParams(CK_VOID_PTR* pParams, CK_ULONG* paramsLen,
                      CK_BYTE_PTR pbParams, CK_ULONG  bParamsLen)
{
  // check buffer overflow
  const CK_ULONG maxOff = bParamsLen;
  CK_BYTE paramType = pbParams[0];
  CK_ULONG off = 1;

  switch(paramType) {
    case MP_NullParams: // no malloc here
      *paramsLen = 0;
      *pParams   = NULL_PTR;
      break;
    case MP_LongParams: // no malloc here
      returnBadParamsIf(off + SIZE_LONG > maxOff);
      *paramsLen = SIZE_LONG;
      *pParams   = pbParams + off;
      off += *paramsLen;
      break;
    case MP_ByteArrayParams: // no malloc here
      returnBadParamsIf(off + SIZE_LONG > maxOff);
      *paramsLen = bytes2long(pbParams, &off);
      returnBadParamsIf(off + (*paramsLen) > maxOff);
      *pParams   = pbParams + off;
      off += *paramsLen;
      break;
    case MP_GCM_PARAMS: {
      mallocParams(p, CK_GCM_PARAMS);
      byteArrayField(p->pIv,  p->ulIvLen);
      p->ulIvBits = 0;

      byteArrayField(p->pAAD, p->ulAADLen);
      longField(p->ulTagBits);
      break;
    }
    case MP_EDDSA_PARAMS: {
      mallocParams(p, CK_EDDSA_PARAMS);
      boolField(p->phFlag);
      byteArrayField(p->pContextData, p->ulContextDataLen);
      break;
    }
    case MP_SIGN_ADDITIONAL_CONTEXT: {
      mallocParams(p, CK_SIGN_ADDITIONAL_CONTEXT);
      longField(p->hedgeVariant);
      byteArrayField(p->pContext, p->ulContextLen);
      break;
    }
    case MP_HASH_SIGN_ADDITIONAL_CONTEXT: {
      mallocParams(p, CK_HASH_SIGN_ADDITIONAL_CONTEXT);
      longField(p->hedgeVariant);
      byteArrayField(p->pContext, p->ulContextLen);
      longField(p->hash);
      break;
    }
    case MP_RSA_PKCS_PSS_PARAMS: {
      mallocParams(p, CK_RSA_PKCS_PSS_PARAMS);
      longField(p->hashAlg);
      longField(p->mgf);
      longField(p->sLen);
      break;
    }
    case MP_XEDDSA_PARAMS: {
      mallocParams(p, CK_XEDDSA_PARAMS);
      longField(p->hash);
      break;
    }
    default:
      return CKR_JNI_BAD_PARAMS;
  }

  returnBadParamsIf(off != maxOff);
  return CKR_OK;
}
