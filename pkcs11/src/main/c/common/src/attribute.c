// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

#include "pkcs11wrapper.h"

/*********************************
 * Attributes
 *********************************/

#define free_tmpl(TMPL, COUNT) \
  for (int i = 0; i < COUNT; i++) { \
    if (TMPL[i].ulValueLen > 0 \
         && TMPL[i].ulValueLen <= MAX_ATTR_VALUE_LEN) { \
      free_t_null(TMPL[i].pValue); \
    } \
  } \
  free_t_null(TMPL)

static CK_BYTE getAttrValueType(CK_ULONG cka)
{
  switch(cka) {
    case CKA_ALWAYS_AUTHENTICATE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_COLOR:
    case CKA_COPYABLE:
    case CKA_DECAPSULATE:
    case CKA_DECRYPT:
    case CKA_DERIVE:
    case CKA_DESTROYABLE:
    case CKA_ENCAPSULATE:
    case CKA_ENCRYPT:
    case CKA_EXTRACTABLE:
    case CKA_HAS_RESET:
    case CKA_LOCAL:
    case CKA_MODIFIABLE:
    case CKA_NEVER_EXTRACTABLE:
    case CKA_OTP_USER_FRIENDLY_MODE:
    case CKA_PRIVATE:
    case CKA_RESET_ON_INIT:
    case CKA_SENSITIVE:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_TOKEN:
    case CKA_TRUSTED:
    case CKA_UNWRAP:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_WRAP:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_X2RATCHET_BOBS1STMSG:
    case CKA_X2RATCHET_ISALICE:
      return AV_BOOL;
    case CKA_BITS_PER_PIXEL:
    case CKA_CERTIFICATE_CATEGORY:
    case CKA_CERTIFICATE_TYPE:
    case CKA_CHAR_COLUMNS:
    case CKA_CHAR_ROWS:
    case CKA_CLASS:
    case CKA_HSS_KEYS_REMAINING:
    case CKA_HSS_LEVELS:
    case CKA_HSS_LMOTS_TYPE:
    case CKA_HSS_LMS_TYPE:
    case CKA_HW_FEATURE_TYPE:
    case CKA_JAVA_MIDP_SECURITY_DOMAIN:
    case CKA_KEY_GEN_MECHANISM:
    case CKA_KEY_TYPE:
    case CKA_MECHANISM_TYPE:
    case CKA_MODULUS_BITS:
    case CKA_NAME_HASH_ALGORITHM:
    case CKA_OBJECT_VALIDATION_FLAGS:
    case CKA_OTP_CHALLENGE_REQUIREMENT:
    case CKA_OTP_COUNTER_REQUIREMENT:
    case CKA_OTP_FORMAT:
    case CKA_OTP_LENGTH:
    case CKA_OTP_PIN_REQUIREMENT:
    case CKA_OTP_TIME_INTERVAL:
    case CKA_OTP_TIME_REQUIREMENT:
    case CKA_PARAMETER_SET:
    case CKA_PIXEL_X:
    case CKA_PIXEL_Y:
    case CKA_PRIME_BITS:
    case CKA_PROFILE_ID:
    case CKA_RESOLUTION:
    case CKA_SUBPRIME_BITS:
    case CKA_TRUST_CLIENT_AUTH:
    case CKA_TRUST_CODE_SIGNING:
    case CKA_TRUST_EMAIL_PROTECTION:
    case CKA_TRUST_IPSEC_IKE:
    case CKA_TRUST_OCSP_SIGNING:
    case CKA_TRUST_SERVER_AUTH:
    case CKA_TRUST_TIME_STAMPING:
    case CKA_VALIDATION_AUTHORITY_TYPE:
    case CKA_VALIDATION_FLAG:
    case CKA_VALIDATION_LEVEL:
    case CKA_VALIDATION_TYPE:
    case CKA_VALUE_BITS:
    case CKA_VALUE_LEN:
    case CKA_X2RATCHET_BAGSIZE:
    case CKA_X2RATCHET_NR:
    case CKA_X2RATCHET_NS:
    case CKA_X2RATCHET_PNS:
      return AV_LONG;
    case CKA_END_DATE:
    case CKA_START_DATE:
      return AV_DATE;
    case CKA_VALIDATION_VERSION:
      return AV_VERSION;
    case CKA_AC_ISSUER:
    case CKA_APPLICATION:
    case CKA_ATTR_TYPES:
    case CKA_BASE:
    case CKA_CHAR_SETS:
    case CKA_CHECK_VALUE:
    case CKA_COEFFICIENT:
    case CKA_DEFAULT_CMS_ATTRIBUTES:
    case CKA_EC_PARAMS:
    case CKA_EC_POINT:
    case CKA_ENCODING_METHODS:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_GOST28147_PARAMS:
    case CKA_GOSTR3410_PARAMS:
    case CKA_GOSTR3411_PARAMS:
    case CKA_HASH_OF_CERTIFICATE:
    case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
    case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
    case CKA_ID:
    case CKA_ISSUER:
    case CKA_LABEL:
    case CKA_MIME_TYPES:
    case CKA_MODULUS:
    case CKA_OBJECT_ID:
    case CKA_OTP_COUNTER:
    case CKA_OTP_SERVICE_IDENTIFIER:
    case CKA_OTP_SERVICE_LOGO:
    case CKA_OTP_SERVICE_LOGO_TYPE:
    case CKA_OTP_TIME:
    case CKA_OTP_USER_IDENTIFIER:
    case CKA_OWNER:
    case CKA_PRIME:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_PRIVATE_EXPONENT:
    case CKA_PUBLIC_CRC64_VALUE:
    case CKA_PUBLIC_EXPONENT:
    case CKA_PUBLIC_KEY_INFO:
    case CKA_REQUIRED_CMS_ATTRIBUTES:
    case CKA_SEED:
    case CKA_SERIAL_NUMBER:
    case CKA_SUBJECT:
    case CKA_SUBPRIME:
    case CKA_SUPPORTED_CMS_ATTRIBUTES:
    case CKA_UNIQUE_ID:
    case CKA_URL:
    case CKA_VALIDATION_CERTIFICATE_IDENTIFIER:
    case CKA_VALIDATION_CERTIFICATE_URI:
    case CKA_VALIDATION_COUNTRY:
    case CKA_VALIDATION_MODULE_ID:
    case CKA_VALIDATION_PROFILE:
    case CKA_VALIDATION_VENDOR_URI:
    case CKA_VALUE:
    case CKA_X2RATCHET_BAG:
    case CKA_X2RATCHET_CKR:
    case CKA_X2RATCHET_CKS:
    case CKA_X2RATCHET_DHP:
    case CKA_X2RATCHET_DHR:
    case CKA_X2RATCHET_DHS:
    case CKA_X2RATCHET_HKR:
    case CKA_X2RATCHET_HKS:
    case CKA_X2RATCHET_NHKR:
    case CKA_X2RATCHET_NHKS:
    case CKA_X2RATCHET_RK:
      return AV_BYTE_ARRAY;
    case CKA_ALLOWED_MECHANISMS:
    case CKA_HSS_LMOTS_TYPES:
    case CKA_HSS_LMS_TYPES:
      return AV_LONG_ARRAY;
    case CKA_DECAPSULATE_TEMPLATE:
    case CKA_DERIVE_TEMPLATE:
    case CKA_ENCAPSULATE_TEMPLATE:
    case CKA_UNWRAP_TEMPLATE:
    case CKA_WRAP_TEMPLATE:
      return AV_TEMPLATE;
    default:
      return AV_UNKNOWN;
  }
}

static CK_RV do_parseTemplate(
    CK_ATTRIBUTE_PTR* attrs, CK_ULONG *count,
    CK_BYTE_PTR       bytes, CK_ULONG *off,   CK_ULONG maxOff)
{
  returnBadTemplateIf((*off) + SIZE_LONG > maxOff);
  *count = bytes2long(bytes, off);

  // minimal needed size
  returnBadTemplateIf((*off) + (*count) * (2 * SIZE_LONG) > maxOff)
  *attrs = (CK_ATTRIBUTE_PTR) malloc((*count) * sizeof(CK_ATTRIBUTE));
  checkMalloc(*attrs);

  CK_RV rv;
  for (int i = 0; i < *count; i++) {
    (*attrs)[i].ulValueLen = 0;
    (*attrs)[i].pValue     = NULL_PTR;
  }

  CK_ATTRIBUTE_PTR attr;
  CK_ULONG valueLen;
  CK_BYTE valueType;
  for (int i = 0; i < *count; i++) {
    returnBadTemplateIf((*off) + 2 * SIZE_LONG > maxOff);

    attr = &((*attrs)[i]);
    attr->type = bytes2long(bytes, off);
    valueLen   = bytes2long(bytes, off);
    if (valueLen == 0) {
      continue;
    }

    returnBadTemplateIf((*off) + valueLen > maxOff);
    valueType = getAttrValueType(attr->type);

    // assert valueLen in bytes is correct
    CK_ULONG expectedValueLen =
         (valueType == AV_BOOL)    ? 1
       : (valueType == AV_LONG)    ? SIZE_LONG
       : (valueType == AV_DATE)    ? 8
       : (valueType == AV_VERSION) ? 2 : 0;

    returnBadTemplateIf(expectedValueLen != 0 && expectedValueLen != valueLen);

    if (valueType == AV_BOOL) {
      attr->ulValueLen = 1;
      if (bytes[*off] != 0) {
        bytes[*off] = CK_TRUE;
      }
      attr->pValue = bytes + (*off);
     (*off)++;
    } else if (valueType == AV_LONG) {
      attr->ulValueLen = SIZE_LONG;
      attr->pValue = bytes + (*off);
      *off += SIZE_LONG;
    } else if (valueType == AV_DATE) {
      attr->ulValueLen = sizeof(CK_DATE);
      CK_DATE* date = (CK_DATE*) malloc(attr->ulValueLen);
      checkMalloc(date);

      memcpy(date->year,  bytes + *off, 4);
      *off += 4;
      memcpy(date->month, bytes + *off, 2);
      *off += 2;
      memcpy(date->day,   bytes + *off, 2);
      *off += 2;

      attr->pValue = (CK_VOID_PTR) date;
    } else if (valueType == AV_VERSION) {
      attr->ulValueLen = sizeof(CK_VERSION);
      CK_VERSION* version = (CK_VERSION*) malloc(attr->ulValueLen);
      checkMalloc(version);

      version->major = bytes[(*off)++];
      version->minor = bytes[(*off)++];
      attr->pValue = (CK_VOID_PTR) version;
    } else if (valueType == AV_BYTE_ARRAY || valueType == AV_LONG_ARRAY) {
      attr->ulValueLen = valueLen;
      attr->pValue     = bytes + (*off);
      *off += valueLen;
    } else if (valueType == AV_TEMPLATE) {
      // value is a Template
      CK_ATTRIBUTE_PTR subTemplate;
      CK_ULONG subCount;
      rv = do_parseTemplate(&subTemplate, &subCount, bytes, off,
                (*off) + valueLen);
      if (isNOK(rv)) {
        return rv;
      }

      attr->ulValueLen = subCount * sizeof(CK_ATTRIBUTE);
      attr->pValue = (CK_VOID_PTR) subTemplate;
    } else {
      return CKR_JNI_BAD_TEMPLATE;
    }
  }

  return CKR_OK;
}

CK_RV parseTemplate(CK_ATTRIBUTE_PTR* attrs, CK_ULONG *count,
                    CK_BYTE_PTR       bytes, CK_ULONG maxOff)
{
  CK_ULONG off = 0;
  return do_parseTemplate(attrs, count, bytes, &off, maxOff);
}

static CK_ULONG getEncodedLenOfTemplate(CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
  CK_ULONG size = SIZE_LONG;
  if (count == 0) {
    return size;
  }

  CK_ATTRIBUTE attr;
  CK_BYTE valueType;
  CK_ULONG valueLen;

  for (int i = 0; i < count; i++) {
    attr = attrs[i];
    size += 2 * SIZE_LONG; // type and valueLen
    valueLen = attr.ulValueLen;
    if (valueLen > MAX_ATTR_VALUE_LEN || valueLen == 0) {
      continue; // do not encode the value
    }

    valueType = getAttrValueType(attr.type);
    size +=  (valueType == AV_BOOL)    ? 1
           : (valueType == AV_LONG)    ? SIZE_LONG
           : (valueType == AV_DATE)    ? 8
           : (valueType == AV_VERSION) ? 2
           : (valueType == AV_BYTE_ARRAY) ? valueLen
           : (valueType == AV_LONG_ARRAY) ? valueLen
           : 0; // do not encode the value
  }

  return size;
}

static CK_RV encodeTemplate(CK_BYTE_PTR*      dest, CK_ULONG* destLen,
                            CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
  CK_ULONG off = 0;

  if (count == 0) {
    *dest = (CK_BYTE_PTR) malloc(SIZE_LONG);
    checkMalloc(*dest);
    *destLen = SIZE_LONG;
    long2bytes(*dest, &off, count);
    return CKR_OK;
  }

  CK_ULONG len = getEncodedLenOfTemplate(attrs, count);
  *dest = (CK_BYTE_PTR) malloc(len);
  checkMalloc(*dest);

  *destLen = len;

  CK_ATTRIBUTE attr;
  CK_BYTE valueType;
  CK_ULONG valueLen;

  long2bytes(*dest, &off, count);

  for (int i = 0; i < count; i++) {
    attr = attrs[i];
    long2bytes(*dest, &off, attr.type);
    valueType = getAttrValueType(attr.type);

    valueLen = attr.ulValueLen;
    if (valueLen > MAX_ATTR_VALUE_LEN) {
      valueLen = 0;
    } else if (valueLen != 0) {
      valueLen = (valueType == AV_BOOL)   ? 1
           : (valueType == AV_LONG)       ? SIZE_LONG
           : (valueType == AV_DATE)       ? 8
           : (valueType == AV_VERSION)    ? 2
           : (valueType == AV_BYTE_ARRAY) ? valueLen
           : (valueType == AV_LONG_ARRAY) ? valueLen
           : 0; // do not encode the value
    }

    long2bytes(*dest, &off, valueLen);

    if (valueLen == 0) {
      continue;
    }

    if (valueType == AV_BOOL || valueType == AV_LONG
        || valueType == AV_BYTE_ARRAY || valueType == AV_LONG_ARRAY) {
      memcpy2(*dest, &off, attr.pValue, valueLen);
    } else if (valueType == AV_DATE) {
      CK_DATE* date = (CK_DATE*) attr.pValue;
      memcpy2(*dest, &off, date->year,  4);
      memcpy2(*dest, &off, date->month, 2);
      memcpy2(*dest, &off, date->day,   2);
    } else if (valueType == AV_VERSION) {
      copyVersion(*dest, &off, *((CK_VERSION*) attr.pValue));
    } // end if
  } // end for

  return CKR_OK;
}

/******************************************
 * Cryptoki Functions: GetAttributeValue
 ******************************************/

CK_RV getAttributeValue(CK_FUNC_LIST_PTR funcs,
    CK_BYTE_PTR* pPayload,      CK_ULONG* payloadLen,
    CK_BYTE_PTR  pResp,         CK_ULONG respLen,
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_BYTE_PTR pData,          CK_ULONG dataLen)
{
  // hSession = id, hObject = id2, types = pPayload
  CK_ULONG count = dataLen / SIZE_LONG;
  CK_ULONG_PTR types = (CK_ULONG_PTR) pData;

  if (count == 0) {
    buildLongResp(pResp, respLen, CKR_OK);
    encodeTemplate(pPayload, payloadLen, NULL_PTR, 0);
    return CKR_OK;
  }

  CK_ULONG valueLens[count];

  CK_BBOOL allTypesWithFixedLen = CK_TRUE;
  for (int i = 0; i < count; i++) {
    CK_BYTE valueType = getAttrValueType(types[i]);
    valueLens[i] =  (valueType == AV_BOOL)    ? 1
                  : (valueType == AV_LONG)    ? SIZE_LONG
                  : (valueType == AV_VERSION) ? sizeof(CK_VERSION)
                  : (valueType == AV_DATE)    ? sizeof(CK_DATE)
                  : 0;

    if (valueLens[i] == 0) {
      allTypesWithFixedLen = CK_FALSE;
      break;
    }
  }

  CK_ATTRIBUTE_PTR pTemp = (CK_ATTRIBUTE_PTR)
                                malloc(count * sizeof(CK_ATTRIBUTE));
  checkMalloc(pTemp);

  // prepare the template
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG valueLen;

  if (allTypesWithFixedLen) {
    for (int i = 0; i < count; i++) {
      attr = &(pTemp[i]);
      attr->type       = types[i];
      attr->pValue     = (CK_VOID_PTR) malloc(valueLens[i]);
      attr->ulValueLen = (attr->pValue == NULL_PTR) ? 0 : valueLens[i];
    }
  } else {
    for (int i = 0; i < count; i++) {
      attr = &(pTemp[i]);
      attr->type       = types[i];
      attr->pValue     = NULL_PTR;
      attr->ulValueLen = 0;
    }

    funcs->C_GetAttributeValue(hSession, hObject, pTemp, count);
    for (int i = 0; i < count; i++) {
      attr = &(pTemp[i]);
      valueLen = attr->ulValueLen;
      if (valueLen > 0 && valueLen <= MAX_ATTR_VALUE_LEN) {
        attr->pValue = malloc(valueLen);
      } else {
        attr->pValue     = NULL_PTR;
        attr->ulValueLen = 0;
      }
    }
  }

  // get the real value
  CK_RV rv = funcs->C_GetAttributeValue(hSession, hObject, pTemp, count);
  encodeTemplate(pPayload, payloadLen, pTemp, count);
  buildLongResp(pResp, respLen, rv);
  free_tmpl(pTemp, count);
  return CKR_OK;
}

CK_RV getAttributeValueOfTemplate(CK_FUNC_LIST_PTR funcs,
    CK_BYTE_PTR* pPayload,      CK_ULONG* payloadLen,
    CK_BYTE_PTR  pResp,         CK_ULONG respLen,
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG attrType)
{
  CK_ATTRIBUTE_PTR rootAttr = (CK_ATTRIBUTE_PTR) malloc(sizeof(CK_ATTRIBUTE));
  checkMalloc(rootAttr);

  rootAttr->type       = attrType;
  rootAttr->ulValueLen = 0;
  rootAttr->pValue     = NULL_PTR;

  CK_RV rv = funcs->C_GetAttributeValue(hSession, hObject, rootAttr, 1);

  CK_ULONG valueLen;
  if (isOK(rv)) {
    valueLen = rootAttr->ulValueLen;
    if (valueLen > 0 && valueLen <= MAX_ATTR_VALUE_LEN
        && valueLen % sizeof(CK_ATTRIBUTE) == 0) {
      rootAttr->pValue = malloc(valueLen);
    } else {
      rootAttr->pValue     = NULL_PTR;
      rootAttr->ulValueLen = 0;
      rv = CKR_ATTRIBUTE_VALUE_INVALID;
    }
  }

  if (isOK(rv)) {
    rv = funcs->C_GetAttributeValue(hSession, hObject, rootAttr, 1);
  }

  CK_ULONG count = 0;
  CK_ATTRIBUTE_PTR newTemplate = NULL_PTR;

  if (isOK(rv)) {
    count = rootAttr->ulValueLen / sizeof(CK_ATTRIBUTE);
    newTemplate = (CK_ATTRIBUTE_PTR) rootAttr->pValue;

    CK_ATTRIBUTE_PTR attr;
    CK_BYTE valueType;
    CK_BBOOL isValid;

    for (int i = 0; i < count; i++) {
      attr = &newTemplate[i];
      valueLen = attr->ulValueLen;
      isValid  = valueLen > 0 && valueLen <= MAX_ATTR_VALUE_LEN;
      if (isValid) {
        valueType = getAttrValueType(attr->type);
        isValid = (valueType == AV_BOOL || valueType == AV_LONG ||
                   valueType == AV_DATE || valueType == AV_VERSION ||
                   valueType == AV_BYTE_ARRAY ||
                   valueType == AV_LONG_ARRAY);
      }

      if (isValid) {
        attr->pValue = malloc(valueLen);
      } else {
        attr->pValue = NULL_PTR;
        attr->ulValueLen = 0;
      }
    }

    CK_BBOOL withValidAttrs = CK_FALSE;
    for (int i = 0; i < count; i++) {
      if (newTemplate[i].ulValueLen != 0) {
        withValidAttrs = CK_TRUE;
        break;
      }
    }

    if (withValidAttrs == CK_FALSE) {
      rv = CKR_ATTRIBUTE_VALUE_INVALID;
    }
  }

  if (isOK(rv)) {
    rv = funcs->C_GetAttributeValue(hSession, hObject, rootAttr, 1);
  }

  buildLongResp(pResp, respLen, rv);
  if (isOK(rv)) {
    encodeTemplate(pPayload, payloadLen, newTemplate, count);
  } else {
    encodeTemplate(pPayload, payloadLen, NULL_PTR, 0);
  }

  if (newTemplate != NULL_PTR && count > 0) {
    free_tmpl(newTemplate, count);
  }

  free_t_null(rootAttr);
  return CKR_OK;
}

void freeParsedTemplate(CK_ATTRIBUTE_PTR* attrs, CK_ULONG count)
{
  CK_ATTRIBUTE attr;
  CK_BYTE valueType;
  CK_ULONG subCount;

  for (int i = 0; i < count; i++) {
    attr = (*attrs)[i];
    if (attr.pValue == NULL_PTR) {
      continue;
    }

    valueType = getAttrValueType(attr.type);
    if (valueType == AV_DATE || valueType == AV_VERSION) {
      free_t_null(attr.pValue);
    } else if (valueType == AV_TEMPLATE) {
      subCount = attr.ulValueLen / sizeof(CK_ATTRIBUTE);
      if (attr.pValue != NULL_PTR && subCount > 0) {
        CK_ATTRIBUTE_PTR subAttrs = (CK_ATTRIBUTE_PTR) attr.pValue;
        freeParsedTemplate(&subAttrs, subCount);
      }
    }
  }

  free_t_null(*attrs);
}
