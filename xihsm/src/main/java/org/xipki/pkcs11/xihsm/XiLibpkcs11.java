// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.jni.JniOperation;
import org.xipki.pkcs11.wrapper.jni.JniResp;
import org.xipki.pkcs11.wrapper.jni.JniUtil;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.ParamsType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;

import java.util.HashMap;
import java.util.Map;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
class XiLibpkcs11 {

  private static final Logger LOG = LoggerFactory.getLogger(XiLibpkcs11.class);

  private static final Arch arch = new Arch(true, 8);

  private static final Map<Integer, XiPKCS11Module> moduleMap = new HashMap<>();

  static Arch arch() {
    return arch;
  }

  static void initModule(int moduleId, String modulePath) throws PKCS11Exception {
    if (moduleMap.containsKey(moduleId)) {
      LOG.error("module with module id {} already exists", moduleId);
      throw new PKCS11Exception(JniResp.CKR_JNI_NO_MODULE);
    }

    XiPKCS11Module m = new XiPKCS11Module();
    m.initModule(modulePath);
    moduleMap.put(moduleId, m);
  }

  static void closeModule(int moduleId) throws PKCS11Exception {
    XiPKCS11Module m = moduleMap.remove(moduleId);
    if (m == null) {
      throw new PKCS11Exception(JniResp.CKR_JNI_NO_MODULE);
    }
    m.closeModule();
  }

  static int getVersion(int moduleId) throws PKCS11Exception {
    XiPKCS11Module m = moduleMap.get(moduleId);
    if (m == null) {
      LOG.error("found no module with module id {}", moduleId);
      throw new PKCS11Exception(JniResp.CKR_JNI_NO_MODULE);
    }
    return m.getCkInfo().cryptokiVersion().version();
  }

  protected static byte[] doQuery(
      int opCode, byte[] resp, int moduleId, long id, long id2, long id3,
      int size, byte[] data, byte[] data2, long ckm, byte[] pMechParams,
      byte[] pTemplate, byte[] pTemplate2) throws PKCS11Exception {
    JniOperation op = JniOperation.ofCode(opCode);
    if (op == null) {
      throw new PKCS11Exception(JniResp.CKR_JNI_BAD_OP);
    }

    // data1
    switch (op) {
      case C_DecapsulateKey:
      // attribute value
      case C_GetAttributeValue:
      // Digest
      // sign & verify
      case C_SignX:
      case C_SignUpdate:
        if (data == null) {
          LOG.error("data shall not be null");
          throw new PKCS11Exception(JniResp.CKR_JNI_BAD_ARG);
        }
    }

    // data2:
    if (op == JniOperation.C_LoginUser) {
      if (data2 == null) {
        LOG.error("data2 shall not be null");
        throw new PKCS11Exception(JniResp.CKR_JNI_BAD_ARG);
      }
    }

    XiPKCS11Module m = moduleMap.get(moduleId);
    if (m == null) {
      LOG.error("found no module with module id {}", moduleId);
      throw new PKCS11Exception(JniResp.CKR_JNI_NO_MODULE);
    }

    switch (op) {
      // module management
      case C_Initialize:
        m.C_Initialize(id2); // flags
        return null;
      case C_GetInfo:
        return m.C_GetInfo().getEncoded(arch);
      case C_Finalize:
        m.C_Finalize();
        return null;
      // slot management
      case C_GetSlotList: {
        boolean tokenPresentOnly = id2 != 0; // flags
        long[] slotList = m.C_GetSlotList(tokenPresentOnly);
        return JniUtil.encodeLongs(arch, slotList);
      }
    }

    long slotID = id;
    switch (op) {
      case C_GetSlotInfo:
        return m.C_GetSlotInfo(slotID).getEncoded(arch);
      case C_GetTokenInfo:
        return m.C_GetTokenInfo(slotID).getEncoded(arch);
      case C_GetMechanismList: {
        long[] mechList = m.C_GetMechanismList(slotID);
        return JniUtil.encodeLongs(arch, mechList);
      }
      case C_GetMechanismInfo:
        return m.C_GetMechanismInfo(slotID, id2).getEncoded(arch);
      case C_OpenSession: {
        long v = m.C_OpenSession(slotID, id2); // flags
        return JniUtil.encodeLong(arch, v);
      }
      case C_CloseAllSessions:
        m.C_CloseAllSessions(slotID);
        return null;
    }

    // session based operations
    CkMechanism mech = null;
    if (pMechParams != null && pMechParams.length > 0) {
      CkParams params = pMechParams[0] == ParamsType.NullParams.getCode()
          ? null : CkParams.decodeParams(arch, pMechParams);
      mech = new CkMechanism(ckm, params);
    }

    Template template  = (pTemplate == null)  ? null : Template.decode(arch, pTemplate);
    Template template2 = (pTemplate2 == null) ? null : Template.decode(arch, pTemplate2);

    switch (op) {
      // key management
      case C_GenerateKey:
      case C_GenerateKeyPair:
      case C_DecapsulateKey:
      // Digest
      case C_DigestX:
      // sign & verify
      case C_SignX:
      case C_SignInit:
        if (mech == null) {
          LOG.error("mechanism shall not be null");
          throw new PKCS11Exception(JniResp.CKR_JNI_BAD_ARG);
        }
    }

    switch (op) {
      // key management
      case C_GenerateKey:
      case C_GenerateKeyPair:
      case C_DecapsulateKey:
      // object management
      case C_CreateObject:
      case C_CopyObject:
      case C_FindObjectsInit:
      case C_SetAttributeValue:
        if (template == null) {
          LOG.error("template shall not be null");
          throw new PKCS11Exception(JniResp.CKR_JNI_BAD_ARG);
        }
    }

    if (op == JniOperation.C_GenerateKeyPair) {
      if (template2 == null) {
        LOG.error("template2 shall not be null");
        throw new PKCS11Exception(JniResp.CKR_JNI_BAD_ARG);
      }
    }

    long hSession = id;
    byte[] payload = null;

    switch (op) {
      // session management
      case C_CloseSession:
        m.C_CloseSession(hSession);
        break;
      case C_GetSessionInfo:
        payload = m.C_GetSessionInfo(hSession).getEncoded(arch());
        break;
      case C_SessionCancel:
        m.C_SessionCancel(hSession, id2); // flags
        break;
      // key management
      case C_GenerateKey: {
        long hKey = m.C_GenerateKey(hSession, mech, template);
        payload = JniUtil.encodeLong(arch, hKey);
        break;
      }
      case C_GenerateKeyPair: {
        long[] hKeys = m.C_GenerateKeyPair(hSession, mech, template, template2);
        payload = JniUtil.encodeLongs(arch, hKeys);
        break;
      }
      case C_DecapsulateKey: {
        long hKey = m.C_DecapsulateKey(hSession, mech, id2, // hPrivateKey
                      data, template);
        payload = JniUtil.encodeLong(arch, hKey);
        break;
      }
      case C_DeriveKey: {
        long hKey = m.C_DeriveKey(hSession, mech, id2, // hBaseKey
                      template);
        payload = JniUtil.encodeLong(arch, hKey);
        break;
      }
      // object management
      case C_CreateObject: {
        long hKey = m.C_CreateObject(hSession, template);
        payload = JniUtil.encodeLong(arch, hKey);
        break;
      }
      case C_CopyObject: {
        long hNewObj = m.C_CopyObject(hSession, id2, // hObject
                        template);
        payload = JniUtil.encodeLong(arch, hNewObj);
        break;
      }
      case C_DestroyObject:
        m.C_DestroyObject(hSession, id2); // hObject
        break;
      case C_FindObjectsInit:
        m.C_FindObjectsInit(hSession, template);
        break;
      case C_FindObjects: {
        long[] hObjects = m.C_FindObjects(hSession, size); // maxCount = size
        payload = JniUtil.encodeLongs(arch, hObjects);
        break;
      }
      case C_FindObjectsFinal:
        m.C_FindObjectsFinal(hSession);
        break;
      // PIN
      case C_Login:
        m.C_Login(hSession, id2, // userType
            data);
        break;
      case C_LoginUser:
        m.C_LoginUser(hSession, id2, // userType
            data, data2);
        break;
      case C_Logout:
        m.C_Logout(hSession);
        break;
      // attribute value
      case C_GetAttributeValue: {
        long[] types = JniUtil.readLongs(arch, data);
        Template temp = m.C_GetAttributeValue(hSession, id2, // hObject
                          types);
        buildLongResp(PKCS11T.CKR_OK, resp);
        payload = temp.getEncoded(arch());
        break;
      }
      case C_GetAttributeValueX: {
        Template temp = m.C_GetAttributeValue(hSession, id2, // hObject
                          new long[] {id3});
        buildLongResp(PKCS11T.CKR_OK, resp);
        payload = temp.getEncoded(arch());
        break;
      }
      case C_SetAttributeValue:
        m.C_SetAttributeValue(hSession, id2, // hObject
            template);
        break;
      // Digest
      case C_DigestX:
        payload = m.C_DigestX(hSession, mech, data, id2, data2);
        break;
      // Sign
      case C_SignX:
        payload = m.C_SignX(hSession, mech, id2, data); // hKey: id2
        break;
      // Sign
      case C_DecryptX:
        payload = m.C_DecryptX(hSession, mech, id2, data); // hKey: id2
        break;
      case C_SignInit:
        m.C_SignInit(hSession, mech, id2); // hKey
        break;
      case C_SignUpdate:
        m.C_SignUpdate(hSession, data);
        break;
      case C_SignFinal:
        payload = m.C_SignFinal(hSession);
        break;
      default:
        LOG.error("invalid OP {}", op);
        throw new PKCS11Exception(JniResp.CKR_JNI_BAD_OP);
    }

    return payload;
  }

  private static void buildLongResp(long value, byte[] resp) {
    new JniResp.JniLongResp(value).writeTo(arch, resp);
  }

}
