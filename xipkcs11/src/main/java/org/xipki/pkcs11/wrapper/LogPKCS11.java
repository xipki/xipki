// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.jni.PKCS11;
import org.xipki.pkcs11.wrapper.type.CkInfo;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkSessionInfo;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.util.codec.Args;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A wrapper of {@link PKCS11} which logs the input, output and error of calling
 * PKCS#11 functions.
 *
 * @author Lijun Liao (xipki)
 */
public class LogPKCS11 {

  private static final Logger LOG = LoggerFactory.getLogger(LogPKCS11.class);

  private final boolean debugEnabled = LOG.isDebugEnabled();

  private final PKCS11Loader pkcs11Loader;

  private final PKCS11Module module;

  private PKCS11 pkcs11;

  LogPKCS11(String modulePath, PKCS11Module module) {
    this.pkcs11Loader = new PKCS11Loader(modulePath);
    this.module = Args.notNull(module, "module");
  }

  public synchronized void reconnect() throws PKCS11Exception {
    close();
    pkcs11 = null;
    pkcs11();
    LOG.info("reconnected PKCS#11");
  }

  private synchronized PKCS11 pkcs11() throws PKCS11Exception {
    if (pkcs11 == null) {
      try {
        pkcs11 = pkcs11Loader.newPKCS11();
      } catch (IOException e) {
        LOG.error("Could not connect to PKCS#11 module", e);
        throw new PKCS11Exception(PKCS11T.CKR_CRYPTOKI_NOT_INITIALIZED);
      }
    }

    return pkcs11;
  }

  /* ***************************************
   * PKCS#11 V2.x Functions
   * ***************************************/

  public void C_Finalize() throws PKCS11Exception {
    String method = "C_Finalize";
    debugIn(method, null);
    try {
      pkcs11().C_Finalize();
      debugOut(method, null);
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public CkInfo C_GetInfo() throws PKCS11Exception {
    String method = "C_GetInfo";
    debugIn(method, null);
    try {
      return toNonNullT(method, null, pkcs11().C_GetInfo());
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public long[] C_GetSlotList(boolean tokenPresent) throws PKCS11Exception {
    String method = "C_GetSlotList";
    debugIn(method, null);
    try {
      long[] longs = pkcs11().C_GetSlotList(tokenPresent);
      long[] rv = (longs == null) ? new long[0] : longs;
      debugOut(method, null, Arrays.toString(rv));
      return rv;
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public CkSlotInfo C_GetSlotInfo(long slotID) throws PKCS11Exception {
    String method = "C_GetSlotInfo";
    debugIn(method, null, "slotID={}", slotID);
    try {
      return toNonNullT(method, null, pkcs11().C_GetSlotInfo(slotID));
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public CkTokenInfo C_GetTokenInfo(long slotID) throws PKCS11Exception {
    String method = "C_GetTokenInfo";
    debugIn(method, null, "slotID={}", slotID);
    try {
      return toNonNullT(method, null, pkcs11().C_GetTokenInfo(slotID));
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public long[] C_GetMechanismList(long slotID) throws PKCS11Exception {
    String method = "C_GetMechanismList";
    debugIn(method, null, "slotID={}", slotID);
    try {
      long[] mechs = pkcs11().C_GetMechanismList(slotID);
      if (debugEnabled) {
        List<String> texts = new ArrayList<>(mechs.length);
        for (long v : mechs) {
          texts.add(codeToText(Category.CKM, v));
        }
        debugOut(method, null, texts);
      }
      return mechs;
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public CkMechanismInfo C_GetMechanismInfo(long slotID, long type)
      throws PKCS11Exception {
    String method = "C_GetMechanismInfo";
    if (debugEnabled) {
      debugIn(method, null, "slotID={}, type={}",
          slotID, codeToText(Category.CKM, type));
    }

    try {
      return toNonNullT(method, null,
          pkcs11().C_GetMechanismInfo(slotID, type));
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public long C_OpenSession(long slotID, long flags, Long oldHandle)
      throws PKCS11Exception {
    final String method = "C_OpenSession";
    if (debugEnabled) {
      debugIn(method, oldHandle, "slotID={}, flags=0x{}",
          slotID, Functions.toFullHex(flags));
    }
    try {
      long ret = pkcs11().C_OpenSession(slotID, flags);
      debugOut(method, oldHandle, ret);
      return ret;
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public void C_CloseSession(long hSession) throws PKCS11Exception {
    final String method = "C_CloseSession";
    debugIn(method, hSession);
    try {
      pkcs11().C_CloseSession(hSession);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_CloseAllSessions(long slotID) throws PKCS11Exception {
    final String method = "C_CloseAllSessions";
    if (debugEnabled) {
      debugIn(method, null, "slotID={}", slotID);
    }
    try {
      pkcs11().C_CloseAllSessions(slotID);
      debugOut(method, null);
    } catch (PKCS11Exception e) {
      throw debugError(method, null, e);
    }
  }

  public CkSessionInfo C_GetSessionInfo(long hSession) throws PKCS11Exception {
    String method = "C_GetSessionInfo";
    debugIn(method, hSession);
    try {
      return toNonNullT(method, hSession, pkcs11().C_GetSessionInfo(hSession));
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_Login(long hSession, long userType, byte[] pin)
      throws PKCS11Exception {
    final String method = "C_Login";
    if (debugEnabled) {
      debugIn(method, hSession, "userType={}",
          PKCS11T.codeToName(Category.CKU, userType));
    }

    try {
      pkcs11().C_Login(hSession, userType, pin);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_Logout(long hSession) throws PKCS11Exception {
    final String method = "C_Logout";
    debugIn(method, hSession);
    try {
      pkcs11().C_Logout(hSession);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public long C_CreateObject(long hSession, Template template)
      throws PKCS11Exception {
    final String method = "C_CreateObject";
    if (debugEnabled) {
      long objClass = template.getLongAttrValue(PKCS11T.CKA_CLASS);
      if (objClass == PKCS11T.CKO_PRIVATE_KEY
          || objClass == PKCS11T.CKO_SECRET_KEY) {
        template.attributesAsSensitive(PKCS11T.CKA_VALUE, // secret key, DSA, EC
            PKCS11T.CKA_PRIVATE_EXPONENT, PKCS11T.CKA_PRIME_1,
            PKCS11T.CKA_PRIME_2, PKCS11T.CKA_EXPONENT_1,
            PKCS11T.CKA_EXPONENT_2, PKCS11T.CKA_COEFFICIENT); // RSA
      }
      debugIn(method, hSession, "template={}", template);
    }

    try {
      long hObject = pkcs11().C_CreateObject(hSession, template);
      debugOut(method, hSession, hObject);
      return hObject;
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public long C_CopyObject(long hSession, long hObject,
                           Template template)
      throws PKCS11Exception {
    final String method = "C_CopyObject";
    debugIn(method, hSession, "hObject={}, template={}", hObject, template);
    try {
      long ret = pkcs11().C_CopyObject(hSession, hObject, template);
      debugOut(method, hSession, hObject);
      return ret;
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_DestroyObject(long hSession, long hObject)
      throws PKCS11Exception {
    final String method = "C_DestroyObject";
    debugIn(method, hSession, "hSession={}", hSession);
    try {
      pkcs11().C_DestroyObject(hSession, hObject);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public Template C_GetAttributeValue(
      long hSession, long hObject, long[] attrTypes)
      throws PKCS11Exception {
    final String method = "C_GetAttributeValue";

    int size = attrTypes.length;
    try {
      if (size == 0) {
        return new Template();
      }

      if (debugEnabled) {
        List<String> attrNames = new ArrayList<>(attrTypes.length);
        for (long attrType : attrTypes) {
          attrNames.add(PKCS11T.ckaCodeToName(attrType));
        }
        debugIn(method, hSession, "hObject={}, {}", hObject, attrNames);
      }

      Template template = pkcs11().C_GetAttributeValue(
          hSession, hObject, attrTypes);
      if (debugEnabled) {
        Template tmpTemplate = new Template(template.attributes());
        template.attributesAsSensitive(PKCS11T.CKA_VALUE, PKCS11T.CKA_PRIME,
            // RSA
            PKCS11T.CKA_PRIVATE_EXPONENT,
            PKCS11T.CKA_PRIME_1, PKCS11T.CKA_PRIME_2,
            PKCS11T.CKA_EXPONENT_1, PKCS11T.CKA_EXPONENT_2);
        debugOut(method, hObject, tmpTemplate);
      }
      return template;
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_SetAttributeValue(
      long hSession, long hObject, Template template)
      throws PKCS11Exception {
    final String method = "C_SetAttributeValue";
    debugIn(method, hSession, "hObject={}, template={}", hObject, template);
    try {
      pkcs11().C_SetAttributeValue(hSession, hObject, template);
      debugOut(method, hObject);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_FindObjectsInit(long hSession, Template template)
      throws PKCS11Exception {
    final String method = "C_FindObjectsInit";
    debugIn(method, hSession, "template={}", template);
    try {
      pkcs11().C_FindObjectsInit(hSession, template);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public long[] C_FindObjects(long hSession, int maxObjectCount)
      throws PKCS11Exception {
    final String method = "C_FindObjects";
    debugIn(method, hSession, "maxObjectCount={}", maxObjectCount);
    try {
      long[] ret = pkcs11().C_FindObjects(hSession, maxObjectCount);
      if (debugEnabled) {
        debugOut(method, hSession, Arrays.toString(ret));
      }
      return ret;
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_FindObjectsFinal(long hSession) throws PKCS11Exception {
    final String method = "C_FindObjectsFinal";
    debugIn(method, hSession);
    try {
      pkcs11().C_FindObjectsFinal(hSession);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_DigestInit(long hSession, CkMechanism mechanism)
      throws PKCS11Exception {
    final String method = "C_DigestInit";
    debugIn(method, hSession, "mechanism={}", mechanism);
    try {
      pkcs11().C_DigestInit(hSession, mechanism);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public byte[] C_Digest(long hSession, byte[] data, int maxSize)
      throws PKCS11Exception {
    final String method = "C_Digest";
    debugIn(method, hSession, "data.len={}, maxSize={}", len(data), maxSize);
    try {
      return toNonNull(method, hSession,
          pkcs11().C_Digest(hSession, data, maxSize),
          true);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_DigestUpdate(long hSession, byte[] part)
      throws PKCS11Exception {
    final String method = "C_DigestUpdate";
    debugIn(method, hSession, "part.len={}", len(part));
    try {
      pkcs11().C_DigestUpdate(hSession, part);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_DigestKey(long hSession, long hKey) throws PKCS11Exception {
    final String method = "C_DigestKey";
    debugIn(method, hSession, "hKey={}", hKey);
    try {
      pkcs11().C_DigestKey(hSession, hKey);
      debugOut(method, hKey);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public byte[] C_DigestFinal(long hSession, int maxSize)
      throws PKCS11Exception {
    final String method = "C_DigestFinal";
    debugIn(method, hSession, "maxSize={}", maxSize);
    try {
      return toNonNull(method, hSession,
          pkcs11().C_DigestFinal(hSession, maxSize), true);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_SignInit(long hSession, CkMechanism mechanism, long hKey)
      throws PKCS11Exception {
    final String method = "C_SignInit";
    debugIn(method, hSession, "hKey={}, mechanism={}", hKey, mechanism);
    try {
      pkcs11().C_SignInit(hSession, mechanism, hKey);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public byte[] C_Sign(long hSession, byte[] data, int maxSize)
      throws PKCS11Exception {
    final String method = "C_Sign";
    debugIn(method, hSession, "data.len={}, maxSize={}", len(data), maxSize);
    try {
      return toNonNull(method, hSession,
          pkcs11().C_Sign(hSession, data, maxSize));
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_SignUpdate(long hSession, byte[] part) throws PKCS11Exception {
    final String method = "C_SignUpdate";
    debugIn(method, hSession, "part.len={}", len(part));
    try {
      pkcs11().C_SignUpdate(hSession, part);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public byte[] C_SignFinal(long hSession, int maxSize)
      throws PKCS11Exception {
    final String method = "C_SignFinal";
    debugIn(method, hSession, "maxSize={}", maxSize);
    try {
      return toNonNull(method, hSession,
          pkcs11().C_SignFinal(hSession, maxSize));
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public long C_GenerateKey(long hSession, CkMechanism mechanism,
                            Template template)
      throws PKCS11Exception {
    final String method = "C_GenerateKey";
    debugIn(method, hSession, "mechanism={}, template={}",
        mechanism, template);
    try {
      long hKey = pkcs11().C_GenerateKey(hSession, mechanism, template);
      debugOut(method, hSession, hKey);
      return hKey;
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public PKCS11KeyPair C_GenerateKeyPair(
      long hSession, CkMechanism mechanism, Template publicKeyTemplate,
      Template privateKeyTemplate) throws PKCS11Exception {
    final String method = "C_GenerateKeyPair";
    debugIn(method, hSession, "mechanism={}, publicKeyTemplate={}, " +
        "privateTemplate={}", mechanism, publicKeyTemplate, privateKeyTemplate);
    try {
      long[] objectHandles = pkcs11().C_GenerateKeyPair(hSession,
          mechanism, publicKeyTemplate, privateKeyTemplate);

      PKCS11KeyPair rv = new PKCS11KeyPair(objectHandles[0], objectHandles[1]);
      debugOut(method, hSession, "hPublicKey=" + rv.getPublicKey() +
          ", hPrivateKey=" + rv.getPrivateKey());
      return rv;
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  /* ***************************************
   * PKCS#11 V3.0 Functions
   * ***************************************/
  public void C_LoginUser(long hSession, long userType, byte[] pin,
                          byte[] username)
      throws PKCS11Exception {
    final String method = "C_LoginUser";

    if (debugEnabled) {
      debugIn(method, hSession, "userType={}, username={}",
          PKCS11T.codeToName(Category.CKU, userType),
          (username == null) ? null : new String(username));
    }

    try {
      pkcs11().C_LoginUser(hSession, userType, pin, username);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  public void C_SessionCancel(long hSession, long flags)
      throws PKCS11Exception {
    final String method = "C_SessionCancel";
    debugIn(method, hSession, "flags=0x{}", Functions.toFullHex(flags));
    try {
      pkcs11().C_SessionCancel(hSession, flags);
      debugOut(method, hSession);
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  /* ***************************************
   * PKCS#11 V3.2 Functions
   * ***************************************/

  public long C_DecapsulateKey(
      long hSession, CkMechanism mechanism, long hPrivateKey,
      byte[] encapsulatedKey, Template template)
      throws PKCS11Exception {
    final String method = "C_DecapsulateKey";
    debugIn(method, hSession, "hPrivateKey={}, encapsulatedKey.len={}, " +
        "mechanism={}, template={}", hPrivateKey, len(encapsulatedKey),
        mechanism, template);
    try {
      long hKey = pkcs11().C_DecapsulateKey(hSession, mechanism,
          hPrivateKey, encapsulatedKey, template);
      debugOut(method, hSession, hKey);
      return hKey;
    } catch (PKCS11Exception e) {
      throw debugError(method, hSession, e);
    }
  }

  /* ***************************************
   * Helper Functions
   * ***************************************/

  void close() {
    if (pkcs11 != null) {
      pkcs11.closeModule();
    }
  }

  private static String buildText(String type, String method, Long hSession) {
    String ret = type + " " + method;
    if (hSession != null) {
      ret += "(hSession=" + hSession + ")";
    }
    return ret;
  }

  private void debugIn(String method, Long hSession) {
    if (debugEnabled) {
      LOG.debug(buildText(" IN", method, hSession));
    }
  }

  private void debugIn(String method, Long hSession, String format,
                       Object... arguments) {
    if (debugEnabled) {
      LOG.debug(buildText(" IN", method, hSession) + ": " + format,
          arguments);
    }
  }

  private void debugOut(String method, Long hSession) {
    if (debugEnabled) {
      LOG.debug(buildText("OUT", method, hSession));
    }
  }

  private void debugOut(String method, Long hSession, Object result) {
    if (debugEnabled) {
      LOG.debug("{}: {}", buildText("OUT", method, hSession), result);
    }
  }

  private PKCS11Exception debugError(
      String method, Long hSession, PKCS11Exception e) {
    if (debugEnabled) {
      LOG.debug("{}: {}", buildText("ERR", method, hSession),
          module.codeToName(Category.CKR, e.getErrorCode()));
    }
    return e;
  }

  private <T> T toNonNullT(String method, Long hSession, T ret) {
    debugOut(method, hSession, ret);
    return ret;
  }

  private byte[] toNonNull(String method, Long hSession, byte[] bytes) {
    return toNonNull(method, hSession, bytes, false);
  }

  private byte[] toNonNull(String method, Long hSession, byte[] bytes,
                           boolean printHex) {
    byte[] rv = (bytes == null) ? new byte[0] : bytes;
    debugOut(method, hSession, toText(rv, printHex));
    return rv;
  }

  private static int len(byte[] bytes) {
    return bytes == null ? 0 : bytes.length;
  }

  private String codeToText(Category cat, long code) {
    return module.codeToName(cat, code) + " (0x" +
        Functions.toFullHex(code) + ")";
  }

  private static String toText(byte[] bytes, boolean printHex) {
    if (bytes == null) {
      return "<null>";
    }

    String text = "byte[" + bytes.length + "]";
    if (printHex) {
      text += ": " + Functions.toHex(bytes);
    }
    return text;
  }

}
