// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkSessionInfo;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.MultiPartOperation;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.objects.XiKey;
import org.xipki.pkcs11.xihsm.objects.XiPrivateKey;
import org.xipki.pkcs11.xihsm.objects.XiPrivateOrSecretKey;
import org.xipki.pkcs11.xihsm.objects.XiSecretKey;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.OperationType;
import org.xipki.security.HashAlgo;
import org.xipki.util.codec.Args;

import java.util.Arrays;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_TOKEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_VALUE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_VALUE_LEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_SESSION_READ_ONLY;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_TEMPLATE_INCONSISTENT;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class XiSession {

  private final XiSlot slot;

  private final long handle;

  private final boolean rw;

  private final ActiveOperation activeOperation = new ActiveOperation();

  private long[] findObjectHandles;

  private int findObjectIndex;

  public XiSession(long handle, XiSlot slot, boolean rw) {
    this.handle = handle;
    this.slot = Args.notNull(slot, "slot");
    this.rw = rw;
  }

  public XiSlot getSlot() {
    return slot;
  }

  public void close() {
  }

  public boolean isRw() {
    return rw;
  }

  public void C_CloseSession() {
    slot.removeSession(handle);
    close();
  }

  public CkSessionInfo C_GetSessionInfo() throws HsmException {
    long flags = PKCS11T.CKF_SERIAL_SESSION | (rw ? 0 : PKCS11T.CKF_RW_SESSION);
    long state = slot.loginState(handle).getSessionState(rw);
    return new CkSessionInfo(slot.getSlotId(), state, flags, 0);
  }

  public void C_SessionCancel(long flags) throws HsmException {
    if (flags == 0) {
      return;
    }

    long allOps = PKCS11T.CKF_SIGN | PKCS11T.CKF_VERIFY
        | PKCS11T.CKF_DIGEST | PKCS11T.CKF_GENERATE | PKCS11T.CKF_GENERATE_KEY_PAIR;
    // TODO: add CKF_DECRYPT and CKF_DERIVE if both operations are supported
    if ((flags & allOps) != flags) {
    }

    long processedFlags = 0;
    OperationType currentOpType = activeOperation.getOperationType();
    if ((flags & PKCS11T.CKF_SIGN) != 0) {
      processedFlags |= PKCS11T.CKF_SIGN;
      if (currentOpType == OperationType.SIGN) {
        leaveActiveOp();
      }
    }

    if ((flags & PKCS11T.CKF_DIGEST) != 0) {
      processedFlags |= PKCS11T.CKF_DIGEST;
      if (currentOpType == OperationType.DIGEST) {
        leaveActiveOp();
      }
    }

    if ((flags & PKCS11T.CKF_GENERATE_KEY_PAIR) != 0) {
      processedFlags |= PKCS11T.CKF_GENERATE_KEY_PAIR;
    }

    if ((flags & PKCS11T.CKF_GENERATE) != 0) {
      processedFlags |= PKCS11T.CKF_GENERATE;
    }

    if (processedFlags != flags) {
      throw new HsmException(PKCS11T.CKR_FUNCTION_FAILED,
          "could not cancel all operations masked by flags " + flags);
    }

    if ((flags & PKCS11T.CKF_SIGN) != 0) {
      if (currentOpType == OperationType.SIGN) {
        leaveActiveOp();
      }
    }

    if ((flags & PKCS11T.CKF_DIGEST) != 0) {
      if (currentOpType == OperationType.DIGEST) {
        leaveActiveOp();
      }
    }
  }

  public void C_Login(long userType, byte[] pin) throws HsmException {
    slot.loginState().login(userType, pin);
  }

  public void C_Logout() throws HsmException {
    slot.loginState().logout();
  }

  public long C_CreateObject(XiTemplate template) throws HsmException {
    return slot.C_CreateObject(handle, rw, template);
  }

  public void C_DestroyObject(long hObject) throws HsmException {
    slot.C_DestroyObject(handle, rw, hObject);
  }

  public Template C_GetAttributeValue(long hObject, long[] attrTypes) throws HsmException {
    return slot.C_GetAttributeValue(handle, hObject, attrTypes);
  }

  public void C_SetAttributeValue(long hObject, XiTemplate template) throws HsmException {
    slot.C_SetAttributeValue(handle, rw, hObject, template);
  }

  public void C_FindObjectsInit(XiTemplate template) throws HsmException {
    findObjectHandles = slot.findObjects(handle, template);
    if (findObjectHandles == null) {
      findObjectHandles = new long[0];
    }
    findObjectIndex = 0;
  }

  public long[] C_FindObjects(int maxObjectCount) throws HsmException {
    if (findObjectHandles == null) {
      throw new HsmException(PKCS11T.CKR_OPERATION_NOT_INITIALIZED,
          "C_FindObjectsInit has not been called before.");
    }

    if (maxObjectCount < 1) {
      throw new HsmException(PKCS11T.CKR_ARGUMENTS_BAD,
          "maxObjectCount is too big: " + maxObjectCount);
    }

    int realSize = Math.min(findObjectHandles.length - findObjectIndex, maxObjectCount);
    long[] ret = Arrays.copyOfRange(findObjectHandles, findObjectIndex,
        findObjectIndex + realSize);
    findObjectIndex += realSize;
    return ret;
  }

  public void C_FindObjectsFinal() throws HsmException {
    if (findObjectHandles == null) {
      throw new HsmException(PKCS11T.CKR_OPERATION_NOT_INITIALIZED,
          "C_FindObjectsInit has not been called before.");
    }

    findObjectIndex = 0;
    findObjectHandles = null;
  }

  public byte[] C_DigestKeyX(XiMechanism mechanism, byte[] prefix, long hKey, byte[] suffix)
      throws HsmException {
    assertLoggedInAndNoActiveOp();

    byte[] keyValue;
    if (hKey == 0) {
      keyValue = new byte[0];
    } else {
      XiKey obj = slot.getKey(handle, hKey);
      if (!(obj instanceof XiSecretKey)) {
        throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
            "The key to be digested is not a SecretKey.");
      }

      keyValue = ((XiSecretKey) obj).getValue();
    }

    HashAlgo ha;
    long ckm = mechanism.getCkm();
    if (ckm == PKCS11T.CKM_SHA_1) {
      ha = HashAlgo.SHA1;
    } else if (ckm == PKCS11T.CKM_SHA224) {
      ha = HashAlgo.SHA224;
    } else if (ckm == PKCS11T.CKM_SHA256) {
      ha = HashAlgo.SHA256;
    } else if (ckm == PKCS11T.CKM_SHA384) {
      ha = HashAlgo.SHA384;
    } else if (ckm == PKCS11T.CKM_SHA512) {
      ha = HashAlgo.SHA512;
    } else if (ckm == PKCS11T.CKM_VENDOR_SM3) {
      ha = HashAlgo.SM3;
    } else {
      throw new HsmException(PKCS11T.CKR_MECHANISM_INVALID,
          "unsupported C_Digest algorithm " + PKCS11T.ckmCodeToName(ckm));
    }

    try {
      enterSimplePartOp();
      return ha.hash(prefix, keyValue, suffix);
    } finally {
      leaveActiveOp();
    }
  }

  public byte[] C_SignX(XiMechanism mechanism, long hKey, byte[] data) throws HsmException {
    assertLoggedInAndNoActiveOp();
    try {
      enterSimplePartOp();
      XiKey key = slot.getKey(handle, hKey);
      if (!(key instanceof XiPrivateKey || key instanceof XiSecretKey)) {
        throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
            "C_SignX is not supported for the given key type " + key.getClass().getName());
      }

      return ((XiPrivateOrSecretKey) key).sign(mechanism, data, slot.getRandom());
    } finally {
      leaveActiveOp();
    }
  }

  public void C_SignInit(XiMechanism mechanism, long hKey) throws HsmException {
    assertLoggedInAndNoActiveOp();

    XiKey key = slot.getKey(handle, hKey);
    enterMultiPartOp(new MultiPartOperation(OperationType.SIGN, key, mechanism, slot.getRandom()));
}

  public void C_SignUpdate(byte[] part) throws HsmException {
    boolean succ = false;
    try {
      activeOperation.assertMultiOpInitialized(OperationType.SIGN).update(part);
      succ = true;
    } finally {
      if (!succ) {
        leaveActiveOp();
      }
    }
  }

  public byte[] C_SignFinal() throws HsmException {
    try {
      return activeOperation.assertMultiOpInitialized(OperationType.SIGN).signFinal();
    } finally {
      leaveActiveOp();
    }
  }

  public byte[] C_DecryptX(XiMechanism mechanism, long hKey, byte[] cipherText)
      throws HsmException {
    assertLoggedInAndNoActiveOp();
    try {
      enterSimplePartOp();
      XiKey key = slot.getKey(handle, hKey);
      if (!(key instanceof XiPrivateKey || key instanceof XiSecretKey)) {
        throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
            "C_DecryptX is not supported for the given key type " + key.getClass().getName());
      }

      return ((XiPrivateOrSecretKey) key).decrypt(mechanism, cipherText);
    } finally {
      leaveActiveOp();
    }
  }

  public long C_DeriveKey(XiMechanism mechanism, long hBaseKey, XiTemplate template)
      throws HsmException {
    assertLoggedInAndNoActiveOp();
    try {
      enterSimplePartOp();
      return doDeriveKey(mechanism, hBaseKey, template);
    } finally {
      leaveActiveOp();
    }
  }

  private long doDeriveKey(XiMechanism mechanism, long hBaseKey, XiTemplate template)
      throws HsmException {
    XiKey key = slot.getKey(handle, hBaseKey);
    if (!(key instanceof XiPrivateOrSecretKey)) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
          "Key (handle=" + hBaseKey + ") is neither Private Key nor Secret Key");
    }

    XiPrivateOrSecretKey sKey = (XiPrivateOrSecretKey) key;
    if (!rw) {
      // check RW before processing operation.
      Boolean b = template.removeBool(CKA_TOKEN);
      boolean inToken = b != null && b;
      if (inToken) {
        throw new HsmException(CKR_SESSION_READ_ONLY, null);
      }
    }

    applyAttributes(sKey.getDeriveTemplate(), template);
    byte[] derivedKey = sKey.deriveKey(mechanism, template);
    template.remove(CKA_VALUE_LEN);
    template.add(XiAttribute.ofByteArray(CKA_VALUE, derivedKey));
    return slot.C_CreateObject(handle, rw, template);
  }

  public long C_DecapsulateKey(XiMechanism mechanism, long hPrivateKey,
                              byte[] encapsulatedKey, XiTemplate template) throws HsmException {
    assertLoggedInAndNoActiveOp();

    try {
      enterSimplePartOp();
      return doDecapsulateKey(mechanism, hPrivateKey, encapsulatedKey, template);
    } finally {
      leaveActiveOp();
    }
  }

  private long doDecapsulateKey(XiMechanism mechanism, long hPrivateKey,
                                byte[] encapsulatedKey, XiTemplate template)
      throws HsmException {
    XiPrivateKey privateKey = (XiPrivateKey) slot.getKey(handle, hPrivateKey);

    applyAttributes(privateKey.getUnwrapTemplate(), template);
    long keyClass = template.getNonNullAttribute(PKCS11T.CKA_CLASS).getLongValue();

    if (PKCS11T.CKO_SECRET_KEY != keyClass) {
      throw new HsmException(PKCS11T.CKR_TEMPLATE_INCONSISTENT,
          "template.CKA_CLASS invalid: " + PKCS11T.ckmCodeToName(keyClass));
    }

    byte[] decapKey = privateKey.decapsulateKey(mechanism, encapsulatedKey);

    template.add(XiAttribute.ofByteArray(PKCS11T.CKA_VALUE, decapKey));
    return slot.C_CreateObject(handle, rw, template);
  }

  public long[] C_GenerateKeyPair(
      XiMechanism mechanism, XiTemplate pPublicKeyTemplate, XiTemplate pPrivateKeyTemplate)
      throws HsmException {
    return slot.C_GenerateKeyPair(handle, rw, mechanism, pPublicKeyTemplate, pPrivateKeyTemplate);
  }

  public long C_GenerateKey(XiMechanism mechanism, XiTemplate template)
      throws HsmException {
    assertLoggedInAndNoActiveOp();
    try {
      enterSimplePartOp();
      return slot.C_GenerateKey(handle, rw, mechanism, template);
    } finally {
      leaveActiveOp();
    }
  }

  private void assertLoggedInAndNoActiveOp() throws HsmException {
    slot.loginState(handle).assertLoggedIn();
    activeOperation.assertNotActive();
  }

  private void enterMultiPartOp(MultiPartOperation op) throws HsmException {
    activeOperation.enterMultiOp(op);
  }

  void leaveMultiPartOp(OperationType op) {
    activeOperation.clearActiveOp(op);
  }

  private void enterSimplePartOp() throws HsmException {
    activeOperation.enterSimpleOp();
  }

  private void leaveActiveOp() {
    activeOperation.clearActiveOp();
  }

  private static void applyAttributes(XiTemplate source, XiTemplate target) throws HsmException {
    if (source == null) {
      return;
    }

    for (XiAttribute sAttr : source.getAttributes()) {
      XiAttribute tAttr = target.getAttribute(sAttr.type());
      if (tAttr == null) {
        target.add(sAttr);
      } else if (!tAttr.equals(sAttr)) {
        throw new HsmException(CKR_TEMPLATE_INCONSISTENT, "inconsistent attribute " + tAttr);
      }
    }
  }

}
