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
import org.xipki.pkcs11.xihsm.objects.XiSecretKey;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.OperationType;
import org.xipki.util.codec.Args;

import java.util.Arrays;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_TEMPLATE_INCONSISTENT;

/**
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
        | PKCS11T.CKF_DIGEST | PKCS11T.CKF_GENERATE
        | PKCS11T.CKF_GENERATE_KEY_PAIR;
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

  public Template C_GetAttributeValue(long hObject, long[] attrTypes)
      throws HsmException {
    return slot.C_GetAttributeValue(handle, hObject, attrTypes);
  }

  public void C_SetAttributeValue(long hObject, XiTemplate template)
      throws HsmException {
    slot.C_SetAttributeValue(handle, rw, hObject, template);
  }

  public void C_FindObjectsInit(XiTemplate template)
      throws HsmException {
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

    int realSize = Math.min(findObjectHandles.length - findObjectIndex,
        maxObjectCount);
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

  public void C_DigestInit(XiMechanism mechanism) throws HsmException {
    assertLoggedInAndNoActiveOp();
    enterMultiPartOp(new MultiPartOperation(OperationType.DIGEST, null,
        mechanism, null));
  }

  public byte[] C_Digest(byte[] data) throws HsmException {
    try {
      return activeOperation.assertMultiOpInitialized(OperationType.DIGEST)
          .doFinal(data);
    } finally {
      leaveActiveOp();
    }
  }

  public void C_DigestUpdate(byte[] part) throws HsmException {
    boolean succ = false;
    try {
      activeOperation.assertMultiOpInitialized(OperationType.DIGEST)
          .update(part);
      succ = true;
    } finally {
      if (!succ) {
        leaveActiveOp();
      }
    }
  }

  public void C_DigestKey(long hKey) throws HsmException {
    boolean succ = false;
    try {
      MultiPartOperation op =
          activeOperation.assertMultiOpInitialized(OperationType.DIGEST);
      XiKey obj = slot.getKey(handle, hKey);
      if (!(obj instanceof XiSecretKey)) {
        throw new HsmException(
            PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
            "The key to be digested is not a SecretKey.");
      }
      op.update(((XiSecretKey) obj).getValue());
      succ = true;
    } finally {
      if (!succ) {
        leaveActiveOp();
      }
    }
  }

  public byte[] C_DigestFinal() throws HsmException {
    try {
      return activeOperation.assertMultiOpInitialized(OperationType.DIGEST)
          .doFinal();
    } finally {
      leaveActiveOp();
    }
  }

  public void C_SignInit(XiMechanism mechanism, long hKey) throws HsmException {
    assertLoggedInAndNoActiveOp();

    XiKey key = slot.getKey(handle, hKey);
    enterMultiPartOp(new MultiPartOperation(OperationType.SIGN,
        key, mechanism, slot.getRandom()));
 }

  public byte[] C_Sign(byte[] data) throws HsmException {
    try {
      return activeOperation.assertMultiOpInitialized(OperationType.SIGN)
          .signFinal(data);
    } finally {
      leaveActiveOp();
    }
  }

  public void C_SignUpdate(byte[] part) throws HsmException {
    boolean succ = false;
    try {
      activeOperation.assertMultiOpInitialized(OperationType.SIGN)
          .update(part);
      succ = true;
    } finally {
      if (!succ) {
        leaveActiveOp();
      }
    }
  }

  public byte[] C_SignFinal() throws HsmException {
    try {
      return activeOperation.assertMultiOpInitialized(OperationType.SIGN)
          .signFinal();
    } finally {
      leaveActiveOp();
    }
  }

  public long C_DecapsulateKey(XiMechanism mechanism, long hPrivateKey,
                              byte[] encapsulatedKey, XiTemplate template)
      throws HsmException {
    assertLoggedInAndNoActiveOp();

    try {
      enterSimplePartOp();
      return doDecapsulateKey(mechanism, hPrivateKey,
          encapsulatedKey, template);
    } finally {
      leaveActiveOp();
    }
  }

  private long doDecapsulateKey(XiMechanism mechanism, long hPrivateKey,
                                byte[] encapsulatedKey, XiTemplate template)
      throws HsmException {
    XiPrivateKey privateKey = (XiPrivateKey) slot.getKey(handle, hPrivateKey);

    applyAttributes(privateKey.getUnwrapTemplate(), template);
    long keyClass = template.getNonNullAttribute(PKCS11T.CKA_CLASS)
        .getLongValue();

    if (PKCS11T.CKO_SECRET_KEY != keyClass) {
      throw new HsmException(PKCS11T.CKR_TEMPLATE_INCONSISTENT,
          "template.CKA_CLASS invalid: " +
              PKCS11T.ckmCodeToName(keyClass));
    }

    byte[] decapKey = privateKey.decapsulateKey(mechanism, encapsulatedKey);

    template.add(XiAttribute.ofByteArray(PKCS11T.CKA_VALUE, decapKey));
    return slot.C_CreateObject(handle, rw, template);
  }

  public long[] C_GenerateKeyPair(
      XiMechanism mechanism, XiTemplate pPublicKeyTemplate,
      XiTemplate pPrivateKeyTemplate) throws HsmException {
    return slot.C_GenerateKeyPair(handle, rw,
        mechanism, pPublicKeyTemplate, pPrivateKeyTemplate);
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

  private static void applyAttributes(XiTemplate source, XiTemplate target)
      throws HsmException {
    if (source == null) {
      return;
    }

    for (XiAttribute sAttr : source.getAttributes()) {
      XiAttribute tAttr = target.getAttribute(sAttr.type());
      if (tAttr == null) {
        target.add(sAttr);
      } else if (!tAttr.equals(sAttr)) {
        throw new HsmException(CKR_TEMPLATE_INCONSISTENT,
            "inconsistent attribute " + tAttr);
      }
    }
  }

}
