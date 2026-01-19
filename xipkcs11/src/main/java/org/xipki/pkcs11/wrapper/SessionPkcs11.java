// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkSessionInfo;
import org.xipki.util.codec.Args;

/**
 * A wrapper of {@link LogPKCS11} for a given session.
 *
 * @author Lijun Liao (xipki)
 */
class SessionPkcs11 {

  private static final Logger LOG =
      LoggerFactory.getLogger(SessionPkcs11.class);

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private final LogPKCS11 pkcs11;

  private final Token token;

  private final long openSessionFlags;

  private final Object loginSync;

  private SessionAuth auth;

  /**
   * The session handle to perform the operations with.
   */
  private long hSession;

  private boolean recoverable = true;

  SessionPkcs11(LogPKCS11 pkcs11, Token token, Object loginSync,
                long hSession, long openSessionFlags) {
    this.pkcs11 = Args.notNull(pkcs11, "pkcs11");
    this.token = Args.notNull(token, "token");
    this.loginSync = Args.notNull(loginSync, "loginSync");
    this.hSession = hSession;
    this.openSessionFlags = openSessionFlags;
  }

  boolean isRecoverable() {
    return recoverable;
  }

  void setAuth(SessionAuth auth) {
    this.auth = auth;
  }

  long hSession() {
    return hSession;
  }

  private void recoverAtomicOp(PKCS11Exception e) throws PKCS11Exception {
    recover(true, e);
  }

  private PKCS11Exception recoverMultiOp(PKCS11Exception e) {
    try {
      recover(true, e);
    } catch (Exception ex) {
      if (e != ex) {
        LOG.warn("error recovering session {}", hSession, ex);
      }
    }
    return e;
  }

  private void recoverPinOp(PKCS11Exception e) throws PKCS11Exception {
    recover(false, e);
  }

  private void recover(boolean loginAllowed, PKCS11Exception e)
      throws PKCS11Exception {
    long err = e.getErrorCode();
    if (err == PKCS11T.CKR_USER_NOT_LOGGED_IN) {
      if (!loginAllowed || auth == null) {
        throw e;
      }

      try {
        login();
      } catch (PKCS11Exception ex) {
        if (!auth.isCurable()) {
          recoverable = false;
          LOG.warn("session {} is not recoverable: {}",
              hSession, PKCS11T.ckrCodeToName(ex.getErrorCode()));
        }

        throw ex;
      }
    } else if (err == PKCS11T.CKR_SESSION_CLOSED
        || err == PKCS11T.CKR_SESSION_HANDLE_INVALID
        || err == PKCS11T.CKR_DEVICE_ERROR
        || err == PKCS11T.CKR_DEVICE_MEMORY
        || err == PKCS11T.CKR_DEVICE_REMOVED
        || err == PKCS11T.CKR_HOST_MEMORY
    ) {
      try {
        pkcs11.C_CloseSession(hSession);
      } catch (Exception ex) {
      }

      long hSessionNew = token.rawOpenSession(openSessionFlags, hSession);
      LOG.info("session {} is not active due to {}, replaced it " +
          "with new session {}", hSession, PKCS11T.ckrCodeToName(err),
          hSessionNew);

      this.hSession = hSessionNew;
      this.recoverable = true;
      login();
    } else {
      throw e;
    }
  }

  void login() throws PKCS11Exception {
    if (auth == null) {
      throw new IllegalStateException("auth is not set");
    }

    synchronized (loginSync) {
      auth.authenticate(pkcs11, hSession);
    }
  }

  /* ***************************************
   * PKCS#11 V2.x Functions
   * ***************************************/

  void C_CloseSession() throws PKCS11Exception {
    pkcs11.C_CloseSession(hSession);
  }

  CkSessionInfo C_GetSessionInfo() throws PKCS11Exception {
    try {
      return pkcs11.C_GetSessionInfo(hSession);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      return pkcs11.C_GetSessionInfo(hSession);
    }
  }

  void C_Login(long userType, byte[] pin) throws PKCS11Exception {
    synchronized (loginSync) {
      try {
        pkcs11.C_Login(hSession, userType, pin);
      } catch (PKCS11Exception e) {
        recoverPinOp(e);
        pkcs11.C_Login(hSession, userType, pin);
      }
    }
  }

  void C_Logout() throws PKCS11Exception {
    try {
      pkcs11.C_Logout(hSession);
    } catch (PKCS11Exception e) {
      recoverPinOp(e);
      pkcs11.C_Logout(hSession);
    }
  }

  long C_CreateObject(Template template) throws PKCS11Exception {
    try {
      return pkcs11.C_CreateObject(hSession, template);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      return pkcs11.C_CreateObject(hSession, template);
    }
  }

  long C_CopyObject(long hObject, Template template)
      throws PKCS11Exception {
    try {
      return pkcs11.C_CopyObject(hSession, hObject, template);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      return pkcs11.C_CopyObject(hSession, hObject, template);
    }
  }

  void C_DestroyObject(long hObject) throws PKCS11Exception {
    try {
      pkcs11.C_DestroyObject(hSession, hObject);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      pkcs11.C_DestroyObject(hSession, hObject);
    }
  }

  Template C_GetAttributeValue(long hObject, long[] attrTypes)
      throws PKCS11Exception {
    try {
      return pkcs11.C_GetAttributeValue(hSession, hObject, attrTypes);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      return pkcs11.C_GetAttributeValue(hSession, hObject, attrTypes);
    }
  }

  void C_SetAttributeValue(long hObject, Template template)
      throws PKCS11Exception {
    try {
      pkcs11.C_SetAttributeValue(hSession, hObject, template);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      pkcs11.C_SetAttributeValue(hSession, hObject, template);
    }
  }

  void C_FindObjectsInit(Template template) throws PKCS11Exception {
    try {
      pkcs11.C_FindObjectsInit(hSession, template);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      pkcs11.C_FindObjectsInit(hSession, template);
    }
  }

  long[] C_FindObjects(int maxObjectCount) throws PKCS11Exception {
    try {
      return pkcs11.C_FindObjects(hSession, maxObjectCount);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  void C_FindObjectsFinal() throws PKCS11Exception {
    try {
      pkcs11.C_FindObjectsFinal(hSession);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  void C_DigestInit(CkMechanism mechanism) throws PKCS11Exception {
    try {
      pkcs11.C_DigestInit(hSession, mechanism);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      pkcs11.C_DigestInit(hSession, mechanism);
    }
  }

  byte[] C_Digest(byte[] data, int maxSize) throws PKCS11Exception {
    try {
      return pkcs11.C_Digest(hSession, data, maxSize);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  void C_DigestUpdate(byte[] part) throws PKCS11Exception {
    try {
      pkcs11.C_DigestUpdate(hSession, part);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  void C_DigestKey(long hKey) throws PKCS11Exception {
    try {
      pkcs11.C_DigestKey(hSession, hKey);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  byte[] C_DigestFinal(int maxSize) throws PKCS11Exception {
    try {
      return pkcs11.C_DigestFinal(hSession, maxSize);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  void C_SignInit(CkMechanism mechanism, long hKey) throws PKCS11Exception {
    try {
      pkcs11.C_SignInit(hSession, mechanism, hKey);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      pkcs11.C_SignInit(hSession, mechanism, hKey);
    }
  }

  byte[] C_Sign(byte[] data, int maxSize)
      throws PKCS11Exception {
    try {
      return pkcs11.C_Sign(hSession, data, maxSize);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  void C_SignUpdate(byte[] part) throws PKCS11Exception {
    try {
      pkcs11.C_SignUpdate(hSession, part);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  byte[] C_SignFinal(int maxSize)
      throws PKCS11Exception {
    try {
      return pkcs11.C_SignFinal(hSession, maxSize);
    } catch (PKCS11Exception e) {
      throw recoverMultiOp(e);
    }
  }

  long C_GenerateKey(CkMechanism mechanism, Template template)
      throws PKCS11Exception {
    try {
      return pkcs11.C_GenerateKey(hSession, mechanism, template);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      return pkcs11.C_GenerateKey(hSession, mechanism, template);
    }
  }

  PKCS11KeyPair C_GenerateKeyPair(
      CkMechanism mechanism, Template publicKeyTemplate,
      Template privateKeyTemplate)
      throws PKCS11Exception {
    try {
      return pkcs11.C_GenerateKeyPair(hSession, mechanism,
          publicKeyTemplate, privateKeyTemplate);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      return pkcs11.C_GenerateKeyPair(hSession, mechanism,
          publicKeyTemplate, privateKeyTemplate);
    }
  }

  /* ***************************************
   * PKCS#11 V3.0 Functions
   * ***************************************/

  void C_LoginUser(long userType, byte[] pin, byte[] username)
      throws PKCS11Exception {
    synchronized (loginSync) {
      try {
        pkcs11.C_LoginUser(hSession, userType, pin, username);
      } catch (PKCS11Exception e) {
        recoverPinOp(e);
        pkcs11.C_LoginUser(hSession, userType, pin, username);
      }
    }
  }

  void C_SessionCancel(long flags) throws PKCS11Exception {
    try {
      pkcs11.C_SessionCancel(hSession, flags);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      pkcs11.C_SessionCancel(hSession, flags);
    }
  }

  /* ***************************************
   * PKCS#11 V3.2 Functions
   * ***************************************/

  long C_DecapsulateKey(CkMechanism mechanism, long hPrivateKey,
                        byte[] encapsulatedKey, Template template)
      throws PKCS11Exception {
    try {
      return pkcs11.C_DecapsulateKey(hSession, mechanism, hPrivateKey,
          encapsulatedKey, template);
    } catch (PKCS11Exception e) {
      recoverAtomicOp(e);
      return pkcs11.C_DecapsulateKey(hSession, mechanism, hPrivateKey,
          encapsulatedKey, template);
    }
  }

}
