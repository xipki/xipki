// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm;

import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.mgr.UserVerifier;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public class LoginState {

  private final UserVerifier userVerifier;

  private boolean loggedIn;

  private Long userType;

  public LoginState(UserVerifier userVerifier) {
    this.userVerifier = Args.notNull(userVerifier, "userVerifier");
  }

  public boolean isLoggedIn() {
    return loggedIn;
  }

  public LoginState notLoggedInCopy() {
    return new LoginState(userVerifier);
  }

  public void login(long userType, byte[] pin) throws HsmException {
    String name = PKCS11T.ckuCodeToName(userType);
    if (loggedIn) {
      throw new HsmException(PKCS11T.CKR_USER_ALREADY_LOGGED_IN,
          "The session has been logged in for " + name);
    }

    userVerifier.verify(userType, pin);
    this.loggedIn = true;
    this.userType = userType;
  }

  public Long getUserType() {
    return userType;
  }

  public void logoutIfLoggedIn() {
    if (loggedIn) {
      this.loggedIn = false;
      this.userType = null;
    }
  }

  public void logout() throws HsmException {
    if (!loggedIn) {
      throw new HsmException(PKCS11T.CKR_USER_NOT_LOGGED_IN,
          "The session has not been logged in");
    }
    this.loggedIn = false;
    this.userType = null;
  }

  public void assertLoggedIn() throws HsmException {
    if ((!loggedIn)) {
      throw new HsmException(PKCS11T.CKR_USER_NOT_LOGGED_IN,
          "The session has not been logged in");
    }
  }

  public void assertLoggedIn(long userType) throws HsmException {
    if ((!loggedIn)) {
      throw new HsmException(PKCS11T.CKR_USER_NOT_LOGGED_IN,
          "The session has not been logged in");
    }

    if (this.userType != null && userType == this.userType) {
      return;
    }

    throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
        "The session is not logged in with user " +
            PKCS11T.codeToName(Category.CKU, userType));
  }

  public long getSessionState(boolean rw) {
    if (loggedIn) {
      if (userType == PKCS11T.CKU_SO) {
        return PKCS11T.CKS_RW_SO_FUNCTIONS;
      } else {
        return rw ? PKCS11T.CKS_RW_USER_FUNCTIONS
                  : PKCS11T.CKS_RO_USER_FUNCTIONS;
      }
    } else {
      return rw ? PKCS11T.CKS_RW_PUBLIC_SESSION
                : PKCS11T.CKS_RO_PUBLIC_SESSION;
    }
  }

}
