// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.codec.Args;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Slot authentication.
 *
 * @author Lijun Liao (xipki)
 */
public class SessionAuth {

  private static final Logger LOG = LoggerFactory.getLogger(SessionAuth.class);

  private final boolean useLoginUser;

  private final long userType;

  private final byte[] userName;

  private final List<byte[]> pins;

  private final AtomicLong incurableCkr = new AtomicLong(0);

  private SessionAuth(boolean useLoginUser, long userType, String userName,
                      List<String> pins) {
    this.useLoginUser = useLoginUser;
    this.userType = userType;
    this.userName = userName == null ? null
        : userName.getBytes(StandardCharsets.UTF_8);
    if (pins == null || pins.isEmpty()) {
      this.pins = Collections.singletonList(new byte[0]);
    } else {
      this.pins = new ArrayList<>(pins.size());
      for (String s : pins) {
        this.pins.add(s.getBytes(StandardCharsets.UTF_8));
      }
    }
  }

  public static SessionAuth ofLoginUser(
      long userType, String userName, List<String> pins) {
    return new SessionAuth(true, userType,
        Args.notNull(userName, "userName"), pins);
  }

  public static SessionAuth ofLogin(
      long userType, List<String> pins) {
    return new SessionAuth(false, userType, null, pins);
  }

  public void authenticate(LogPKCS11 pkcs11, long hSession)
      throws PKCS11Exception {
    long start = System.currentTimeMillis();

    String userText = "user ";
    if (userName != null) {
      userText += new String(userName) + " ";
    }
    userText += "of type " + PKCS11T.codeToName(Category.CKU, userType);

    long ckr = this.incurableCkr.get();
    if (ckr != 0) {
      LOG.info("login session {}: duration {}ms", hSession,
          System.currentTimeMillis() - start);
      throw new PKCS11Exception(ckr);
    }

    try {
      for (byte[] pin : pins) {
        if (useLoginUser) {
          pkcs11.C_LoginUser(hSession, userType, pin, userName);
        } else {
          pkcs11.C_Login(hSession, userType, pin);
        }
      }

      incurableCkr.set(0);
      LOG.info("authenticate successful as {} with {}", userText,
          (pins.get(0).length == 0 ? "NULL pin" : "pin"));
    } catch (PKCS11Exception ex) {
      long err = ex.getErrorCode();
      if (err == PKCS11T.CKR_USER_ALREADY_LOGGED_IN) {
        LOG.warn("user already logged in");
        return;
      } else if (err == PKCS11T.CKR_USER_ANOTHER_ALREADY_LOGGED_IN) {
        LOG.warn("another user already logged in");
      } else if (err == PKCS11T.CKR_PIN_EXPIRED
          || err == PKCS11T.CKR_PIN_INCORRECT
          || err == PKCS11T.CKR_PIN_INVALID
          || err == PKCS11T.CKR_PIN_LOCKED
          || err == PKCS11T.CKR_PIN_TOO_WEAK
          || err == PKCS11T.CKR_PIN_LEN_RANGE) {
        incurableCkr.set(err);
      }

      throw ex;
    } finally {
      LOG.info("login session {} took {}ms", hSession,
          System.currentTimeMillis() - start);
    }
  }

  public boolean isCurable() {
    return incurableCkr.get() == 0;
  }

}
