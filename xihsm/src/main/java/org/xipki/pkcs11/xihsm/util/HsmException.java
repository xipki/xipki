// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.util;

import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11T;

/**
 * @author Lijun Liao (xipki)
 */
public class HsmException extends Exception {

  private final long errorCode;

  public static HsmException newGeneralError(String message) {
    return new HsmException(PKCS11T.CKR_GENERAL_ERROR, message);
  }

  public static HsmException newGeneralError(String message, Exception e) {
    return new HsmException(PKCS11T.CKR_GENERAL_ERROR, message, e);
  }

  /**
   * Constructor taking the error code as defined for the CKR_* constants
   * in PKCS#11.
   *
   * @param errorCode The PKCS#11 error code (return value).
   */
  public HsmException(long errorCode) {
    super(PKCS11T.ckrCodeToName(errorCode));
    this.errorCode = errorCode;
  }

  /**
   * Constructor taking the error code as defined for the CKR_* constants
   * in PKCS#11.
   *
   * @param errorCode The PKCS#11 error code (return value).
   * @param message The detailed message.
   */
  public HsmException(long errorCode, String message) {
    super(PKCS11T.ckrCodeToName(errorCode)
        + (message == null || message.isEmpty() ? "" : ": " + message));
    this.errorCode = errorCode;
  }

  /**
   * Constructor taking the error code as defined for the CKR_* constants
   * in PKCS#11.
   *
   * @param errorCode The PKCS#11 error code (return value).
   * @param message The detailed message.
   * @param cause The cause.
   */
  public HsmException(long errorCode, String message, Throwable cause) {
    super(PKCS11T.ckrCodeToName(errorCode)
        + (message == null || message.isEmpty() ? "" : ": " + message), cause);
    this.errorCode = errorCode;
  }

  public PKCS11Exception toPKCS11Exception() {
    return new PKCS11Exception(errorCode);
  }

  public long getErrorCode() {
    return errorCode;
  }

}
