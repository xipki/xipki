// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * This is the superclass of all checked exceptions used by this package. A
 * PKCS11Exception indicates that a function call to the underlying
 * PKCS#11 module returned a value not equal to CKR_OK. The application can get
 * the returned value by calling getErrorCode(). A return value not equal to
 * CKR_OK is the only reason for such an exception to be thrown.
 * PKCS#11 defines the meaning of an error-code, which may depend on the
 * context in which the error occurs.
 *
 * @author Lijun Liao (xipki)
 */
public class PKCS11Exception extends TokenException {

  /**
   * The code of the error which was the reason for this exception.
   */
  private final long errorCode;

  private final String errorName;

  /**
   * Constructor taking the error code as defined for the CKR_* constants
   * in PKCS#11.
   *
   * @param errorCode
   *          The PKCS#11 error code (return value).
   */
  public PKCS11Exception(long errorCode) {
    this(errorCode, PKCS11T.ckrCodeToName(errorCode));
  }

  /**
   * Constructor taking the error code as defined for the CKR_* constants
   * in PKCS#11.
   *
   * @param errorCode
   *          The PKCS#11 error code (return value).
   * @param name
   *          The error name.
   */
  public PKCS11Exception(long errorCode, String name) {
    super(name);
    if (name == null || name.isEmpty()) {
      throw new IllegalArgumentException("name must not be null or blank.");
    }
    this.errorName = name;
    this.errorCode = errorCode;
  }

  /**
   * Returns the PKCS#11 error code.
   *
   * @return The error code; e.g. 0x00000030.
   */
  public long getErrorCode() {
    return errorCode;
  }

  public String getErrorName() {
    return errorName;
  }

}
