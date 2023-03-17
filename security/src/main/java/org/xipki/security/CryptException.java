// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

/**
 * Exception that indicates cryptographic error.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CryptException extends Exception {

  public CryptException() {
    super();
  }

  public CryptException(String message, Throwable cause) {
    super(message, cause);
  }

  public CryptException(String message) {
    super(message);
  }

  public CryptException(Throwable cause) {
    super(cause);
  }

}
