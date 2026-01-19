// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.exception;

/**
 * General security exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class XiSecurityException extends Exception {

  public XiSecurityException(String message, Throwable cause) {
    super(message, cause);
  }

  public XiSecurityException(String message) {
    super(message);
  }

  public XiSecurityException(Throwable cause) {
    super(cause);
  }

}
