// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.exception;

/**
 * General security exception.
 *
 * @author Lijun Liao (xipki)
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
