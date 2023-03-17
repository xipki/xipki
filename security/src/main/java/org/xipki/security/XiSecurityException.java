// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

/**
 * General security exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class XiSecurityException extends Exception {

  public XiSecurityException() {
    super();
  }

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
