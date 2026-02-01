// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.exception;

import java.security.GeneralSecurityException;

/**
 * Exception that indicates no idle signer is available.
 *
 * @author Lijun Liao (xipki)
 */
public class NoIdleSignerException extends GeneralSecurityException {

  public NoIdleSignerException(String message) {
    super(message);
  }

  public NoIdleSignerException(Throwable cause) {
    super(cause);
  }

  public NoIdleSignerException(String message, Throwable cause) {
    super(message, cause);
  }

}
