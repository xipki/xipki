// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import java.security.GeneralSecurityException;

/**
 * Exception that indicates no idle signer is available.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class NoIdleSignerException extends GeneralSecurityException {

  public NoIdleSignerException() {
  }

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
