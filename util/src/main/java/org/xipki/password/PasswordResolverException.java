// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import java.security.GeneralSecurityException;

/**
 * Password resolver exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class PasswordResolverException extends GeneralSecurityException {

  public PasswordResolverException() {
  }

  public PasswordResolverException(String message) {
    super(message);
  }

  public PasswordResolverException(Throwable cause) {
    super(cause);
  }

  public PasswordResolverException(String message, Throwable cause) {
    super(message, cause);
  }

}
