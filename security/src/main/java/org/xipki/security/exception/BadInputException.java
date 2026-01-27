// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.exception;

/**
 * Exception that indicates bad input.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class BadInputException extends Exception {

  public BadInputException(String message) {
    super(message);
  }

  public BadInputException(Throwable cause) {
    super(cause);
  }

  public BadInputException(String message, Throwable cause) {
    super(message, cause);
  }

}
