// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.exception;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class EncodeException extends Exception {

  public EncodeException(String message) {
    super(message);
  }

  public EncodeException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

  public EncodeException(String message, Throwable cause) {
    super(message, cause);
  }

}
