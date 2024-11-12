// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.exception;

/**
 * Exception for object creation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ObjectCreationException extends Exception {

  public ObjectCreationException(String msg) {
    super(msg);
  }

  public ObjectCreationException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

  public ObjectCreationException(String msg, Throwable cause) {
    super(msg, cause);
  }

}
