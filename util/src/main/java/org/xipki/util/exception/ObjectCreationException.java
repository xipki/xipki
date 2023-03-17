// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.exception;

/**
 * Exception for object creation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ObjectCreationException extends Exception {

  public ObjectCreationException(String msg, Throwable cause) {
    super(msg, cause);
  }

  public ObjectCreationException(String msg) {
    super(msg);
  }
}
