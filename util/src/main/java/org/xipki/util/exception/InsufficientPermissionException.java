// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.exception;

/**
 * Exception indicates insufficient permission.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class InsufficientPermissionException extends Exception {

  public InsufficientPermissionException(String message) {
    super(message);
  }

}
