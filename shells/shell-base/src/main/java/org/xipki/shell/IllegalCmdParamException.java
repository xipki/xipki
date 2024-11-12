// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

/**
 * Exception for illegal action parameters / options.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class IllegalCmdParamException extends Exception {

  public IllegalCmdParamException() {
  }

  public IllegalCmdParamException(String message) {
    super(message);
  }

  public IllegalCmdParamException(Throwable cause) {
    super(cause);
  }

  public IllegalCmdParamException(String message, Throwable cause) {
    super(message, cause);
  }

}
