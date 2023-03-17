// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

/**
 * Action failure.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CmdFailure extends Exception {

  public CmdFailure() {
  }

  public CmdFailure(String message) {
    super(message);
  }

  public CmdFailure(Throwable cause) {
    super(cause);
  }

  public CmdFailure(String message, Throwable cause) {
    super(message, cause);
  }

}
