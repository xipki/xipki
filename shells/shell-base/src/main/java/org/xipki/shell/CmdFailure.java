// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

/**
 * Action failure.
 *
 * @author Lijun Liao (xipki)
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
