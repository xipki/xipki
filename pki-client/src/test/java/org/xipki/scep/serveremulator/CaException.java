// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

/**
 * Emulator CA exception.
 *
 * @author Lijun Liao (xipki)
 */

public class CaException extends Exception {

  public CaException() {
  }

  public CaException(String message) {
    super(message);
  }

  public CaException(Throwable cause) {
    super(cause);
  }

  public CaException(String message, Throwable cause) {
    super(message, cause);
  }

}
