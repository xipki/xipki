// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

/**
 * Exception related to CA management.
 *
 * @author Lijun Liao (xipki)
 */

public class CaMgmtException extends Exception {

  public CaMgmtException() {
  }

  public CaMgmtException(String message, Throwable cause) {
    super(message, cause);
  }

  public CaMgmtException(String message) {
    super(message);
  }

  public CaMgmtException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

}
