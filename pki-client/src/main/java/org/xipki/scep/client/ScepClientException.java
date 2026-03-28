// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

/**
 * SCEP Client Exception exception type.
 *
 * @author Lijun Liao (xipki)
 */

public class ScepClientException extends Exception {

  public ScepClientException(String message, Throwable cause) {
    super(message, cause);
  }

  public ScepClientException(String message) {
    super(message);
  }

  public ScepClientException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

  /**
   * Operation Not Supported Exception exception type.
   *
   * @author Lijun Liao (xipki)
   */
  public static class OperationNotSupportedException extends ScepClientException {

    public OperationNotSupportedException(String message) {
      super(message);
    }

  }

}
