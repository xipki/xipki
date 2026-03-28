// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

/**
 * CMP Client Exception exception type.
 *
 * @author Lijun Liao (xipki)
 */

public class CmpClientException extends Exception {

  public CmpClientException(String message) {
    super(message);
  }

  public CmpClientException(String message, Throwable cause) {
    super(message, cause);
  }

}
