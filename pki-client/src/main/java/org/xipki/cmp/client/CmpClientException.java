// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

/**
 * CMP client exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CmpClientException extends Exception {

  public CmpClientException(String message) {
    super(message);
  }

  public CmpClientException(String message, Throwable cause) {
    super(message, cause);
  }

}
