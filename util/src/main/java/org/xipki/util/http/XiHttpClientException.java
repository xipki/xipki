// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

/**
 * HTTP client exception.
 *
 * @author Lijun Liao (xipki)
 */

public class XiHttpClientException extends Exception {

  public XiHttpClientException(String message, Throwable cause) {
    super(message, cause);
  }

  public XiHttpClientException(String message) {
    super(message);
  }

  public XiHttpClientException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

}
