// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

/**
 * Encoding exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class EncodingException extends Exception {

  public EncodingException(String message) {
    super(message);
  }

  public EncodingException(Throwable cause) {
    super(cause);
  }

  public EncodingException(String message, Throwable cause) {
    super(message, cause);
  }

}
