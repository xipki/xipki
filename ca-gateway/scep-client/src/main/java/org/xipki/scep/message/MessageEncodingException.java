// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.message;

/**
 * Exception indicate error while encoding message.
 *
 * @author Lijun Liao (xipki)
 */

public class MessageEncodingException extends Exception {

  public MessageEncodingException(String message, Throwable cause) {
    super(message, cause);
  }

  public MessageEncodingException(String message) {
    super(message);
  }

  public MessageEncodingException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

}
