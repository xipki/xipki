// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.message;

/**
 * Exception indicate error while decoding message.
 *
 * @author Lijun Liao
 */

public class MessageDecodingException extends Exception {

  public MessageDecodingException(String message, Throwable cause) {
    super(message, cause);
  }

  public MessageDecodingException(String message) {
    super(message);
  }

  public MessageDecodingException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

}
