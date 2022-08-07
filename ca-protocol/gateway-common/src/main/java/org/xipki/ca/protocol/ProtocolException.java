package org.xipki.ca.protocol;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ProtocolException extends Exception {

  public ProtocolException(String message) {
    super(message);
  }

  public ProtocolException(String message, Throwable cause) {
    super(message, cause);
  }
}
