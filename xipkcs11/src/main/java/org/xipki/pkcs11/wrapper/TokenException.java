// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * The base class for all exceptions in this package. It is able to wrap another
 * exception from a lower layer.
 *
 * @author Lijun Liao (xipki)
 */
public class TokenException extends Exception {

  /**
   * Constructor taking an exception message.
   *
   * @param message
   *          The message giving details about the exception to ease
   *          debugging.
   */
  public TokenException(String message) {
    super(message);
  }

  /**
   * Constructor taking another exception to wrap.
   *
   * @param encapsulatedException
   *          The other exception the wrap into this.
   */
  public TokenException(Exception encapsulatedException) {
    super(encapsulatedException);
  }

  /**
   * Constructor taking a message for this exception and another exception to
   * wrap.
   *
   * @param message
   *          The message giving details about the exception to ease
   *          debugging.
   * @param encapsulatedException
   *          The other exception the wrap into this.
   */
  public TokenException(String message, Exception encapsulatedException) {
    super(message, encapsulatedException);
  }

}
