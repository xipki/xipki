// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class CodecException extends Exception {

  public CodecException(String message) {
    super(message);
  }

  public CodecException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

  public CodecException(String message, Throwable cause) {
    super(message, cause);
  }

  public static final class CodecIOException extends CodecException {

    public CodecIOException(String message) {
      super(message);
    }

    public CodecIOException(String message, IOException cause) {
      super(message, cause);
    }

    public CodecIOException(IOException cause) {
      super(cause);
    }
  }

  /**
   * An exception thrown when parser encounters duplicated JSON object keys.
   */
  public static final class DuplicatedKeyException extends CodecException {

    /**
     * Duplicated key.
     */
    private final String key;

    /**
     * @param key duplicated key.
     */
    public DuplicatedKeyException(final String key) {
      super("Duplicated key: '".concat(key) + "'");
      this.key = key;
    }

    public String getKey() {
      return key;
    }
  }

  /**
   * An exception thrown when parser encounters malformed JSON syntax.
   */
  public static final class UnexpectedCharException extends CodecException {

    /**
     * @param position  position of unexpected character.
     * @param character unexpected character value (zero based).
     */
    public UnexpectedCharException(final int position, final char character) {
      super("Unexpected character '" + character + "' at position " +
          position + ".");
    }

  }
}
