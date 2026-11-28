// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.json;

import org.xipki.util.codec.CodecException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Json Input Stream.
 *
 * @author Lijun Liao (xipki)
 */
public class JsonInputStream {

  // maximal allowed position (inclusive)
  private final int maxPosition;

  private final boolean allowComments;

  private String bytes;

  private int position = -1;

  private JsonInputStream(String bytes, boolean allowComments) {
    this.bytes = bytes;
    this.allowComments = allowComments && hasMultipleLines(bytes);
    // empty input: maxPosition is -1, and read() returns -1 (EOF) immediately.
    this.maxPosition = this.bytes.length() - 1;
  }

  public static JsonInputStream newReader(byte[] bytes, boolean allowComments) {
    return new JsonInputStream(new String(bytes, StandardCharsets.UTF_8), allowComments);
  }

  public static JsonInputStream newReader(String text, boolean allowComments) {
    return newReader(text.getBytes(StandardCharsets.UTF_8), allowComments);
  }

  public static JsonInputStream newReader(Path path, boolean allowComments) throws CodecException {
    byte[] bytes;
    try {
      bytes = Files.readAllBytes(path);
    } catch (IOException e) {
      throw new CodecException.CodecIOException(e);
    }

    return newReader(bytes, allowComments);
  }

  public static JsonInputStream newReader(InputStream is, boolean allowComments)
      throws CodecException {
    byte[] bytes;
    try {
      bytes = is.readAllBytes();
      is.close();
    } catch (IOException e) {
      throw new CodecException.CodecIOException(e);
    }

    return newReader(bytes, allowComments);
  }

  public static boolean hasMultipleLines(String bytes) {
    int n = bytes.length();
    for (int i = 0; i < n; i++) {
      char b = bytes.charAt(i);

      boolean foundNl = false;
      if (b == '\r') {
        foundNl = true;
        if (i + 1 < n && bytes.charAt(i + 1) == '\n') {
          i++;
        }
      } else if (b == '\n') {
        foundNl = true;
      }

      if (foundNl) {
        return i + 1 < n;
      }
    }

    return false;
  }

  public int position() {
    return position;
  }

  public void close() {
    bytes = null;
  }

  public int read() throws CodecException {
    if (position == maxPosition) {
      return -1;
    }

    if (allowComments && position == -1) {
      // the beginning of the input is the beginning of the first line.
      return readAtLineStart();
    }

    char chr = bytes.charAt(++position);

    if (!allowComments) {
      return chr;
    } else if (chr != '\r' && chr != '\n') {
      return chr;
    }

    if (chr == '\r' && position < maxPosition && bytes.charAt(position + 1) == '\n') {
      ++position;
    }

    return readAtLineStart();
  }

  /**
   * Skips the leading whitespaces and the comment lines.
   * @return the first character after them, or -1 if the end of input is reached.
   */
  private int readAtLineStart() {
    while (true) {
      // skip comment line
      // find first none space char
      int firstNonSpaceChar = -1;
      while (position < maxPosition) {
        char b = bytes.charAt(++position);
        if (!isWhiteSpace(b)) {
          firstNonSpaceChar = b;

          break;
        }
      }

      if (firstNonSpaceChar == '/' || firstNonSpaceChar == '#') {
        // comment line, skip to the first character of next line
        while (position < maxPosition) {
          char b = bytes.charAt(++position);
          if (b == '\r' || b == '\n') {
            break;
          }
        }
      } else {
        return firstNonSpaceChar;
      }
    }
  }

  private static boolean isWhiteSpace(char chr) {
    return chr == ' '  | chr == '\b' | chr == '\f' | chr == '\t' | chr == '\r'  | chr == '\n';
  }
}
