// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec;

/**
 * HEX encoder and decoder.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class Hex {

  private static final char[] DIGITS = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  private static final char[] UPPER_DIGITS = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  private static final int[] LINTS = new int['f' + 1];
  private static final int[] HINTS = new int[LINTS.length];

  static {
    for (int i = 0; i < DIGITS.length; i++) {
      LINTS[DIGITS[i]] = i;
    }

    for (int i = 10; i < UPPER_DIGITS.length; i++) {
      LINTS[UPPER_DIGITS[i]] = i;
    }

    for (int i = 0; i < LINTS.length; i++) {
      HINTS[i] = LINTS[i] << 4;
    }
  }

  public static String encode(byte abyte) {
    return new String(new char[]{
        DIGITS[(0xFF & abyte) >>> 4], DIGITS[0x0F & abyte]});
  }

  public static String encodeUpper(byte abyte) {
    return new String(new char[]{
        UPPER_DIGITS[(0xFF & abyte) >>> 4], UPPER_DIGITS[0x0F & abyte]});
  }

  public static String encode(byte[] bytes) {
    return new String(encodeToChars(bytes));
  }

  public static String encode(byte[] bytes, int off, int len) {
    return new String(encodeToChars(bytes, off, len));
  }

  public static char[] encodeToChars(byte[] data) {
    int len = data.length;

    char[] out = new char[len << 1];

    // two characters form the hex value.
    for (int i = 0, j = 0; i < len; i++) {
      out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
      out[j++] = DIGITS[0x0F & data[i]];
    }

    return out;
  }

  public static char[] encodeToChars(byte[] data, int off, int len) {
    if (off + len > data.length) {
      throw new IndexOutOfBoundsException("data is too short");
    }

    char[] out = new char[len << 1];

    // two characters form the hex value.
    for (int i = 0, j = 0; i < len; i++) {
      out[j++] = DIGITS[(0xF0 & data[off + i]) >>> 4];
      out[j++] = DIGITS[ 0x0F & data[off + i]];
    }

    return out;
  }

  public static String encodeUpper(byte[] bytes) {
    return new String(encodeToUpperChars(bytes));
  }

  public static String encodeUpper(byte[] bytes, int off, int len) {
    return new String(encodeToUpperChars(bytes, off, len));
  }

  public static char[] encodeToUpperChars(byte[] data, int off, int len) {
    if (off + len > data.length) {
      throw new IndexOutOfBoundsException("data is too short");
    }

    char[] out = new char[len << 1];

    // two characters form the hex value.
    for (int i = 0, j = 0; i < len; i++) {
      out[j++] = UPPER_DIGITS[(0xF0 & data[off + i]) >>> 4];
      out[j++] = UPPER_DIGITS[ 0x0F & data[off + i]];
    }

    return out;
  }

  public static char[] encodeToUpperChars(byte[] data) {
    int len = data.length;

    char[] out = new char[len << 1];

    // two characters form the hex value.
    for (int i = 0, j = 0; i < len; i++) {
      out[j++] = UPPER_DIGITS[(0xF0 & data[i]) >>> 4];
      out[j++] = UPPER_DIGITS[0x0F & data[i]];
    }

    return out;
  }

  public static byte[] decode(byte[] array) {
    int len = array.length;

    if ((len & 0x01) != 0) {
      throw new IllegalArgumentException("Odd number of characters.");
    }

    byte[] out = new byte[len >> 1];

    // two characters form the hex value.
    for (int i = 0, j = 0; j < len; i++) {
      out[i] = (byte) (HINTS[0xff & array[j++]] | LINTS[0xff & array[j++]]);
    }

    return out;
  }

  public static byte[] decode(String hex) {
    return decode(hex.toCharArray());
  }

  public static byte[] decode(char[] data) {
    int len = data.length;

    if ((len & 0x01) != 0) {
      throw new IllegalArgumentException("Odd number of characters.");
    }

    byte[] out = new byte[len >> 1];

    // two characters form the hex value.
    for (int i = 0, j = 0; j < len; i++) {
      out[i] = (byte) (HINTS[assertValidHex(data[j++])]
          | LINTS[assertValidHex(data[j++])]);
    }

    return out;
  }

  public static int decode(String hex, byte[] out, int outOff) {
    return decode(hex.toCharArray(), out, outOff);
  }

  public static int decode(char[] data, byte[] out, int outOff) {
    int len = data.length;

    if ((len & 0x01) != 0) {
      throw new IllegalArgumentException("Odd number of characters.");
    }

    int outLen = (len >> 1);

    if (out.length < outOff + outLen) {
      throw new IndexOutOfBoundsException("out is too short");
    }

    // two characters form the hex value.
    for (int i = 0, j = 0; j < len; i++) {
      out[outOff + i] = (byte) (HINTS[assertValidHex(data[j++])]
          | LINTS[assertValidHex(data[j++])]);
    }

    return outLen;
  }

  public static byte decodeSingle(byte[] array, int offset) {
    return (byte)  (HINTS[assertValidHex(0xff & array[offset])]
                  | LINTS[assertValidHex(0xff & array[offset + 1])]);
  }

  private static int assertValidHex(char c) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F'))) {
      throw new IllegalArgumentException("invalid character '" + c + "'");
    }
    return c;
  }

  private static int assertValidHex(int c) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F'))) {
      throw new IllegalArgumentException("invalid character '" + c + "'");
    }
    return c;
  }

  public static void append(StringBuilder buf, byte[] data,
                            int numBytesPerLine, String indent) {
    append(false, buf, data, 0, data.length, ":",
        numBytesPerLine, indent);
  }

  public static void append(boolean uppercase, StringBuilder buf, byte[] data,
                            int numBytesPerLin, String indent) {
    append(uppercase, buf, data, 0, data.length, ":",
        numBytesPerLin, indent);
  }

  public static void append(StringBuilder buf, byte[] data, int offset,
                            int len, String sep) {
    append(false, buf, data, offset, len, sep, Integer.MAX_VALUE, "");
  }

  public static void append(boolean uppercase, StringBuilder buf,
                            byte[] data, int offset, int len, String sep) {
    append(uppercase, buf, data, offset, len, sep, Integer.MAX_VALUE, "");
  }

  public static void append(StringBuilder buf, byte[] data, int offset, int len,
                            String sep, int numBytesPerLin, String indent) {
    append(false, buf, data, offset, len, sep, numBytesPerLin, indent);
  }

  public static void append(boolean uppercase, StringBuilder buf,
                            byte[] data, int offset, int len,
                            String sep, int numBytesPerLin, String indent) {
    Args.notNegative(offset, "offset");
    Args.positive(len, "len");
    Args.positive(numBytesPerLin, "numBytesPerLin");

    char[] digits = uppercase ? UPPER_DIGITS : DIGITS;
    int lastOffset = offset + len;
    Args.max(data.length, "data.length", lastOffset);

    buf.append(indent);
    for (int i = 0; i < len; i++) {
      int ii = 0xFF & data[offset + i];
      buf.append(digits[ii >>> 4]).append(digits[0x0F & ii]);

      int i1 = i + 1;
      if (i1 != len) {
        buf.append(sep);
      }

      if (i1 != len && (i1 % numBytesPerLin) == 0) {
        buf.append("\n").append(indent);
      }
    }

    if (numBytesPerLin != Integer.MAX_VALUE) {
      buf.append("\n");
    }
  }

}
