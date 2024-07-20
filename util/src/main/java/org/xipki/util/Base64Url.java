// #THIRDPARTY#

package org.xipki.util;

import java.util.Arrays;

/**
 * This is an implementation of Base64Url based on the fast Base64
 * implementation of Mikael Grev.
 */
public class Base64Url {
  private static final String CA_TEXT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  private static final char[] CA = CA_TEXT.toCharArray();

  private static final byte[] BASE64URL_BYTES = StringUtil.toUtf8Bytes(CA_TEXT + "=");

  private static final int[] IA = new int[256];

  static {
    Arrays.fill(IA, -1);
    for (int i = 0, is = CA.length; i < is; ++i) {
      IA[CA[i]] = i;
    }
    IA['='] = 0;
  }

  public static boolean containsOnlyBase64UrlChars(byte[] bytes, int offset, int len) {
    final int maxIndex = Math.min(bytes.length, offset + len);

    for (int i = offset; i < maxIndex; i++) {
      byte bt = bytes[i];

      boolean contained = false;
      for (byte cb : BASE64URL_BYTES) {
        if (bt == cb) {
          contained = true;
          break;
        }
      }

      if (!contained) {
        return false;
      }
    }

    return true;
  }

  /**
   * Encodes a raw byte array into a BASE64Url <code>char[]</code> representation i accordance with
   * RFC 2045.
   *
   * @param sArr
   *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
   *          returned.
   * @return A BASE64Url encoded array. Never <code>null</code>.
   */
  public static char[] encodeToChar(byte[] sArr) {
    return encodeToChar(sArr, true);
  }

  /**
   * Encodes a raw byte array into a BASE64Url <code>char[]</code> representation i without padding
   * accordance with RFC 2045.
   *
   * @param sArr
   *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
   *          returned.
   * @return A BASE64Url encoded array. Never <code>null</code>.
   */
  public static char[] encodeToCharNoPadding(byte[] sArr) {
    return encodeToChar(sArr, false);
  }

  public static char[] encodeToChar(byte[] sArr, boolean withPadding) {
    // Check special case
    int sLen = sArr != null ? sArr.length : 0;
    if (sLen == 0) {
      return new char[0];
    }
    //assert sArr != null;

    int eLen = (sLen / 3) * 3;              // Length of even 24-bits.
    int left = sLen - eLen; // 0 - 2.

    int dLen;
    if (withPadding) {
      dLen = ((sLen - 1) / 3 + 1) << 2;   // Returned character / byte count
    } else {
      dLen = eLen / 3 * 4;
      if (left == 1) {
        dLen += 2;
      } else if (left == 2) {
        dLen += 3;
      }
    }

    char[] dArr = new char[dLen];

    // Encode even 24-bits
    for (int s = 0, d = 0; s < eLen;) {
      // Copy next three bytes into lower 24 bits of int, paying attention to sign.
      int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

      // Encode the int into four chars
      dArr[d++] = CA[(i >>> 18) & 0x3f];
      dArr[d++] = CA[(i >>> 12) & 0x3f];
      dArr[d++] = CA[(i >>> 6)  & 0x3f];
      dArr[d++] = CA[ i         & 0x3f];
    }

    // Pad and encode last bits if source isn't even 24 bits.
    int offset = eLen / 3 * 4;

    if (left > 0) {
      // Prepare the int
      int i = ((sArr[eLen] & 0xff) << 10) | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

      dArr[offset++] = CA[i >> 12];
      dArr[offset++] = CA[(i >>> 6) & 0x3f];

      // 1 -> 2, 2 -> 3
      if (withPadding) {
        // Set last four chars
        dArr[offset++] = left == 2 ? CA[i & 0x3f] : '=';
        dArr[offset] = '=';
      } else {
        if (left == 2) {
          dArr[offset] = CA[i & 0x3f];
        }
      }
    }
    return dArr;
  }

  /**
   * Decodes a BASE64Url encoded char array that is known to be reasonably well formatted.
   * The preconditions are:<br>
   * + The array must have no line separators at all (one line).<br>
   * + The array may not contain illegal characters within the encoded string<br>
   * + The array CAN have illegal characters at the beginning and end, those will be dealt with
   * appropriately.<br>
   * @param sArr
   *          The source array. Length 0 will return an empty array. <code>null</code> will throw
   *          an exception.
   * @return The decoded array of bytes. May be of length 0.
   */
  public static byte[] decodeFast(char[] sArr) {
    // Check special case
    int sLen = sArr.length;
    if (sLen == 0) {
      return new byte[0];
    }

    int sIx = 0, eIx = sLen - 1;    // Start and end index after trimming.

    // Trim illegal chars from start
    while (sIx < eIx && IA[sArr[sIx]] < 0) {
      ++sIx;
    }

    // Trim illegal chars from end
    while (eIx > 0 && IA[sArr[eIx]] < 0) {
      --eIx;
    }

    // get the padding count (=) (0, 1 or 2)
    int pad = sArr[eIx] == '=' ? (sArr[eIx - 1] == '=' ? 2 : 1) : 0;  // Count '=' at end.
    int cCnt = eIx - sIx + 1;   // Content count including possible separators

    int len = (cCnt * 6 >> 3) - pad; // The number of decoded bytes
    byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

    // Decode all but the last 0 - 2 bytes.
    int d = 0;
    for (int eLen = (len / 3) * 3; d < eLen;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = IA[sArr[sIx++]] << 18 | IA[sArr[sIx++]] << 12
          | IA[sArr[sIx++]] << 6 | IA[sArr[sIx++]];

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      dArr[d++] = (byte) (i >> 8);
      dArr[d++] = (byte) i;
    }

    if (d < len) {
      // Decode last 1-3 bytes (incl '=') into 1-3 bytes
      int i = 0;
      for (int j = 0; sIx <= eIx - pad; ++j) {
        i |= IA[sArr[sIx++]] << (18 - j * 6);
      }

      for (int r = 16; d < len; r -= 8) {
        dArr[d++] = (byte) (i >> r);
      }
    }

    return dArr;
  }

  // ****************************************************************************************
  // *  byte[] version
  // ****************************************************************************************

  /**
   * Encodes a raw byte array into a BASE64Url <code>byte[]</code> representation i accordance with
   * RFC 2045.
   * @param sArr
   *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
   *          returned.
   * @return A BASE64Url encoded array. Never <code>null</code>.
   */
  public static byte[] encodeToByte(byte[] sArr) {
    return encodeToByte(sArr, true);
  }

  /**
   * Encodes a raw byte array into a BASE64Url <code>byte[]</code> representation without padding i
   * accordance with RFC 2045.
   * @param sArr
   *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
   *          returned.
   * @return A BASE64Url encoded array. Never <code>null</code>.
   */
  public static byte[] encodeToByteNoPadding(byte[] sArr) {
    return encodeToByte(sArr, false);
  }

  public static byte[] encodeToByte(byte[] sArr, boolean withPadding) {
    // Check special case
    int sLen = sArr != null ? sArr.length : 0;
    if (sLen == 0) {
      return new byte[0];
    }
    //assert sArr != null;

    int eLen = (sLen / 3) * 3;              // Length of even 24-bits.
    int left = sLen - eLen; // 0 - 2.

    int dLen;
    if (withPadding) {
      dLen = ((sLen - 1) / 3 + 1) << 2;   // Returned character / byte count
    } else {
      dLen = eLen / 3 * 4;
      if (left == 1) {
        dLen += 2;
      } else if (left == 2) {
        dLen += 3;
      }
    }

    byte[] dArr = new byte[dLen];

    // Encode even 24-bits
    for (int s = 0, d = 0; s < eLen;) {
      // Copy next three bytes into lower 24 bits of int, paying attention to sign.
      int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

      // Encode the int into four chars
      dArr[d++] = (byte) CA[(i >>> 18) & 0x3f];
      dArr[d++] = (byte) CA[(i >>> 12) & 0x3f];
      dArr[d++] = (byte) CA[(i >>> 6)  & 0x3f];
      dArr[d++] = (byte) CA[ i         & 0x3f];
    }

    // Pad and encode last bits if source isn't an even 24 bits.
    int offset = eLen / 3 * 4;
    if (left > 0) {
      // Prepare the int
      int i = ((sArr[eLen] & 0xff) << 10) | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

      // Set last four chars
      dArr[offset++] = (byte) CA[i >> 12];
      dArr[offset++] = (byte) CA[(i >>> 6) & 0x3f];

      // 1 -> 2, 2 -> 3
      if (withPadding) {
        dArr[offset++] = left == 2 ? (byte) CA[i & 0x3f] : (byte) '=';
        dArr[offset] = '=';
      } else {
        if (left == 2) {
          dArr[offset] = (byte) CA[i & 0x3f];
        }
      }
    }
    return dArr;
  }

  /**
   * Decodes a BASE64Url encoded byte array that is known to be reasonably well formatted.
   * The preconditions are:<br>
   * + The array must have no line separators at all (one line).<br>
   * + The array may not contain illegal characters within the encoded string<br>
   * + The array CAN have illegal characters at the beginning and end, those will be dealt with
   *   appropriately.<br>
   * @param sArr
   *          The source array. Length 0 will return an empty array. <code>null</code> will throw
   *          an exception.
   * @return The decoded array of bytes. May be of length 0.
   */
  public static byte[] decodeFast(byte[] sArr) {
    // Check special case
    int sLen = sArr.length;
    if (sLen == 0) {
      return new byte[0];
    }

    int sIx = 0, eIx = sLen - 1;    // Start and end index after trimming.

    // Trim illegal chars from start
    while (sIx < eIx && IA[sArr[sIx] & 0xff] < 0) {
      ++sIx;
    }

    // Trim illegal chars from end
    while (eIx > 0 && IA[sArr[eIx] & 0xff] < 0) {
      --eIx;
    }

    // get the padding count (=) (0, 1 or 2)
    int pad = sArr[eIx] == '=' ? (sArr[eIx - 1] == '=' ? 2 : 1) : 0;  // Count '=' at end.
    int cCnt = eIx - sIx + 1;   // Content count

    int len = (cCnt * 6 >> 3) - pad; // The number of decoded bytes
    byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

    // Decode all but the last 0 - 2 bytes.
    int d = 0;
    for (int eLen = (len / 3) * 3; d < eLen;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = IA[sArr[sIx++]] << 18 | IA[sArr[sIx++]] << 12
          | IA[sArr[sIx++]] << 6 | IA[sArr[sIx++]];

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      dArr[d++] = (byte) (i >> 8);
      dArr[d++] = (byte) i;
    }

    if (d < len) {
      // Decode last 1-3 bytes (incl '=') into 1-3 bytes
      int i = 0;
      for (int j = 0; sIx <= eIx - pad; ++j) {
        i |= IA[sArr[sIx++]] << (18 - j * 6);
      }

      for (int r = 16; d < len; r -= 8) {
        dArr[d++] = (byte) (i >> r);
      }
    }

    return dArr;
  }

  // ****************************************************************************************
  // * String version
  // ****************************************************************************************

  /**
   * Encodes a raw byte array into a BASE64Url <code>String</code> representation i accordance with
   * RFC 2045.
   * @param sArr
   *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
   *          returned.
   * @return A BASE64Url encoded array. Never <code>null</code>.
   */
  public static String encodeToString(byte[] sArr) {
    return new String(encodeToChar(sArr, true));
  }

  public static String encodeToStringNoPadding(byte[] sArr) {
    return new String(encodeToChar(sArr, false));
  }

  public static String encodeToString(byte[] sArr, boolean withPadding) {
    return new String(encodeToChar(sArr, withPadding));
  }

  /**
   * Decodes a BASE64Url encoded string that is known to be reasonably well formatted.
   * The preconditions are:<br>
   * + The array must have no line separators at all (one line).<br>
   * + The array may not contain illegal characters within the encoded string<br>
   * + The array CAN have illegal characters at the beginning and end, those will be dealt with
   *    appropriately.<br>
   * @param s
   *          The source string. Length 0 will return an empty array. <code>null</code> will
   *          throw an exception.
   * @return The decoded array of bytes. May be of length 0.
   */
  public static byte[] decodeFast(String s) {
    // Check special case
    int sLen = s.length();
    if (sLen == 0) {
      return new byte[0];
    }

    int sIx = 0, eIx = sLen - 1;    // Start and end index after trimming.

    // Trim illegal chars from start
    while (sIx < eIx && IA[s.charAt(sIx) & 0xff] < 0) {
      ++sIx;
    }

    // Trim illegal chars from end
    while (eIx > 0 && IA[s.charAt(eIx) & 0xff] < 0) {
      --eIx;
    }

    // get the padding count (=) (0, 1 or 2)
    int pad = s.charAt(eIx) == '='
        ? (s.charAt(eIx - 1) == '=' ? 2 : 1) : 0; // Count '=' at end.
    int cCnt = eIx - sIx + 1;   // Content count including possible separators

    int len = (cCnt * 6 >> 3) - pad; // The number of decoded bytes
    byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

    // Decode all but the last 0 - 2 bytes.
    int d = 0;
    for (int eLen = (len / 3) * 3; d < eLen;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = IA[s.charAt(sIx++)] << 18 | IA[s.charAt(sIx++)] << 12
          | IA[s.charAt(sIx++)] << 6 | IA[s.charAt(sIx++)];

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      dArr[d++] = (byte) (i >> 8);
      dArr[d++] = (byte) i;
    }

    if (d < len) {
      // Decode last 1-3 bytes (incl '=') into 1-3 bytes
      int i = 0;
      for (int j = 0; sIx <= eIx - pad; ++j) {
        i |= IA[s.charAt(sIx++)] << (18 - j * 6);
      }

      for (int r = 16; d < len; r -= 8) {
        dArr[d++] = (byte) (i >> r);
      }
    }

    return dArr;
  }
}
