// #THIRDPARTY#

package org.xipki.util.codec;

import java.util.Arrays;

/**
 * This class is based on the Base64 implemented by Mikael Grev, and licensed
 * under BSD.
 */

public abstract class Base64 {

  private static final char[] STD_CA =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
          .toCharArray();

  private static final char[] URL_CA;

  private static final int[] IA = new int[256];

  private static final Encoder pemEncoder =
      new Encoder(false, true, false, 64);

  private static final Encoder encoder = new Encoder(false, true);

  private static final Encoder noPaddingEncoder = new Encoder(false, false);

  private static final Encoder urlEncoder = new Encoder(true, true);

  private static final Encoder urlNoPaddingEncoder = new Encoder(true, false);

  static {
    URL_CA = STD_CA.clone();
    URL_CA[62] = '-';
    URL_CA[63] = '_';

    Arrays.fill(IA, -1);
    for (int i = 0, is = STD_CA.length; i < is; ++i) {
      IA[STD_CA[i]] = i;
    }
    IA['='] = 0;

    IA['-'] = 62;
    IA['_'] = 63;
  }

  public static Encoder getEncoder() {
    return encoder;
  }

  public static Encoder getUrlEncoder() {
    return urlEncoder;
  }

  public static Encoder getNoPaddingEncoder() {
    return noPaddingEncoder;
  }

  public static Encoder getUrlNoPaddingEncoder() {
    return urlNoPaddingEncoder;
  }

  public static byte[] encodeToByte(byte[] sArr) {
    return encoder.encodeToByte(sArr);
  }

  public static char[] encodeToChar(byte[] sArr) {
    return encoder.encodeToChar(sArr);
  }

  public static String encodeToString(byte[] sArr) {
    return encoder.encodeToString(sArr);
  }

  public static byte[] encodeToByte(byte[] sArr, boolean lineSep) {
    return encoder.encodeToByte(sArr, lineSep);
  }

  public static char[] encodeToChar(byte[] sArr, boolean lineSep) {
    return encoder.encodeToChar(sArr, lineSep);
  }

  public static String encodeToString(byte[] sArr, boolean lineSep) {
    return encoder.encodeToString(sArr, lineSep);
  }

  public static boolean containsOnlyValidChars(byte[] bytes) {
    return containsOnlyValidChars(bytes, 0, bytes.length);
  }

  public static boolean containsOnlyValidChars(
      byte[] bytes, int off, int len) {
    int endIndex = off + len;
    for (int i = off; i < endIndex; i++) {
      int x = bytes[i] & 0xFF;
      if ((x >= '0' && x <= '9')
          || (x >= 'a' && x <= 'z')
          || (x >= 'A' && x <= 'Z')
          || (x == '=') || (x == '+') || (x == '/')
          || (x == '-') || (x == '_')) {
        continue;
      }

      return false;
    }

    return true;
  }

  /**
   * Encodes a raw byte array into a PEM <code>byte[]</code> representation
   * in accordance with RFC 2045, with line 64 characters per line, and with
   * LF as line separator.
   * @param sArr
   *          The bytes to convert. If <code>null</code> or length 0 an empty
   *          array will be returned.
   * @return A BASE64 encoded array. Never <code>null</code>.
   */
  public static String encodeToPemString(byte[] sArr) {
    Args.notNull(sArr, "sArr");
    return pemEncoder.encodeToString(sArr, true);
  }

  public static byte[] encodeToPemByte(byte[] sArr) {
    Args.notNull(sArr, "sArr");
    return pemEncoder.encodeToByte(sArr, true);
  }

  /**
   * Decodes a BASE64 / BASE64-URL encoded char array. All illegal characters will be
   * ignored and can handle both arrays with and without line separators.
   * @param sArr The source array. <code>null</code> or length 0 will return an
   *             empty array.
   * @return The decoded array of bytes. Maybe of length 0.
   */
  public static byte[] decode(char[] sArr) {
    // Check special case
    int sLen = sArr != null ? sArr.length : 0;
    if (sLen == 0) {
      return new byte[0];
    }
    //assert sArr != null;

    // Count illegal characters (including '\r', '\n') to know what size the
    // returned array will be, so we don't have to reallocate & copy it later.
    int sepCnt = 0;

    // Number of separator characters. (Actually illegal characters, but
    // that's a bonus...)
    for (int i = 0; i < sLen; ++i) {
      if (IA[sArr[i]] < 0) {
        ++sepCnt;
      }
    }

    int pad = 0;
    for (int i = sLen; i > 1 && IA[sArr[--i]] <= 0;) {
      if (sArr[i] == '=') {
        ++pad;
      }
    }
    int maxSArrIndex = sArr.length - pad;

    int len = ((sLen - sepCnt) * 6 >> 3) - pad;

    byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

    for (int s = 0, d = 0; d < len;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = 0;
      for (int j = 0; j < 4 && s < maxSArrIndex;) {   // j only increased if a valid char was found.
        int c = IA[sArr[s++]];
        if (c >= 0) {
          i |= c << (18 - j * 6);
          j++;
        }
      }

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      if (d < len) {
        dArr[d++]= (byte) (i >> 8);
        if (d < len) {
          dArr[d++] = (byte) i;
        }
      }
    }
    return dArr;
  }

  /**
   * Decodes a BASE64 /BASE64-URL encoded char array that is known to be reasonably well formatted. The method
   * is about twice as fast as {@link #decode(char[])}. The preconditions are:<br>
   * + The array must have a line length of 76 chars OR no line separators at all (one line).<br>
   * + Line separator must be "\r\n", as specified in RFC 2045
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
    int sepCnt = sLen > 76 ? (sArr[76] == '\r' ? cCnt / 78 : 0) << 1 : 0;

    int len = ((cCnt - sepCnt) * 6 >> 3) - pad; // The number of decoded bytes
    byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

    // Decode all but the last 0 - 2 bytes.
    int d = 0;
    for (int cc = 0, eLen = (len / 3) * 3; d < eLen;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = IA[sArr[sIx++]] << 18 | IA[sArr[sIx++]] << 12
          | IA[sArr[sIx++]] << 6 | IA[sArr[sIx++]];

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      dArr[d++] = (byte) (i >> 8);
      dArr[d++] = (byte) i;

      // If line separator, jump over it.
      if (sepCnt > 0 && ++cc == 19) {
        sIx += 2;
        cc = 0;
      }
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

  /**
   * Decodes a BASE64 / BASE&$-URL encoded <code>String</code>. All illegal characters will be ignored and can
   * handle both strings with and without line separators.<br>
   * <b>Note!</b> It can be up to about 2x the speed to call
   * <code>decode(str.toCharArray())</code> instead. That will create a temporary array though.
   * This version will use <code>str.charAt(i)</code> to iterate the string.
   * @param str
   *          The source string. <code>null</code> or length 0 will return an empty array.
   * @return The decoded array of bytes. May be of length 0.
   * @throws IllegalArgumentException
   *         If the legal characters (including '=') isn't divideable by 4.
   *         (I.e. definitely corrupted).
   */
  public static byte[] decode(String str) {    // Check special case
    return str == null || str.isEmpty() ? new byte[0]
        : decode(str.toCharArray());
  }

  /**
   * Decodes a BASE64 / BASE64-URL encoded string that is known to be resonably well formatted. The method is
   * about twice as fast as {@link #decode(String)}. The preconditions are:<br>
   * + The array must have a line length of 76 chars OR no line separators at all (one line).<br>
   * + Line separator must be "\r\n", as specified in RFC 2045
   * + The array may not contain illegal characters within the encoded string<br>
   * + The array CAN have illegal characters at the beginning and end, those will be dealt with
   *    appropriately.<br>
   * @param s
   *          The source string. Length 0 will return an empty array. <code>null</code> will
   *          throw an exception.
   * @return The decoded array of bytes. May be of length 0.
   */
  public static byte[] decodeFast(String s) {
    return s == null || s.isEmpty() ? new byte[0]
        : decodeFast(s.toCharArray());
  }

  /**
   * Decodes a BASE64 / BASE64URL encoded byte array. All illegal characters will be ignored and can handle
   * both arrays with and without line separators.
   * @param sArr
   *          The source array. Length 0 will return an empty array. <code>null</code> will throw
   *          an exception.
   * @return The decoded array of bytes. May be of length 0.
   * @throws IllegalArgumentException
   *         If the legal characters (including '=') isn't divideable by 4.
   *         (I.e. definitely corrupted).
   */
  public static byte[] decode(byte[] sArr) {
    // Check special cases
    int sLen = sArr.length;

    // Count illegal characters (including '\r', '\n') to know what size the returned array
    // will be, so we don't have to reallocate & copy it later.
    // Number of separator characters. (Actually illegal characters, but that's a bonus...)
    int sepCnt = 0;
    for (byte b : sArr) {
      if (IA[b & 0xff] < 0) {
        ++sepCnt;
      }
    }

    int pad = 0;
    for (int i = sLen; i > 1 && IA[sArr[--i] & 0xff] <= 0;) {
      if (sArr[i] == '=') {
        ++pad;
      }
    }
    int maxSArrIndex = sArr.length - pad;

    int len = ((sLen - sepCnt) * 6 >> 3) - pad;

    byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

    for (int s = 0, d = 0; d < len;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = 0;
      for (int j = 0; j < 4 && s < maxSArrIndex;) {   // j only increased if a valid char was found.
        int c = IA[sArr[s++] & 0xff];
        if (c >= 0) {
          i |= c << (18 - j * 6);
          j++;
        }
      }

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      if (d < len) {
        dArr[d++]= (byte) (i >> 8);
        if (d < len) {
          dArr[d++] = (byte) i;
        }
      }
    }

    return dArr;
  }

  /**
   * Decodes a BASE64 / BASE64-URL encoded byte array that is known to be reasonably well formatted. The method
   * is about twice as fast as {@link #decode(byte[])}. The preconditions are:<br>
   * + The array must have a line length of 76 chars OR no line separators at all (one line).<br>
   * + Line separator must be "\r\n", as specified in RFC 2045
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
    int cCnt = eIx - sIx + 1;   // Content count including possible separators
    int sepCnt = sLen > 76 ? (sArr[76] == '\r' ? cCnt / 78 : 0) << 1 : 0;

    int len = ((cCnt - sepCnt) * 6 >> 3) - pad; // The number of decoded bytes
    byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

    // Decode all but the last 0 - 2 bytes.
    int d = 0;
    for (int cc = 0, eLen = (len / 3) * 3; d < eLen;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = IA[sArr[sIx++]] << 18 | IA[sArr[sIx++]] << 12
          | IA[sArr[sIx++]] << 6 | IA[sArr[sIx++]];

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      dArr[d++] = (byte) (i >> 8);
      dArr[d++] = (byte) i;

      // If line separator, jump over it.
      if (sepCnt > 0 && ++cc == 19) {
        sIx += 2;
        cc = 0;
      }
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

  public static class Encoder {

    private final boolean base64Url;

    private final boolean withPadding;

    private final boolean CRLFAsLineSep;

    private final int charsPerLine;

    private Encoder(boolean base64Url, boolean withPadding) {
      this(base64Url, withPadding, true, 76);
    }

    private Encoder(boolean base64Url, boolean withPadding,
                    boolean CRLFAsLineSep, int charsPerLine) {
      this.base64Url = base64Url;
      this.withPadding = withPadding;
      this.CRLFAsLineSep = CRLFAsLineSep;
      this.charsPerLine = charsPerLine;
    }

    public boolean containsOnlyValidChars(byte[] bytes, int off, int len) {
      int endIndex = off + len;
      for (int i = off; i < endIndex; i++) {
        int x = bytes[i] & 0xFF;
        if ((x >= '0' && x <= '9')
            || (x >= 'a' && x <= 'z')
            || (x >= 'A' && x <= 'Z')
            || (x == '\r' || x == '\n')) {
          continue;
        }

        switch (x) {
          case '=':
            if (!withPadding) {
              return false;
            }
            break;
          case '+':
          case '/':
            if (base64Url) {
              return false;
            }
            break;
          case '-':
          case '_':
            if (!base64Url) {
              return false;
            }
            break;
          default:
            return false;
        }
      }

      return true;
    }

    /**
     * The same as encodeToChar(byte[], false)
     *
     * @param sArr The bytes to convert. If <code>null</code> or length 0, an
     *             empty array will be returned.
     * @return A BASE64 encoded array without line separator.
     */
    public char[] encodeToChar(byte[] sArr) {
      return encodeToChar(sArr, false);
    }

    /**
     * Encodes a raw byte array into a BASE64 <code>char[]</code> representation
     * in accordance with RFC 2045.
     *
     * @param sArr The bytes to convert. If <code>null</code> or length 0 an
     *            empty array will be returned.
     * @param lineSep
     *          Optional "\r\n" or "\n" after 76 characters, unless end of file.<br>
     *          No line separator will be in breach of RFC 2045 which specifies
     *          max 76 per line but will be a little faster.
     * @return A BASE64 encoded array. Never <code>null</code>.
     */
    public char[] encodeToChar(byte[] sArr, boolean lineSep) {
      // Check special case
      int sLen = sArr != null ? sArr.length : 0;
      if (sLen == 0) {
        return new char[0];
      }
      //assert sArr != null;

      // Length of even 24-bits.
      int eLen = (sLen / 3) * 3;
      // Returned character count
      int cCnt = ((sLen - 1) / 3 + 1) << 2;

      // Length of returned array
      int dLen = cCnt;
      if (lineSep) {
        int numSeps = (cCnt - 1) / charsPerLine;
        dLen += numSeps;
        if (CRLFAsLineSep) {
          dLen += numSeps;
        }
      }

      int left = sLen - eLen;
      if (!withPadding && left > 0) {
        dLen -= (left == 1) ? 2 : 1;
      }

      char[] dArr = new char[dLen];

      char[] CA = base64Url ? URL_CA : STD_CA;

      // Encode even 24-bits
      final int numGroups = charsPerLine / 4;

      for (int s = 0, d = 0, cc = 0; s < eLen;) {
        // Copy the next three bytes into lower 24 bits of int, paying attention to sign.
        int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

        // Encode the int into four chars
        dArr[d++] = CA[(i >>> 18) & 0x3f];
        dArr[d++] = CA[(i >>> 12) & 0x3f];
        dArr[d++] = CA[(i >>> 6)  & 0x3f];
        dArr[d++] = CA[ i         & 0x3f];

        // Add optional line separator
        if (lineSep && ++cc == numGroups && d < dLen - 2) {
          if (CRLFAsLineSep) {
            dArr[d++] = '\r';
          }
          dArr[d++] = '\n';
          cc = 0;
        }
      }

      // Pad and encode last bits if source isn't even 24 bits.
      if (left > 0) {
        // Prepare the int
        int i = ((sArr[eLen] & 0xff) << 10)
            | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

        int off;
        if (withPadding) {
          off = dLen - 4;
        } else {
          off = (left == 2) ? dLen - 3 : dLen - 2;
        }

        // Set last four chars
        dArr[off++] = CA[ i >> 12];
        dArr[off++] = CA[(i >>> 6) & 0x3f];

        if (withPadding) {
          dArr[off++] = left == 2 ? CA[i & 0x3f] : '=';
          dArr[off] = '=';
        } else {
          if (left == 2) {
            dArr[off] = CA[i & 0x3f];
          }
        }
      }

      return dArr;
    }

    // *******************
    // *  byte[] version
    // *******************

    /**
     *
     * The same #encodeToByte(byte[], false)}.
     * @param sArr
     *          The bytes to convert. If <code>null</code> or length 0 an empty
     *          array will be returned.
     * @return A BASE64 encoded array without line separator. Never <code>null</code>.
     */
    public byte[] encodeToByte(byte[] sArr) {
      return encodeToByte(sArr, false);
    }

    /**
     * Encodes a raw byte array into a BASE64 <code>byte[]</code> representation in accordance with
     * RFC 2045.
     * @param sArr
     *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
     *          returned.
     * @param lineSep
     *         Optional "\r\n" or "\n" after 76 characters, unless end of file.<br>
     *         No line separator will be in breach of RFC 2045 which specifies max 76 per line but
     *         will be a little faster.
     * @return A BASE64 encoded array. Never <code>null</code>.
     */
    public byte[] encodeToByte(byte[] sArr, boolean lineSep) {
      if ((charsPerLine & 0x3) != 0) {
        throw new IllegalArgumentException("charsPerLine % 4 != 0");
      }

      // number of 3-byte groups
      final int nn = charsPerLine >> 2;

      // Check special cases
      int sLen = sArr != null ? sArr.length : 0;
      if (sLen == 0) {
        return new byte[0];
      }
      //assert sArr != null;

      // Length of even 24-bits.
      int eLen = (sLen / 3) * 3;
      // Returned character count
      int cCnt = ((sLen - 1) / 3 + 1) << 2;

      // Length of returned array
      int dLen = cCnt;
      if (lineSep) {
        int numSeps = (cCnt - 1) / charsPerLine;
        dLen += numSeps;
        if (CRLFAsLineSep) {
          dLen += numSeps;
        }
      }

      int left = sLen - eLen;
      if (!withPadding && left > 0) {
        dLen -= (left == 1) ? 2 : 1;
      }

      byte[] dArr = new byte[dLen];

      char[] CA = base64Url ? URL_CA : STD_CA;

      // Encode even 24-bits
      for (int s = 0, d = 0, cc = 0; s < eLen;) {
        // Copy next three bytes into lower 24 bits of int, paying attention to sign.
        int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

        // Encode the int into four chars
        dArr[d++] = (byte) CA[(i >>> 18) & 0x3f];
        dArr[d++] = (byte) CA[(i >>> 12) & 0x3f];
        dArr[d++] = (byte) CA[(i >>> 6)  & 0x3f];
        dArr[d++] = (byte) CA[ i         & 0x3f];

        // Add optional line separator
        if (lineSep && ++cc == nn && d < dLen - 2) {
          if (CRLFAsLineSep) {
            dArr[d++] = '\r';
          }
          dArr[d++] = '\n';
          cc = 0;
        }
      }

      // Pad and encode last bits if source isn't an even 24 bits.
      if (left > 0) {
        // Prepare the int
        int i = ((sArr[eLen] & 0xff) << 10)
            | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

        int off;
        if (withPadding) {
          off = dLen - 4;
        } else {
          off = (left == 2) ? dLen - 3 : dLen - 2;
        }

        // Set last four chars
        dArr[off++] = (byte) CA[ i >> 12];
        dArr[off++] = (byte) CA[(i >>> 6) & 0x3f];

        if (withPadding) {
          dArr[off++] = left == 2 ? (byte) CA[i & 0x3f] : (byte) '=';
          dArr[off] = '=';
        } else {
          if (left == 2) {
            dArr[off] = (byte) CA[i & 0x3f];
          }
        }
      }
      return dArr;
    }

    // ******************
    // * String version
    // ******************

    /**
     *
     * The same as encodeToString(byte[], false).
     *
     * @param sArr
     *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
     *          returned.
     * @return A BASE64 encoded array without line separator. Never <code>null</code>.
     */
    public String encodeToString(byte[] sArr) {
      return encodeToString(sArr, false);
    }

    /**
     * Encodes a raw byte array into a BASE64 <code>String</code> representation in accordance with
     * RFC 2045.
     * @param sArr
     *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
     *          returned.
     * @param lineSep
     *          Optional "\r\n" or "\n" after {@link #charsPerLine} characters, unless end of file.
     * @return A BASE64 encoded array. Never <code>null</code>.
     */
    public String encodeToString(byte[] sArr, boolean lineSep) {
      // Reuse char[] since we can't create a String incrementally anyway and StringBuffer/Builder
      // would be slower.
      return new String(encodeToChar(sArr, lineSep));
    }

  }
}
