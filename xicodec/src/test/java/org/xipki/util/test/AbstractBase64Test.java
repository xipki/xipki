// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.test;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * BASE64 encoding tests.
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractBase64Test {

  private static final int startLen = 0;

  private static final int endLen = 200;

  private static final Random rnd = new Random();

  protected abstract String jdkEncode(byte[] data);

  protected abstract byte[] encodeToByte(
      byte[] data, boolean wrapLongLine, boolean withPadding);

  protected abstract String encodeToString(
      byte[] data, boolean wrapLongLine, boolean withPadding);

  protected abstract byte[] decode(byte[] data);

  protected abstract byte[] decode(String data);

  protected abstract byte[] decodeFast(byte[] data);

  protected abstract byte[] decodeFast(String data);

  @Test
  public void testEncodeWrapLineWithPadding() {
    for (int len = startLen; len < endLen; len++) {
      byte[] data = new byte[len];
      rnd.nextBytes(data);
      check("testEncodeWrapLineWithPadding", data, true, true);
    }
  }

  @Test
  public void testEncodeWrapLineNoPadding() {
    for (int len = startLen; len < endLen; len++) {
      byte[] data = new byte[len];
      rnd.nextBytes(data);
      check("testEncodeWrapLineNoPadding", data, true, false);
    }
  }

  @Test
  public void testEncodeSingleLineWithPadding() {
    for (int len = startLen; len < endLen; len++) {
      byte[] data = new byte[len];
      rnd.nextBytes(data);
      check("testEncodeWrapLineWithPadding", data, false, true);
    }
  }

  @Test
  public void testEncodeSingleLineNoPadding() {
    for (int len = startLen; len < endLen; len++) {
      byte[] data = new byte[len];
      rnd.nextBytes(data);
      check("testEncodeWrapLineNoPadding", data, false, false);
    }
  }

  private void check(String desc, byte[] data,
                     boolean wrapLongLine, boolean withPadding) {
    int len = data.length;

    System.out.println(desc + " len=" + len);

    String expectedEncoded = jdkEncode(data);

    if (!withPadding) {
      if (expectedEncoded.endsWith("==")) {
        expectedEncoded = expectedEncoded.substring(
            0, expectedEncoded.length() - 2);
      } else if (expectedEncoded.endsWith("=")) {
        expectedEncoded = expectedEncoded.substring(
            0, expectedEncoded.length() - 1);
      }
    }

    if (wrapLongLine) {
      int numCharsPerLine = 76;
      int eLen = expectedEncoded.length();
      if (eLen > numCharsPerLine) {
        StringBuilder sb = new StringBuilder(
            expectedEncoded.length() + eLen / numCharsPerLine * 2 + 2);

        int index = 0;
        while (index < eLen) {
          int blen = Math.min(numCharsPerLine, eLen - index);
          sb.append(expectedEncoded, index, index + blen);
          sb.append("\r\n");
          index += blen;
        }
        sb.delete(sb.length() - 2, sb.length());
        expectedEncoded = sb.toString();
      }
    }

    // encodeToString
    {
      String encodedStr = encodeToString(data, wrapLongLine, withPadding);
      Assert.assertEquals(expectedEncoded, encodedStr);

      byte[] decodedFast = decodeFast(encodedStr);
      Assert.assertArrayEquals(data, decodedFast);

      byte[] decoded = decode(encodedStr);
      Assert.assertArrayEquals(data, decoded);
    }

    // encodeToByte
    {
      byte[] encodedBytes = encodeToByte(data, wrapLongLine, withPadding);
      Assert.assertEquals(expectedEncoded,
          new String(encodedBytes, StandardCharsets.US_ASCII));

      byte[] decodedFast = decodeFast(encodedBytes);
      Assert.assertArrayEquals(data, decodedFast);

      byte[] decoded = decode(encodedBytes);
      Assert.assertArrayEquals(data, decoded);
    }
  }

}
