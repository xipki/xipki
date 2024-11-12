// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.common.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.util.Base64Url;

import java.util.Arrays;

/**
 * Test for {@link Base64Url}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
public class Base64UrlTest {

  @Test
  public void testEncodeWithPadding() {
    int[] lens = {0, 7, 8, 9};

    for (int len : lens) {
      int left = len % 3;
      int expectedLen = len / 3 * 4 + (left + 2) / 3 * 4;
      System.out.println("testEncodeWithPadding len=" + len + ", encoded len=" + expectedLen);
      byte[] data = new byte[len];
      Arrays.fill(data, (byte) 0x11);
      byte[] encodedBytes = Base64Url.encodeToByte(data);
      byte[] decoded1 = Base64Url.decodeFast(encodedBytes);
      Assert.assertEquals(expectedLen, encodedBytes.length);
      Assert.assertArrayEquals(data, decoded1);

      char[] encodedChars = Base64Url.encodeToChar(data);
      byte[] decoded2 = Base64Url.decodeFast(encodedChars);
      Assert.assertEquals(expectedLen, encodedChars.length);
      Assert.assertArrayEquals(data, decoded2);
    }
  }

  @Test
  public void testEncodeWithoutPadding() {
    int[] lens = {0, 7, 8, 9};

    for (int len : lens) {
      int left = len % 3;
      int expectedLen = len / 3 * 4;
      if (left == 1) {
        expectedLen += 2;
      } else if (left == 2) {
        expectedLen += 3;
      }
      System.out.println("testEncodeWithoutPadding len=" + len + ", encoded len=" + expectedLen);

      byte[] data = new byte[len];
      Arrays.fill(data, (byte) 0x11);
      byte[] encodedBytes = Base64Url.encodeToByteNoPadding(data);
      byte[] decoded1 = Base64Url.decodeFast(encodedBytes);
      Assert.assertEquals(expectedLen, encodedBytes.length);
      Assert.assertArrayEquals(data, decoded1);

      char[] encodedChars = Base64Url.encodeToCharNoPadding(data);
      byte[] decoded2 = Base64Url.decodeFast(encodedChars);
      Assert.assertEquals(expectedLen, encodedChars.length);
      Assert.assertArrayEquals(data, decoded2);
    }
  }

}
