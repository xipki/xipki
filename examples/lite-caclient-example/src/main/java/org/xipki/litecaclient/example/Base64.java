/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.litecaclient.example;

import java.util.Arrays;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Base64 {
  private static final char[] CA =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
  private static final int[] IA = new int[256];

  static {
    Arrays.fill(IA, -1);
    for (int i = 0, is = CA.length; i < is; ++i) {
      IA[CA[i]] = i;
    }
    IA['='] = 0;
  }

  /**
   * Encodes a raw byte array into a BASE64 <code>char[]</code> representation i accordance with
   * RFC 2045.
   *
   * @param sarr
   *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
   *          returned.
   * @param lineSep
   *          Optional "\r\n" after 76 characters, unless end of file.<br>
   *          No line separator will be in breach of RFC 2045 which specifies max 76 per line but
   *          will be a little faster.
   * @return A BASE64 encoded array. Never <code>null</code>.
   */
  public static final char[] encodeToChar(byte[] sarr, boolean lineSep) {
    // Check special case
    int slen = sarr != null ? sarr.length : 0;
    if (slen == 0) {
      return new char[0];
    }
    //assert sArr != null;

    int elen = (slen / 3) * 3;              // Length of even 24-bits.
    int ccnt = ((slen - 1) / 3 + 1) << 2;   // Returned character count
    int dlen = ccnt + (lineSep ? (ccnt - 1) / 76 << 1 : 0); // Length of returned array
    char[] darr = new char[dlen];

    // Encode even 24-bits
    for (int s = 0, d = 0, cc = 0; s < elen;) {
      // Copy next three bytes into lower 24 bits of int, paying attension to sign.
      int ii = (sarr[s++] & 0xff) << 16 | (sarr[s++] & 0xff) << 8 | (sarr[s++] & 0xff);

      // Encode the int into four chars
      darr[d++] = CA[(ii >>> 18) & 0x3f];
      darr[d++] = CA[(ii >>> 12) & 0x3f];
      darr[d++] = CA[(ii >>> 6) & 0x3f];
      darr[d++] = CA[ii & 0x3f];

      // Add optional line separator
      if (lineSep && ++cc == 19 && d < dlen - 2) {
        darr[d++] = '\r';
        darr[d++] = '\n';
        cc = 0;
      }
    }

    // Pad and encode last bits if source isn't even 24 bits.
    int left = slen - elen; // 0 - 2.
    if (left > 0) {
      // Prepare the int
      int ii = ((sarr[elen] & 0xff) << 10) | (left == 2 ? ((sarr[slen - 1] & 0xff) << 2) : 0);

      // Set last four chars
      darr[dlen - 4] = CA[ii >> 12];
      darr[dlen - 3] = CA[(ii >>> 6) & 0x3f];
      darr[dlen - 2] = left == 2 ? CA[ii & 0x3f] : '=';
      darr[dlen - 1] = '=';
    }
    return darr;
  }

  /**
   * Encodes a raw byte array into a BASE64 <code>String</code> representation i accordance with
   * RFC 2045.
   * @param arr
   *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
   *          returned.
   * @param lineSep
   *          Optional "\r\n" after 76 characters, unless end of file.<br>
   *          No line separator will be in breach of RFC 2045 which specifies max 76 per line but
   *          will be a little faster.
   * @return A BASE64 encoded array. Never <code>null</code>.
   */
  public static final String encodeToString(byte[] arr, boolean lineSep) {
    // Reuse char[] since we can't create a String incrementally anyway and StringBuffer/Builder
    // would be slower.
    return new String(encodeToChar(arr, lineSep));
  }
}
