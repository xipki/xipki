// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.extra.misc;

import java.io.IOException;
import java.util.Arrays;

/**
 * Util to convert different signature formats.
 *
 * @author Lijun Liao (xipki)
 */
public class SignatureConverter {

  public static byte[] dsaSigPlainToX962(byte[] sig) {
    if (sig.length % 2 != 0) {
      // invalid format, just returns sig.
      return sig;
    }

    int rOrSLen = sig.length / 2;

    //----- determine the length of the DER-encoded R
    int derRLen = rOrSLen;
    // remove the leading zeros.
    for (int i = 0; i < rOrSLen; i++) {
      if (sig[i] == 0) {
        derRLen--;
      } else {
        break;
      }
    }

    // add one zero if the first byte is greater than 127.
    if ((sig[rOrSLen - derRLen] & 0x80) != 0) {
      derRLen++;
    }

    //----- determine the length of the DER-encoded S
    int derSLen = rOrSLen;
    // remove the leading zeros.
    for (int i = 0; i < rOrSLen; i++) {
      if (sig[rOrSLen + i] == 0) {
        derSLen--;
      } else {
        break;
      }
    }

    // add one zero if the first byte is greater than 127.
    if ((sig[sig.length - derSLen] & 0x80) != 0) {
      derSLen++;
    }

    int contentLen = 2 + derRLen + 2 + derSLen;
    int numBytesForContentLen = 1;
    if (contentLen > 127) {
      numBytesForContentLen++;
    }

    // construct the result
    byte[] res = new byte[1 + numBytesForContentLen + contentLen];
    res[0] = 0x30;

    // length
    int offset = 1;
    if (numBytesForContentLen > 1) {
      res[offset++] = (byte) 0x81;
    }
    res[offset++] = (byte) contentLen;

    // R
    res[offset++] = 0x02;
    res[offset++] = (byte) derRLen;

    if (derRLen >= rOrSLen) {
      System.arraycopy(sig, 0, res, offset + derRLen - rOrSLen, rOrSLen);
    } else {
      System.arraycopy(sig, rOrSLen - derRLen, res, offset, derRLen);
    }
    offset += derRLen;

    // S
    res[offset++] = 0x02;
    res[offset++] = (byte) derSLen;

    if (derSLen >= rOrSLen) {
      System.arraycopy(sig, rOrSLen, res, offset + derSLen - rOrSLen, rOrSLen);
    } else {
      System.arraycopy(sig, sig.length - derSLen, res, offset, derSLen);
    }

    return res;
  }

  public static byte[] dsaSigX962ToPlain(byte[] sig) throws IOException {
    return dsaSigX962ToPlain0(sig, null);
  }

  public static byte[] dsaSigX962ToPlain(byte[] sig, int rOrSLen)
      throws IOException {
    return dsaSigX962ToPlain0(sig, rOrSLen);
  }

  private static byte[] dsaSigX962ToPlain0(byte[] sig, Integer rOrSLen)
      throws IOException {
    byte[][] bytesArray = DerUtil.readTwoBigIntBytes(sig, 0, sig.length);
    byte[] r = bytesArray[0];
    byte[] s = bytesArray[1];

    // remove leading zero
    if (r[0] == 0) {
      r = Arrays.copyOfRange(r, 1, r.length);
    }

    if (s[0] == 0) {
      s = Arrays.copyOfRange(s, 1, s.length);
    }

    if (rOrSLen != null) {
      if (r.length > rOrSLen || s.length > rOrSLen) {
        // we can not fix it.
        return sig;
      }
    } else {
      rOrSLen = Math.max(r.length, s.length);
    }

    byte[] rs = new byte[2 * rOrSLen];
    System.arraycopy(r, 0, rs, rOrSLen - r.length, r.length);
    System.arraycopy(s, 0, rs, rs.length - s.length, s.length);
    return rs;
  }
}
