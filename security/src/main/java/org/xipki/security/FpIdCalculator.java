// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * MD'5 Fingerprint calculator.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class FpIdCalculator {

  private FpIdCalculator() {
  }

  /**
   * Hash the data.getBytes("UTF-8") and returns the first 8 bytes of the hash value.
   * @param data data over which the hash value is calculated.
   * @return long represented of the first 8 bytes
   */
  public static long hash(String data) {
    byte[] encoded = StringUtil.toUtf8Bytes(Args.notNull(data, "data"));
    byte[] bytes = HashAlgo.SHA1.hash(encoded);
    return bytesToLong(bytes);
  }

  /**
   * Hash the data and returns the first 8 bytes of the hash value.
   * @param data data over which the hash value is calculated.
   * @return long represented of the first 8 bytes
   */
  public static long hash(byte[] data) {
    byte[] bytes = HashAlgo.SHA1.hash(Args.notNull(data, "data"));
    return bytesToLong(bytes);
  }

  private static long bytesToLong(byte[] bs) {
    int hi = bs[0] << 24 | (bs[1] & 0xff) << 16 | (bs[2] & 0xff) << 8 | (bs[3] & 0xff);
    int lo = bs[4] << 24 | (bs[5] & 0xff) << 16 | (bs[6] & 0xff) << 8 | (bs[7] & 0xff);
    return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
  }

}
