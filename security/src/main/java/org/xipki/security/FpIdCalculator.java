/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security;

import org.xipki.util.StringUtil;

import static org.xipki.util.Args.notNull;

/**
 * MD'5 Fingerprint calculator.
 *
 * @author Lijun Liao
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
    notNull(data, "data");
    byte[] encoded = StringUtil.toUtf8Bytes(data);
    byte[] bytes = HashAlgo.SHA1.hash(encoded);
    return bytesToLong(bytes);
  }

  /**
   * Hash the data and returns the first 8 bytes of the hash value.
   * @param data data over which the hash value is calculated.
   * @return long represented of the first 8 bytes
   */
  public static long hash(byte[] data) {
    notNull(data, "data");
    byte[] bytes = HashAlgo.SHA1.hash(data);
    return bytesToLong(bytes);
  }

  private static long bytesToLong(byte[] bs) {
    int hi = bs[0] << 24 | (bs[1] & 0xff) << 16 | (bs[2] & 0xff) << 8 | (bs[3] & 0xff);
    int lo = bs[4] << 24 | (bs[5] & 0xff) << 16 | (bs[6] & 0xff) << 8 | (bs[7] & 0xff);
    return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
  } // method bytesToLong

}
