/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class FpIdCalculator {

  private static final int PARALLELISM = 50;

  private static final ConcurrentBag<ConcurrentBagEntry<Digest>> MDS = getMD5MessageDigests();

  private FpIdCalculator() {
  }

  private static ConcurrentBag<ConcurrentBagEntry<Digest>> getMD5MessageDigests() {
    ConcurrentBag<ConcurrentBagEntry<Digest>> mds = new ConcurrentBag<>();
    for (int i = 0; i < PARALLELISM; i++) {
      Digest md = new SHA1Digest();
      mds.add(new ConcurrentBagEntry<>(md));
    }
    return mds;
  }

  /**
   * Hash the data.getBytes("UTF-8") and returns the first 8 bytes of the hash value.
   * @param data data over which the hash value is calculated.
   * @return long represented of the first 8 bytes
   */
  public static long hash(String data) {
    Args.notNull(data, "data");
    byte[] encoded = StringUtil.toUtf8Bytes(data);
    return hash(encoded);
  }

  /**
   * Hash the data and returns the first 8 bytes of the hash value.
   * @param data data over which the hash value is calculated.
   * @return long represented of the first 8 bytes
   */
  public static long hash(byte[] data) {
    Args.notNull(data, "data");

    ConcurrentBagEntry<Digest> md0 = null;
    for (int i = 0; i < 3; i++) {
      try {
        md0 = MDS.borrow(10, TimeUnit.SECONDS);
        break;
      } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
      }
    }

    if (md0 == null) {
      throw new RuntimeOperatorException("could not get idle MessageDigest");
    }

    try {
      Digest md = md0.value();
      md.reset();
      md.update(data, 0, data.length);
      byte[] bytes = new byte[md.getDigestSize()];
      md.doFinal(bytes, 0);

      return bytesToLong(bytes);
    } finally {
      MDS.requite(md0);
    }
  }

  private static long bytesToLong(byte[] bs) {
    int hi = bs[0] << 24
        | (bs[1] & 0xff) << 16
        | (bs[2] & 0xff) << 8
        | (bs[3] & 0xff);

    int lo = bs[4] << 24
        | (bs[5] & 0xff) << 16
        | (bs[6] & 0xff) << 8
        | (bs[7] & 0xff);

    return ((long)(hi & 0xffffffffL) << 32) | (long)(lo & 0xffffffffL);
  }

}
