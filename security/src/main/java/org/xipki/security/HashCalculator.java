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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.common.concurrent.ConcurrentBagEntry;
import org.xipki.common.concurrent.ConcurrentBag;
import org.xipki.common.util.Base64;
import org.xipki.common.util.Hex;
import org.xipki.common.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class HashCalculator {

  private static final int PARALLELISM = 50;

  private static final ConcurrentHashMap<HashAlgoType, ConcurrentBag<ConcurrentBagEntry<Digest>>>
      MDS_MAP = new ConcurrentHashMap<>();

  static {
    for (HashAlgoType ha : HashAlgoType.values()) {
      MDS_MAP.put(ha, getMessageDigests(ha));
    }
  }

  private HashCalculator() {
  }

  private static ConcurrentBag<ConcurrentBagEntry<Digest>> getMessageDigests(
      HashAlgoType hashAlgo) {
    ConcurrentBag<ConcurrentBagEntry<Digest>> mds = new ConcurrentBag<>();
    for (int i = 0; i < PARALLELISM; i++) {
      mds.add(new ConcurrentBagEntry<Digest>(hashAlgo.createDigest()));
    }
    return mds;
  }

  public static String base64Sha1(byte[] data) {
    return Base64.encodeToString(hash(HashAlgoType.SHA1, data, 0, data.length));
  }

  public static String base64Sha1(byte[] data, int offset, int len) {
    return Base64.encodeToString(hash(HashAlgoType.SHA1, data, offset, len));
  }

  public static String hexSha1(byte[] data) {
    return Hex.encode(hash(HashAlgoType.SHA1, data, 0, data.length));
  }

  public static String hexSha1(byte[] data, int offset, int len) {
    return Hex.encode(hash(HashAlgoType.SHA1, data, offset, len));
  }

  public static byte[] sha1(byte[] data) {
    return hash(HashAlgoType.SHA1, data, 0, data.length);
  }

  public static byte[] sha1(byte[] data, int offset, int len) {
    return hash(HashAlgoType.SHA1, data, offset, len);
  }

  public static String base64Sha256(byte[] data) {
    return Base64.encodeToString(hash(HashAlgoType.SHA256, data, 0, data.length));
  }

  public static String base64Sha256(byte[] data, int offset, int len) {
    return Base64.encodeToString(hash(HashAlgoType.SHA256, data, offset, len));
  }

  public static String hexSha256(byte[] data) {
    return Hex.encode(hash(HashAlgoType.SHA256, data, 0, data.length));
  }

  public static String hexSha256(byte[] data, int offset, int len) {
    return Hex.encode(hash(HashAlgoType.SHA256, data, offset, len));
  }

  public static byte[] sha256(byte[] data) {
    return hash(HashAlgoType.SHA256, data, 0, data.length);
  }

  public static byte[] sha256(byte[] data, int offset, int len) {
    return hash(HashAlgoType.SHA256, data, offset, len);
  }

  public static String hexHash(HashAlgoType hashAlgoType, byte[] data) {
    return Hex.encode(hash(hashAlgoType, data, 0, data.length));
  }

  public static String hexHash(HashAlgoType hashAlgoType, byte[] data, int offset, int len) {
    return Hex.encode(hash(hashAlgoType, data, offset, len));
  }

  public static String base64Hash(HashAlgoType hashAlgoType, byte[] data) {
    return Base64.encodeToString(hash(hashAlgoType, data, 0, data.length));
  }

  public static String base64Hash(HashAlgoType hashAlgoType, byte[] data, int offset, int len) {
    return Base64.encodeToString(hash(hashAlgoType, data, offset, len));
  }

  public static byte[] hash(HashAlgoType hashAlgoType, byte[] data) {
    return hash(hashAlgoType, data, 0, data.length);
  }

  public static byte[] hash(HashAlgoType hashAlgoType, byte[] data, int offset, int len) {
    ParamUtil.requireNonNull("hashAlgoType", hashAlgoType);
    ParamUtil.requireNonNull("data", data);
    if (data.length - offset < len) {
      throw new IndexOutOfBoundsException("data.length - offset < len");
    }

    if (!MDS_MAP.containsKey(hashAlgoType)) {
      throw new IllegalArgumentException("unknown hash algo " + hashAlgoType);
    }

    ConcurrentBag<ConcurrentBagEntry<Digest>> mds = MDS_MAP.get(hashAlgoType);

    ConcurrentBagEntry<Digest> md0 = null;
    for (int i = 0; i < 3; i++) {
      try {
        md0 = mds.borrow(10, TimeUnit.SECONDS);
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
      md.update(data, offset, len);
      byte[] bytes = new byte[md.getDigestSize()];
      md.doFinal(bytes, 0);
      return bytes;
    } finally {
      mds.requite(md0);
    }
  } // method hash

}
