// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.util.Base64;
import org.xipki.util.Hex;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static org.xipki.util.Args.notNull;

/**
 * Utility class to calculate hash values.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class HashCalculator {

  private static final int PARALLELISM = 50;

  private static final ConcurrentHashMap<HashAlgo, ConcurrentBag<ConcurrentBagEntry<Digest>>>
      MDS_MAP = new ConcurrentHashMap<>();

  static {
    for (HashAlgo ha : HashAlgo.values()) {
      MDS_MAP.put(ha, getMessageDigests(ha));
    }
  }

  private HashCalculator() {
  }

  private static ConcurrentBag<ConcurrentBagEntry<Digest>> getMessageDigests(HashAlgo hashAlgo) {
    ConcurrentBag<ConcurrentBagEntry<Digest>> mds = new ConcurrentBag<>();
    for (int i = 0; i < PARALLELISM; i++) {
      mds.add(new ConcurrentBagEntry<>(hashAlgo.createDigest()));
    }
    return mds;
  }

  public static String base64Sha1(byte[]... datas) {
    return Base64.encodeToString(hash(HashAlgo.SHA1, datas));
  }

  public static String base64Sha1(byte[] data, int offset, int len) {
    return Base64.encodeToString(hash(HashAlgo.SHA1, data, offset, len));
  }

  public static String hexSha1(byte[]... datas) {
    return Hex.encode(hash(HashAlgo.SHA1, datas));
  }

  public static String hexSha1(byte[] data, int offset, int len) {
    return Hex.encode(hash(HashAlgo.SHA1, data, offset, len));
  }

  public static byte[] sha1(byte[]... datas) {
    return hash(HashAlgo.SHA1, datas);
  }

  public static byte[] sha1(byte[] data, int offset, int len) {
    return hash(HashAlgo.SHA1, data, offset, len);
  }

  public static String base64Sha256(byte[]... datas) {
    return Base64.encodeToString(hash(HashAlgo.SHA256, datas));
  }

  public static String base64Sha256(byte[] data, int offset, int len) {
    return Base64.encodeToString(hash(HashAlgo.SHA256, data, offset, len));
  }

  public static String hexSha256(byte[]... datas) {
    return Hex.encode(hash(HashAlgo.SHA256, datas));
  }

  public static String hexSha256(byte[] data, int offset, int len) {
    return Hex.encode(hash(HashAlgo.SHA256, data, offset, len));
  }

  public static byte[] sha256(byte[]... datas) {
    return hash(HashAlgo.SHA256, datas);
  }

  public static byte[] sha256(byte[] data, int offset, int len) {
    return hash(HashAlgo.SHA256, data, offset, len);
  }

  public static String hexHash(HashAlgo hashAlgo, byte[]... datas) {
    return Hex.encode(hash(hashAlgo, datas));
  }

  public static String hexHash(HashAlgo hashAlgo, byte[] data, int offset, int len) {
    return Hex.encode(hash(hashAlgo, data, offset, len));
  }

  public static String base64Hash(HashAlgo hashAlgo, byte[]... datas) {
    return Base64.encodeToString(hash(hashAlgo, datas));
  }

  public static String base64Hash(HashAlgo hashAlgo, byte[] data, int offset, int len) {
    return Base64.encodeToString(hash(hashAlgo, data, offset, len));
  }

  public static byte[] hash(HashAlgo hashAlgo, byte[]... datas) {
    notNull(hashAlgo, "hashAlgo");
    notNull(datas, "datas");

    if (!MDS_MAP.containsKey(hashAlgo)) {
      throw new IllegalArgumentException("unknown hash algo " + hashAlgo);
    }

    ConcurrentBag<ConcurrentBagEntry<Digest>> mds = MDS_MAP.get(hashAlgo);

    ConcurrentBagEntry<Digest> md0 = null;
    for (int i = 0; i < 3; i++) {
      try {
        md0 = mds.borrow(10, TimeUnit.SECONDS);
        break;
      } catch (InterruptedException ex) {
      }
    }

    if (md0 == null) {
      throw new RuntimeOperatorException("could not get idle MessageDigest");
    }

    try {
      Digest md = md0.value();
      md.reset();
      for (byte[] data : datas) {
        if (data != null && data.length > 0) {
          md.update(data, 0, data.length);
        }
      }

      byte[] bytes = new byte[md.getDigestSize()];
      md.doFinal(bytes, 0);
      return bytes;
    } finally {
      mds.requite(md0);
    }
  } // method hash

  public static byte[] hash(HashAlgo hashAlgo, byte[] data, int offset, int len) {
    notNull(hashAlgo, "hashAlgo");
    notNull(data, "data");

    if (data.length - offset < len) {
      throw new IndexOutOfBoundsException("data.length - offset < len");
    }

    if (!MDS_MAP.containsKey(hashAlgo)) {
      throw new IllegalArgumentException("unknown hash algo " + hashAlgo);
    }

    ConcurrentBag<ConcurrentBagEntry<Digest>> mds = MDS_MAP.get(hashAlgo);

    ConcurrentBagEntry<Digest> md0 = null;
    for (int i = 0; i < 3; i++) {
      try {
        md0 = mds.borrow(10, TimeUnit.SECONDS);
        break;
      } catch (InterruptedException ex) {
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
