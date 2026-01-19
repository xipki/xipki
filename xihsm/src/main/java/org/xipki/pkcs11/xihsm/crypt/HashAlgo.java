// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * Hash algorithm enum.
 *
 * @author Lijun Liao (xipki)
 */

//See https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2019/AlgorithmObjectIdentifiers.html
public enum HashAlgo {

  SHA1(20,     "SHA-1"),
  // rfc5754: no parameters
  SHA224(28,   "SHA-224"),
  SHA256(32,   "SHA-256"),
  SHA384(48,   "SHA-384"),
  SHA512(64,   "SHA-512"),
  SM3(32, "SM3");

  private final int length;

  private final String jceName;

  HashAlgo(int length, String jceName) {
    this.length = length;
    this.jceName = jceName;
  }

  public int getLength() {
    return length;
  }

  public String getJceName() {
    return jceName;
  }

  public ExtendedDigest createDigest() {
    switch (this) {
      case SHA1:
        return new SHA1Digest();
      case SHA224:
        return new SHA224Digest();
      case SHA256:
        return new SHA256Digest();
      case SHA384:
        return new SHA384Digest();
      case SHA512:
        return new SHA512Digest();
      case SM3:
        return new SM3Digest();
      default:
        throw new IllegalStateException(
            "should not reach here, unknown HashAlgo " + name());
    }
  }

  public byte[] hash(byte[]... datas) {
    Digest digest = createDigest();
    for (byte[] data : datas) {
      digest.update(data, 0, data.length);
    }
    byte[] rv = new byte[length];
    digest.doFinal(rv, 0);
    return rv;
  }

}
