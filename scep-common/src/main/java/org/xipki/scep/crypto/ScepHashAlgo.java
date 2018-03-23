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

package org.xipki.scep.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public enum ScepHashAlgo {

  MD5(16, "1.2.840.113549.2.5", "MD5"),
  SHA1(20, "1.3.14.3.2.26", "SHA1"),
  SHA256(32, "2.16.840.1.101.3.4.2.1", "SHA256"),
  SHA512(64, "2.16.840.1.101.3.4.2.3", "SHA512");

  private final int length;

  private final String oid;

  private final String name;

  private ScepHashAlgo(int length, String oid, String name) {
    this.length = length;
    this.oid = oid;
    this.name = name;
  }

  public int getLength() {
    return length;
  }

  public String getOid() {
    return oid;
  }

  public String getName() {
    return name;
  }

  public String hexDigest(byte[] content) {
    byte[] dgst = digest(content);
    return (dgst == null) ? null : Hex.toHexString(dgst);
  }

  public byte[] digest(byte[] content) {
    ScepUtil.requireNonNull("content", content);
    Digest digest;
    if (this == SHA1) {
      digest = new SHA1Digest();
    } else if (this == SHA256) {
      digest = new SHA256Digest();
    } else if (this == SHA512) {
      digest = new SHA512Digest();
    } else if (this == MD5) {
      digest = new MD5Digest();
    } else {
      throw new RuntimeException("should not reach here");
    }
    byte[] ret = new byte[length];
    digest.doFinal(ret, 0);
    return ret;
  }

  public static ScepHashAlgo forNameOrOid(String nameOrOid) {

    String tmpNameOrOid = nameOrOid;

    for (ScepHashAlgo hashAlgo : values()) {
      if (hashAlgo.oid.equals(tmpNameOrOid)) {
        return hashAlgo;
      }

      if (tmpNameOrOid.indexOf('-') != -1) {
        tmpNameOrOid = tmpNameOrOid.replace("-", "");
      }

      if (hashAlgo.name.equalsIgnoreCase(tmpNameOrOid)) {
        return hashAlgo;
      }
    }

    return null;
  }

}
