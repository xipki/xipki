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

package org.xipki.security.bc;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Digest for SHAKE128-256 and SHAKE256-512.
 * @author Lijun Liao
 *
 */
public class XiShakeDigest implements ExtendedDigest {

  private final String name;

  private final int size;

  private final SHAKEDigest underlying;

  public static class XiShake128Digest extends XiShakeDigest {
    public XiShake128Digest() {
      super(128, 256);
    }
  }

  public static class XiShake256Digest extends XiShakeDigest {
    public XiShake256Digest() {
      super(256, 512);
    }
  }

  private XiShakeDigest(int type, int size) {
    this.name = "SHAKE" + type + "-" + size;
    this.underlying = new SHAKEDigest(type);
    this.size = size;
  }

  /**
   * mask generator function, as described in RFC 8692 and RFC 8702.
   */
  public byte[] maskGeneratorFunction(
      // CHECKSTYLE:SKIP
      byte[]  Z,
      int     length) {
    return maskGeneratorFunction(Z, 0, Z.length, length);
  }

  /**
   * mask generator function, as described in RFC 8692 and RFC 8702.
   */
  public byte[] maskGeneratorFunction(
      // CHECKSTYLE:SKIP
      byte[]  Z,
      // CHECKSTYLE:SKIP
      int     zOff,
      // CHECKSTYLE:SKIP
      int     zLen,
      int     length) {
    byte[]  mask = new byte[length];
    underlying.reset();
    underlying.update(Z, zOff, zLen);
    underlying.doFinal(mask, 0, length);
    return mask;
  }

  @Override
  public String getAlgorithmName() {
    return name;
  }

  @Override
  public int getDigestSize() {
    return size / 8;
  }

  @Override
  public void update(byte in) {
    underlying.update(in);
  }

  @Override
  public void update(byte[] in, int inOff, int len) {
    underlying.update(in, inOff, len);
  }

  @Override
  public int doFinal(byte[] out, int outOff) {
    return underlying.doFinal(out, outOff, size / 8);
  }

  @Override
  public void reset() {
    underlying.reset();
  }

  @Override
  public int getByteLength() {
    return underlying.getByteLength();
  }

}
