// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.provider;

import java.security.MessageDigestSpi;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class SM3MessageDigestSpi extends MessageDigestSpi {

  private final SM3Digest digest;

  public SM3MessageDigestSpi() {
    this.digest = new SM3Digest();
  }

  @Override
  protected void engineUpdate(byte input) {
    digest.update(input);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    digest.update(input, offset, len);
  }

  @Override
  protected byte[] engineDigest() {
    byte[] ret = new byte[32];
    digest.doFinal(ret, 0);
    return ret;
  }

  @Override
  protected void engineReset() {
    digest.reset();
  }

}
