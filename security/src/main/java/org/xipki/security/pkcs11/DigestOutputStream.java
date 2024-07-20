// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.crypto.Digest;

import java.io.IOException;
import java.io.OutputStream;

/**
 * {@link OutputStream} with a {@link Digest} as the backend.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class DigestOutputStream extends OutputStream {

  private final Digest digest;

  public DigestOutputStream(Digest digest) {
    this.digest = digest;
  }

  public void reset() {
    digest.reset();
  }

  @Override
  public void write(byte[] bytes, int off, int len) throws IOException {
    digest.update(bytes, off, len);
  }

  @Override
  public void write(byte[] bytes) throws IOException {
    digest.update(bytes, 0, bytes.length);
  }

  @Override
  public void write(int oneByte) throws IOException {
    digest.update((byte) oneByte);
  }

  public byte[] digest() {
    byte[] result = new byte[digest.getDigestSize()];
    digest.doFinal(result, 0);
    reset();
    return result;
  }

}
