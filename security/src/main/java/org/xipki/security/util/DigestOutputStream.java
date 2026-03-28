// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

/**
 * Digest Output Stream.
 *
 * @author Lijun Liao (xipki)
 */
public class DigestOutputStream extends OutputStream {

  private final MessageDigest digest;

  public DigestOutputStream(MessageDigest digest) {
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
    byte[] result = digest.digest();
    reset();
    return result;
  }

}
