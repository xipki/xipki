// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

/**
 * Write only extension.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class WritableOnlyExtension extends Extension {

  private final byte[] encoded;

  private final int from;

  private final int encodedLength;

  public WritableOnlyExtension(byte[] encoded) {
    this(encoded, 0, encoded.length);
  }

  public WritableOnlyExtension(byte[] encoded, int from, int encodedLength) {
    this.encoded = encoded;
    this.from = from;
    this.encodedLength = encodedLength;
  }

  @Override
  public int getEncodedLength() {
    return encodedLength;
  }

  @Override
  public int write(byte[] out, int offset) {
    System.arraycopy(encoded, from, out, offset, encodedLength);
    return encodedLength;
  }

}
