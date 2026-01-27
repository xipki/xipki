// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

/**
 * ASN.1 tagged Sequence of certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class TaggedCertSequence extends ASN1Type {

  private final byte[] encoded;

  private final int encodedLen;

  public TaggedCertSequence(byte[] encodedCert) {
    this(new byte[][]{encodedCert});
  }

  public TaggedCertSequence(byte[][] encodedCerts) {
    int seqBodyLen = 0;
    for (byte[] encodedCert : encodedCerts) {
      seqBodyLen += encodedCert.length;
    }

    int seqLen = getLen(seqBodyLen);
    encodedLen = getLen(seqLen);

    this.encoded = new byte[encodedLen];
    int idx = 0;
    idx += writeHeader((byte) 0xa0, seqLen, encoded, idx);
    idx += writeHeader((byte) 0x30, seqBodyLen, encoded, idx);
    for (byte[] encodedCert : encodedCerts) {
      idx += arraycopy(encodedCert, encoded, idx);
    }
  }

  @Override
  public int getEncodedLength() {
    return encodedLen;
  }

  @Override
  public int write(byte[] out, int offset) {
    return arraycopy(encoded, out, offset);
  }

}
