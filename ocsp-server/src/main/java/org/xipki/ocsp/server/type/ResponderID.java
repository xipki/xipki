// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;

import java.io.IOException;

/**
 * ASN.1 ResponderID.
 *
 * @author Lijun Liao (xipki)
 */
public class ResponderID extends ASN1Type {

  private final byte[] encoded;

  private final int encodedLength;

  public ResponderID(byte[] key) throws IOException {
    this.encoded = new org.bouncycastle.asn1.ocsp.ResponderID(
                    new DEROctetString(key)).getEncoded();
    this.encodedLength = encoded.length;
  }

  public ResponderID(X500Name name) throws IOException {
    this.encoded = new org.bouncycastle.asn1.ocsp.ResponderID(name)
                    .getEncoded();
    this.encodedLength = encoded.length;
  }

  @Override
  public int encodedLength() {
    return encodedLength;
  }

  @Override
  public int write(byte[] out, int offset) {
    return arraycopy(encoded, out, offset);
  }

}
