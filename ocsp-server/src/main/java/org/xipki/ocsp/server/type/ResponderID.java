// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import org.xipki.pkix.asn1.x500.X500Name;

/**
 * Responder ID.
 *
 * @author Lijun Liao (xipki)
 */
public class ResponderID extends ASN1Type {

  private final byte[] encoded;

  private final int encodedLength;

  public ResponderID(byte[] key) {
    this.encoded = org.xipki.pkix.asn1.ocsp.ResponderID.ofByKey(key).getEncoded();
    this.encodedLength = encoded.length;
  }

  public ResponderID(X500Name name) {
    this.encoded = org.xipki.pkix.asn1.ocsp.ResponderID.ofByName(name).getEncoded();
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
