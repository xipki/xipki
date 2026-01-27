// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.ipadress.IPAddress;

/**
 * RFC 3779, 8360
 * <pre>
 * IPAddress ::= BIT STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASN1IPAddress extends ASN1Object {

  private final ASN1BitString value;

  public ASN1IPAddress(byte[] bytes, int unusedBits) {
    this.value = new DERBitString(
        Args.notNull(bytes, "bytes"), unusedBits);
  }

  private ASN1IPAddress(ASN1BitString bitString) {
    this.value = Args.notNull(bitString, "bitString");
  }

  public ASN1BitString getValue() {
    return value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return value;
  }

  public String toString(int afi, IPAddress.Context context) {
    return new IPAddress(value.getBytes(), value.getPadBits())
        .toString(afi, context);
  }

  public static ASN1IPAddress getInstance(Object obj) {
    if (obj instanceof ASN1IPAddress) {
      return (ASN1IPAddress) obj;
    } else if (obj instanceof ASN1BitString) {
      return new ASN1IPAddress((ASN1BitString) obj);
    } else if (obj != null) {
      return new ASN1IPAddress(ASN1BitString.getInstance(obj));
    } else {
      throw new IllegalArgumentException("invalid obj: null");
    }
  }

}
