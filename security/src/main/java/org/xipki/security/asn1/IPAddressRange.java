// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.ipadress.IPAddress;

/**
 * RFC 3779, 8360
 * <pre>
 *    IPAddressRange      ::= SEQUENCE {
 *       min                  IPAddress,
 *       max                  IPAddress }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressRange extends ASN1Object {

  private final ASN1IPAddress min;

  private final ASN1IPAddress max;

  public IPAddressRange(ASN1IPAddress min, ASN1IPAddress max) {
    this.min = Args.notNull(min, "min");
    this.max = Args.notNull(max, "max");
  }

  private IPAddressRange(ASN1Sequence seq) {
    if (seq.size() != 2) {
      throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    this.min = ASN1IPAddress.getInstance(seq.getObjectAt(0));
    this.max = ASN1IPAddress.getInstance(seq.getObjectAt(1));
  }

  public ASN1IPAddress getMin() {
    return min;
  }

  public ASN1IPAddress getMax() {
    return max;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vec = new ASN1EncodableVector(2);
    vec.add(min);
    vec.add(max);
    return new DERSequence(vec);
  }

  public String toString(int afi) {
    return min.toString(afi, IPAddress.Context.RANGE_MIN) + " - "
        + max.toString(afi, IPAddress.Context.RANGE_MAX);
  }

  public static IPAddressRange getInstance(Object  obj) {
    if (obj instanceof IPAddressRange) {
      return (IPAddressRange)obj;
    } else if (obj != null) {
      return new IPAddressRange(ASN1Sequence.getInstance(obj));
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
