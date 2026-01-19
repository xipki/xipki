// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.math.BigInteger;

/**
 * RFC 3779, 8360
 * <pre>
 *    ASRange             ::= SEQUENCE {
 *        min                 ASId,
 *        max                 ASId }
 *
 *    ASId                ::= INTEGER
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASRange extends ASN1Object {

  private final ASN1Integer min;

  private final ASN1Integer max;

  public ASRange(BigInteger min, BigInteger max) {
    this.min = new ASN1Integer(Args.notNull(min, "min"));
    this.max = new ASN1Integer(Args.notNull(max, "max"));
  }

  public ASRange(ASN1Integer min, ASN1Integer max) {
    this.min = Args.notNull(min, "min");
    this.max = Args.notNull(max, "max");
  }

  private ASRange(ASN1Sequence seq) {
    if (seq.size() != 2) {
      throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    this.min = ASN1Integer.getInstance(seq.getObjectAt(0));
    this.max = ASN1Integer.getInstance(seq.getObjectAt(1));
  }

  public ASN1Integer getMin() {
    return min;
  }

  public ASN1Integer getMax() {
    return max;
  }

  @Override
   public String toString() {
    return min.getValue() + "-" + max.getValue();
   }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vec = new ASN1EncodableVector(2);
    vec.add(min);
    vec.add(max);
    return new DERSequence(vec);
  }

  public static ASRange getInstance(Object  obj) {
    if (obj instanceof ASRange) {
      return (ASRange)obj;
    } else if (obj != null) {
      return new ASRange(ASN1Sequence.getInstance(obj));
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
