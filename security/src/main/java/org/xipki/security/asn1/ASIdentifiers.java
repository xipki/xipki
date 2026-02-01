// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * RFC 3779, 8360
 * <pre>
 *    ASIdentifiers       ::= SEQUENCE {
 *        asnum               [0] EXPLICIT ASIdentifierChoice OPTIONAL,
 *        rdi                 [1] EXPLICIT ASIdentifierChoice OPTIONAL}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASIdentifiers extends ASN1Object {

  private final ASIdentifierChoice asnum;

  private final ASIdentifierChoice rdi;

  public ASIdentifiers(ASIdentifierChoice asnum, ASIdentifierChoice rdi) {
    this.asnum = asnum;
    this.rdi = rdi;
  }

  private ASIdentifiers(ASN1Sequence seq) {
    int size = seq.size();
    if (size > 2) {
      throw new IllegalArgumentException("Bad sequence size: " + size);
    }

    ASIdentifierChoice asnum = null;
    ASIdentifierChoice rdi = null;

    for (int i = 0; i < size; i++) {
      ASN1Encodable obj = seq.getObjectAt(i);
      if (obj instanceof ASN1TaggedObject) {
        ASN1TaggedObject to = (ASN1TaggedObject) obj;
        int tag = to.getTagNo();
        if (tag == 0) {
          asnum = ASIdentifierChoice.getInstance(to.getBaseObject());
        } else if (tag == 1) {
          rdi = ASIdentifierChoice.getInstance(to.getBaseObject());
        } else {
          throw new IllegalArgumentException("Bad tag: " + tag);
        }
      } else {
        throw new IllegalArgumentException(
            "Bad object at index " + i + ": " + obj);
      }
    }

    this.asnum = asnum;
    this.rdi = rdi;
  }

  public ASIdentifierChoice asnum() {
    return asnum;
  }

  public ASIdentifierChoice rdi() {
    return rdi;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vec = new ASN1EncodableVector(2);
    if (asnum != null) {
      vec.add(new DERTaggedObject(true, 0, asnum));
    }

    if (rdi != null) {
      vec.add(new DERTaggedObject(true, 1, rdi));
    }

    return new DERSequence(vec);
  }

  public static ASIdentifiers getInstance(Object obj) {
    if (obj instanceof ASIdentifiers) {
      return (ASIdentifiers) obj;
    } else if (obj instanceof ASN1Sequence) {
      return new ASIdentifiers((ASN1Sequence) obj);
    } else if (obj != null) {
      return new ASIdentifiers(ASN1Sequence.getInstance(obj));
    } else {
      throw new IllegalArgumentException("invalid obj: null");
    }
  }

}
