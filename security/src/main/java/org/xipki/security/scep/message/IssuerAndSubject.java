// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.message;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.codec.Args;

/**
 * ASN.1 IssuerAndSubject.
 *
 * @author Lijun Liao (xipki)
 */

public class IssuerAndSubject extends ASN1Object {

  private final X500Name issuer;

  private final X500Name subject;

  private IssuerAndSubject(ASN1Sequence seq) {
    Args.notNull(seq, "seq");
    this.issuer = X500Name.getInstance(seq.getObjectAt(0));
    this.subject = X500Name.getInstance(seq.getObjectAt(1));
  }

  public IssuerAndSubject(X500Name issuer, X500Name subject) {
    this.issuer = Args.notNull(issuer, "issuer");
    this.subject = Args.notNull(subject, "subject");
  }

  public X500Name issuer() {
    return issuer;
  }

  public X500Name subject() {
    return subject;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[]{issuer, subject});
  }

  public static IssuerAndSubject getInstance(Object obj) {
    if (obj instanceof IssuerAndSubject) {
      return (IssuerAndSubject) obj;
    } else if (obj != null) {
      return new IssuerAndSubject(ASN1Sequence.getInstance(obj));
    } else {
      return null;
    }
  }

}
