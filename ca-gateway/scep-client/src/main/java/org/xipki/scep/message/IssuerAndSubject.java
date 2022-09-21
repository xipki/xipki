/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.scep.message;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.Args;

/**
 * ASN.1 IssuerAndSubject.
 *
 * @author Lijun Liao
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

  public X500Name getIssuer() {
    return issuer;
  }

  public X500Name getSubject() {
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
