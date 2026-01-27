// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 3779, 8360
 *
 * <pre>
 *    ASIdentifierChoice  ::= CHOICE {
 *       inherit              NULL, -- inherit from issuer --
 *       asIdsOrRanges        SEQUENCE OF ASIdOrRange }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASIdentifierChoice extends ASN1Object {

  private final List<ASIdOrRange> asIdsOrRanges;

  public ASIdentifierChoice() {
    this.asIdsOrRanges = null;
  }

  public ASIdentifierChoice(List<ASIdOrRange> asIdsOrRanges) {
    this.asIdsOrRanges = asIdsOrRanges;
  }

  private ASIdentifierChoice(ASN1Sequence sequence) {
    int size = sequence.size();

    asIdsOrRanges = new ArrayList<>(size);
    for (int i = 0; i < size; i++) {
      asIdsOrRanges.add(ASIdOrRange.getInstance(sequence.getObjectAt(i)));
    }
  }

  public List<ASIdOrRange> getAsIdsOrRanges() {
    return asIdsOrRanges;
  }

  public boolean isInherit() {
    return asIdsOrRanges == null;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    if (asIdsOrRanges == null) {
      return DERNull.INSTANCE;
    }

    return new DERSequence(asIdsOrRanges.toArray(new ASIdOrRange[0]));
  }

  public static ASIdentifierChoice getInstance(Object obj) {
    if (obj instanceof ASIdentifierChoice) {
      return (ASIdentifierChoice) obj;
    } else if (obj instanceof ASN1Sequence) {
      return new ASIdentifierChoice((ASN1Sequence) obj);
    } else if (obj instanceof ASN1Null) {
      return new ASIdentifierChoice();
    } else if (obj instanceof byte[]) {
      try {
        return getInstance(
            new ASN1StreamParser((byte[]) obj).readObject());
      } catch (IOException e) {
        throw new IllegalArgumentException(e);
      }
    } else {
      throw new IllegalArgumentException("invalid object " + obj);
    }
  }

}
