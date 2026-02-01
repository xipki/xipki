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
 *    IPAddressChoice     ::= CHOICE {
 *       inherit              NULL, -- inherit from issuer --
 *       addressesOrRanges    SEQUENCE OF IPAddressOrRange }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressChoice extends ASN1Object {

  private final List<IPAddressOrRange> addressesOrRanges;

  public IPAddressChoice() {
    this.addressesOrRanges = null;
  }

  public IPAddressChoice(List<IPAddressOrRange> addressesOrRanges) {
    this.addressesOrRanges = addressesOrRanges;
  }

  private IPAddressChoice(ASN1Sequence sequence) {
    int size = sequence.size();

    addressesOrRanges = new ArrayList<>(size);
    for (int i = 0; i < size; i++) {
      addressesOrRanges.add(IPAddressOrRange.getInstance(
          sequence.getObjectAt(i)));
    }
  }

  public boolean isInherit() {
    return addressesOrRanges == null;
  }

  public List<IPAddressOrRange> addressesOrRanges() {
    return addressesOrRanges;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    if (addressesOrRanges == null) {
      return DERNull.INSTANCE;
    }

    return new DERSequence(addressesOrRanges.toArray(new IPAddressOrRange[0]));
  }

  public static IPAddressChoice getInstance(Object obj) {
    if (obj instanceof IPAddressChoice) {
      return (IPAddressChoice) obj;
    } else if (obj instanceof ASN1Sequence) {
      return new IPAddressChoice((ASN1Sequence) obj);
    } else if (obj instanceof ASN1Null) {
      return new IPAddressChoice();
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
