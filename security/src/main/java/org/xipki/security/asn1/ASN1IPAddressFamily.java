// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.ipadress.IPAddressFamily;

/**
 * RFC 3779, 8360
 * <pre>
 *    IPAddressFamily     ::= SEQUENCE {    -- AFI & optional SAFI --
 *       addressFamily        OCTET STRING (SIZE (2..3)),
 *       ipAddressChoice      IPAddressChoice }
 * </pre>
 *
 * A list of AFI is available under
 * https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml.
 *
 * A list of SAFI is available under
 * https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
 *
 * @author Lijun Liao (xipki)
 */
public class ASN1IPAddressFamily extends ASN1Object {

  private final ASN1OctetString addressFamily;

  private final IPAddressChoice ipAddressChoice;

  public ASN1IPAddressFamily(ASN1OctetString addressFamily,
                             IPAddressChoice ipAddressChoice) {
    this.addressFamily = Args.notNull(addressFamily, "addressFamily");
    this.ipAddressChoice = Args.notNull(ipAddressChoice, "ipAddressChoice");
  }

  private ASN1IPAddressFamily(ASN1Sequence seq) {
    if (seq.size() != 2) {
      throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    this.addressFamily = ASN1OctetString.getInstance(seq.getObjectAt(0));
    this.ipAddressChoice = IPAddressChoice.getInstance(seq.getObjectAt(1));
  }

  public ASN1OctetString getAddressFamily() {
    return addressFamily;
  }

  public int getAfi() {
    byte[] bytes = addressFamily.getOctets();
    return new IPAddressFamily(bytes).getAfi();
  }

  public IPAddressChoice getIpAddressChoice() {
    return ipAddressChoice;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vec = new ASN1EncodableVector(2);
    vec.add(addressFamily);
    vec.add(ipAddressChoice);
    return new DERSequence(vec);
  }

  public String addressFamilyToString() {
    return new IPAddressFamily(addressFamily.getOctets()).toString();
  }

  public static ASN1IPAddressFamily getInstance(Object obj) {
    if (obj instanceof ASN1IPAddressFamily) {
      return (ASN1IPAddressFamily) obj;
    } else if (obj instanceof ASN1Sequence) {
      return new ASN1IPAddressFamily((ASN1Sequence) obj);
    } else if (obj != null) {
      return new ASN1IPAddressFamily(ASN1Sequence.getInstance(obj));
    } else {
      throw new IllegalArgumentException("invalid obj: null");
    }
  }

}
