// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.ipadress.IPAddress;

/**
 * RFC 3779, 8360
 * <pre>
 * IPAddressOrRange    ::= CHOICE {
 *     addressPrefix        IPAddress,
 *     addressRange         IPAddressRange }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressOrRange extends ASN1Object {

  private final ASN1IPAddress addressPrefix;

  private final IPAddressRange addressRange;

  public IPAddressOrRange(ASN1IPAddress addressPrefix) {
    this.addressPrefix = Args.notNull(addressPrefix, "addressPrefix");
    this.addressRange = null;
  }

  public IPAddressOrRange(IPAddressRange addressRange) {
    this.addressPrefix = null;
    this.addressRange = Args.notNull(addressRange, "addressRange");
  }

  public ASN1IPAddress addressPrefix() {
    return addressPrefix;
  }

  public IPAddressRange addressRange() {
    return addressRange;
  }

  public String toString(int afi) {
    if (addressPrefix != null) {
      return addressPrefix.toString(afi, IPAddress.Context.PREFIX);
    } else {
      return addressRange.toString(afi);
    }
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return addressPrefix != null
        ? addressPrefix.toASN1Primitive()
        : addressRange.toASN1Primitive();
  }

  public static IPAddressOrRange getInstance(Object  obj) {
    if (obj instanceof IPAddressOrRange) {
      return (IPAddressOrRange) obj;
    } else if (obj instanceof ASN1BitString) {
      return new IPAddressOrRange(ASN1IPAddress.getInstance(obj));
    } else {
      return new IPAddressOrRange(IPAddressRange.getInstance(obj));
    }
  }

}
