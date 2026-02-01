// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.xipki.util.codec.Args;

/**
 * RFC 3779, 8360
 * <pre>
 *    ASIdOrRange         ::= CHOICE {
 *        id                  ASId,
 *        range               ASRange }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASIdOrRange extends ASN1Object {

  private final ASN1Integer id;

  private final ASRange range;

  public ASIdOrRange(ASN1Integer id) {
    this.id = Args.notNull(id, "id");
    this.range = null;
  }

  public ASIdOrRange(ASRange range) {
    this.id = null;
    this.range = Args.notNull(range, "range");
  }

  public ASN1Integer id() {
    return id;
  }

  public ASRange range() {
    return range;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return id != null ? id : range.toASN1Primitive();
  }

  @Override
  public String toString() {
    if (id != null) {
      return id.toString();
    } else {
      return range.toString();
    }
  }

  public static ASIdOrRange getInstance(Object  obj) {
    if (obj instanceof ASIdOrRange) {
      return (ASIdOrRange) obj;
    } else if (obj instanceof ASN1Integer) {
      return new ASIdOrRange((ASN1Integer) obj);
    } else if (obj != null) {
      return new ASIdOrRange(ASRange.getInstance(obj));
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
