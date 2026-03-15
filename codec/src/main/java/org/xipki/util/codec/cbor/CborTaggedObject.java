// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.cbor;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;

import java.util.Arrays;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class CborTaggedObject implements CborEncodable {

  private final long tag;

  private final Object value;

  public CborTaggedObject(long tag, Object value) {
    this.tag = tag;
    this.value = value;
  }

  public long tag() {
    return tag;
  }

  public Object value() {
    return value;
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeTag(tag);
    unwrappedEncode(encoder);
  }

  @Override
  public void unwrappedEncode(CborEncoder encoder) throws CodecException {
    encoder.writeAnyObject(value);
  }

  @Override
  public int hashCode() {
    int hashCode = (value == null) ? 0
        : (value instanceof byte[]) ? Arrays.hashCode((byte[]) value)
        : value.hashCode();

    return hashCode * 31 + Long.hashCode(tag);
  }

  @Override
  public String toString() {
    String str = "tag " + tag + ": ";
    return (value == null) ? str + "<null>"
        : (value instanceof byte[]) ? str + "h'" + Hex.encode(((byte[]) value))
        : str + value;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;

    if (!(obj instanceof CborTaggedObject)) return false;

    CborTaggedObject b = (CborTaggedObject) obj;
    return tag == b.tag && ((value == null) ? b.value == null
        : (value instanceof byte[] && b.value instanceof byte[])
              ? Arrays.equals((byte[]) value, (byte[]) b.value)
        : value.equals(b.value));
  }

}
