// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.cbor;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;

import java.util.Arrays;

/**
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
    int hashCode;
    if (value == null) {
      hashCode = 0;
    } else if (value instanceof byte[]) {
      hashCode = Arrays.hashCode((byte[]) value);
    } else {
      hashCode = value.hashCode();
    }

    return hashCode * 31 + Long.hashCode(tag);
  }

  @Override
  public String toString() {
    String str = "tag " + tag + ": ";
    if (value == null) {
      return str + "<null>";
    } else if (value instanceof byte[]) {
      return str + "h'" + Hex.encode(((byte[]) value));
    } else {
      return str + value;
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;

    if (!(obj instanceof CborTaggedObject)) return false;

    CborTaggedObject b = (CborTaggedObject) obj;
    if (value == null) {
      return b.value == null;
    } else if (value instanceof byte[]) {
      return Arrays.equals((byte[]) value, (byte[]) b.value);
    } else {
      return value.equals(b.value);
    }
  }

}
