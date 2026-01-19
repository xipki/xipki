// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.util.codec.asn1.Asn1Util;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Objects of this class represent a byte-array attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class ByteArrayAttribute extends Attribute {

  public ByteArrayAttribute(long type, byte[] value) {
    super(type, value);
  }

  public ByteArrayAttribute(long type, BigInteger value) {
    super(type, value == null ? null
        : Functions.asUnsignedByteArray(value));
  }

  /**
   * Get the byte-array value of this attribute. Null, is also possible.
   *
   * @return The byte-array value of this attribute or null.
   */
  public byte[] getValue() {
    return (byte[]) value;
  }

  public void setValue(byte[] value) {
    this.value = value;
  }

  public BigInteger getBigIntValue() {
    return isNullValue() ? null
        : new BigInteger(1, (byte[]) value);
  }

  /**
   * Get a string representation of this attribute's value.
   *
   * @return A string representation of this attribute's value.
   */
  @Override
  protected String getValueString() {
    if (isNullValue()) {
      return "<NULL_PTR>";
    }

    byte[] bvalue = (byte[]) value;
    String text = "byte[" + bvalue.length + "]\n"
        + Functions.toString("    ", bvalue);

    long type = type();
    if (type == PKCS11T.CKA_EC_PARAMS) {
      String[] curveNames = Functions.getCurveNames(bvalue);
      String curveOid = Asn1Util.decodeOid(bvalue);
      text += " (" + curveOid + ", " + Arrays.toString(curveNames) + ")";
    }

    return text;
  }

}
