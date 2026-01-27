// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.PKCS11T;

import java.util.Arrays;

/**
 * Objects of this class represent a mechanism array attribute of a PKCS#11
 * object as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class LongArrayAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_VALUE.
   */
  public LongArrayAttribute(long type, long[] value) {
    super(type, value);
  }

  /**
   * Get the mechanism attribute array value of this attribute as Mechanism[].
   * Null, is also possible.
   *
   * @return The mechanism attribute array value of this attribute or null.
   */
  public long[] getValue() {
    return isNullValue() ? null : (long[]) value;
  }

  public void setValue(long[] value) {
    this.value = value != null && value.length == 0 ? null : value;
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

    long[] value = (long[]) this.value;
    DataType dataType = Attribute.getDataType(type());
    if (dataType == DataType.CkMechanismArray) {
      String[] strs = new String[value.length];
      for (int i = 0; i < value.length; i++) {
        strs[i] = PKCS11T.ckmCodeToName(value[i]);
      }
      return Arrays.toString(strs);
    } else {
      return Arrays.toString(value);
    }
  }

}
