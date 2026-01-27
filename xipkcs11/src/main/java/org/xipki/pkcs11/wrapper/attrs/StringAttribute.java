// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import java.nio.charset.StandardCharsets;

/**
 * Objects of this class represent a char-array attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class StringAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_LABEL.
   */
  public StringAttribute(long type, byte[] value) {
    super(type, value);
  }

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_LABEL.
   */
  public StringAttribute(long type, String value) {
    super(type, value == null ? null : value.getBytes(StandardCharsets.UTF_8));
  }

  public void setValue(String value) {
    this.value = (value == null) ? null
        : value.getBytes(StandardCharsets.UTF_8);
  }

  public void setValue(byte[] value) {
    this.value = value;
  }

  /**
   * Get the string value of this attribute. Null, is also possible.
   *
   * @return The char-array value of this attribute or null.
   */
  public String getValue() {
    return isNullValue() ? null
                         : new String((byte[]) value, StandardCharsets.UTF_8);
  }

  public byte[] getByteArrayValue() {
    return (byte[]) value;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  protected String getValueString() {
    String value = getValue();
    return (value != null) ? value : "<NULL_PTR>";
  }

}
