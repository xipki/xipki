// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

/**
 * Objects of this class represent a boolean attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class BooleanAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_PRIVATE.
   */
  public BooleanAttribute(long type, Boolean value) {
    super(type, value);
  }

  /**
   * Get the boolean value of this attribute. Null, is also possible.
   *
   * @return The boolean value of this attribute or null.
   */
  public Boolean getValue() {
    return (Boolean) value;
  }

  public void setValue(Boolean value) {
    this.value = value;
  }

  @Override
  protected String getValueString() {
    return isNullValue() ? "<NULL_PTR>"
        : (boolean) value ? "TRUE" : "FALSE";
  }

}
