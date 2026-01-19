// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

/**
 * Objects of this class represent an attribute array of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class TemplateAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_VALUE.
   */
  public TemplateAttribute(long type, Template value) {
    super(type, value);
  }

  /**
   * Get the attribute array value of this attribute. Null, is also possible.
   *
   * @return The attribute array value of this attribute or null.
   */
  public Template getValue() {
    return (value == null) ? null : (Template) value;
  }

  public void setValue(Template value) {
    this.value = value;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  protected String getValueString() {
    return (value == null) ? "<NULL_PTR>" : "\n" +
        ((Template) value).toString(false, "    ");
  }

}
