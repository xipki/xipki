// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.type.CkVersion;

/**
 * Objects of this class represent a date attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class VersionAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_START_DATE.
   */
  public VersionAttribute(long type, CkVersion value) {
    super(type, value);
  }

  /**
   * Get the date value of this attribute. Null, is also possible.
   *
   * @return The date value of this attribute or null.
   */
  public CkVersion getValue() {
    return isNullValue() ? null : (CkVersion) value;
  }

  public void setValue(CkVersion value) {
    this.value = value;
  }

  @Override
  protected String getValueString() {
    if (isNullValue()) {
      return "<NULL>";
    }

    CkVersion ckVersion = (CkVersion) value;
    return (0xff & ckVersion.major()) + "." + (0xff & ckVersion.minor());
  }

}
