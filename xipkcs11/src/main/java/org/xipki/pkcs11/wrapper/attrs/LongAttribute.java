// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;

/**
 * Objects of this class represent a long attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class LongAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_VALUE_LEN.
   */
  public LongAttribute(long type, Long value) {
    super(type, value);
  }

  /**
   * Get the long value of this attribute. Null, is also possible.
   *
   * @return The long value of this attribute or null.
   */
  public Long getValue() {
    return (Long) value;
  }

  public void setValue(long value) {
    this.value = value;
  }

  /**
   * Get the int value of this attribute. Null, is also possible.
   *
   * @return The int value of this attribute or null.
   */
  public Integer getIntValue() {
    return value == null ? null : ((Long) value).intValue();
  }

  @Override
  protected String getValueString() {
    if (isNullValue()) {
      return "<NULL_PTR>";
    }

    long value = getValue();
    if (type == PKCS11T.CKA_CLASS) {
      return PKCS11T.ckoCodeToName(value);
    } else if (type == PKCS11T.CKA_KEY_TYPE) {
      return PKCS11T.ckkCodeToName(value);
    } else if (type == PKCS11T.CKA_CERTIFICATE_TYPE) {
      return PKCS11T.codeToName(Category.CKC, value);
    } else if (type == PKCS11T.CKA_HW_FEATURE_TYPE) {
      return PKCS11T.codeToName(Category.CKH, value);
    } else {
      DataType dataType = Attribute.getDataType(type);
      if (dataType == DataType.CkMechanism) {
        return PKCS11T.ckmCodeToName(value);
      }
    }

    return Long.toString(value);
  }

}
