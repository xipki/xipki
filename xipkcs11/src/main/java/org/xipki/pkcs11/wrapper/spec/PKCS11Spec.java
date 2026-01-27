// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper.spec;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11T;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class PKCS11Spec {

  private boolean changeable = true;

  public void setUnchangeable() {
    this.changeable = false;
  }

  protected void assertChangeable() {
    if (!changeable) {
      throw new UnsupportedOperationException(
          "This PKCS11Spec is not changeable");
    }
  }

  protected static void appendElement(
      StringBuilder sb, String indent, String name, Object value) {
    if (value == null) {
      return;
    }

    sb.append("\n").append(indent).append(name).append(": ");
    if (value instanceof String) {
      sb.append((String) value);
    } else if (value instanceof char[]) {
      sb.append(new String((char[]) value));
    } else if (value instanceof byte[]) {
      sb.append(Functions.toHex((byte[]) value));
    } else if (value instanceof PKCS11TemplateSpec) {
      sb.append(((PKCS11TemplateSpec) value).toString(false, indent + "  "));
    } else if (value instanceof PKCS11KeyPairType) {
      sb.append(((PKCS11KeyPairType) value).toString(false, indent + "  "));
    } else {
      if (value instanceof Long) {
        long v = (long) value;
        if ("class".equalsIgnoreCase(name)) {
          sb.append(PKCS11T.ckoCodeToName(v));
        } else {
          sb.append(v);
        }
      } else {
        sb.append(value);
      }
    }
  }

}
