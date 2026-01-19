// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11T;

import java.util.Arrays;

/**
 * Parent class of all CK objects needed to be encoded.
 * @author Lijun Liao (xipki)
 */
public abstract class CkType {

  @Override
  public final String toString() {
    return toString(null, "");
  }

  public abstract String toString(PKCS11Module module, String indent);

  public final String toString(PKCS11Module module) {
    return toString(module, "");
  }

  public String toString(String indent, String name, PKCS11Module module,
                         Object... fieldNameValues) {
    final int n2 = fieldNameValues.length;
    if ((n2 & 1) != 0) {
      throw new IllegalArgumentException(
          "fieldNameValues.length is not even: " + n2);
    }

    final int n = n2 >> 1;
    int maxFieldNameLen = 0;
    for (int i = 0; i < n; i++) {
      Object fn = fieldNameValues[2 * i];
      if (!(fn instanceof String)) {
        throw new IllegalArgumentException("field name is not a String");
      }
      maxFieldNameLen = Math.max(maxFieldNameLen, ((String) fn).length());
    }

    StringBuilder sb = new StringBuilder();
    sb.append(indent).append(name).append(": ");
    for (int i = 0; i < n2; i += 2) {
      String fieldName = (String) fieldNameValues[i];
      Object fieldValue = fieldNameValues[i + 1];
      if (fieldValue instanceof byte[] || fieldValue instanceof char[]) {
        sb.append(ptr2str(maxFieldNameLen, indent, fieldName, fieldValue));
      } else if (fieldValue instanceof Byte) {
        sb.append(val2Str(maxFieldNameLen, indent, fieldName,
            "0x" + Integer.toHexString(0xFF & (byte) fieldValue)));
      } else if (fieldValue instanceof Integer) {
        sb.append(val2Str(maxFieldNameLen, indent, fieldName,
            "0x" + Integer.toHexString((int) fieldValue)));
      } else if (fieldValue instanceof Long) {
        sb.append(val2Str(maxFieldNameLen, indent, fieldName,
            "0x" + Long.toHexString((long) fieldValue)));
      } else if (fieldValue instanceof CkType) {
        sb.append("\n").append(indent).append("  ")
            .append(formatFieldName(maxFieldNameLen, fieldName)).append(": ")
            .append(((CkType) fieldValue).toString(module, indent));
      } else {
        sb.append(val2Str(maxFieldNameLen, indent, fieldName, fieldValue));
      }
    }

    return sb.toString();
  }

  private static String ptr2str(int maxFieldNameLen, String indent,
                                String name, Object value) {
    String prefix = "\n" + indent + "  ";
    if (!name.isEmpty()) {
      prefix += formatFieldName(maxFieldNameLen, name) + ": ";
    }

    if (value == null) {
      return prefix + "<NULL_PTR>";
    } else if (value instanceof byte[]) {
      // -1: the leading '\n'.
      char[] spaceIndent = new char[prefix.length() - 1];
      Arrays.fill(spaceIndent, ' ');
      byte[] bytes = (byte[]) value;
      return prefix + "byte[" + bytes.length + "]\n" +
              Functions.toString(new String(spaceIndent), bytes);
    } else if (value instanceof char[]) {
      return prefix + new String((char[]) value);
    } else {
      return prefix + value;
    }
  }

  private static String val2Str(int maxFieldNameLen, String indent,
                                String name, Object value) {
    String prefix = "\n" + indent + "  ";
    if (!name.isEmpty()) {
      prefix += formatFieldName(maxFieldNameLen, name) + ": ";
    }
    return prefix + value;
  }

  private static String formatFieldName(int maxFieldNameLen, String name) {
    if (name.length() >= maxFieldNameLen) {
      return name;
    }
    char[] prefix = new char[maxFieldNameLen - name.length()];
    Arrays.fill(prefix, ' ');
    return new String(prefix) + name;
  }

  protected static String ckmName(long code, PKCS11Module module) {
    return codeToName(Category.CKM, code, module);
  }

  protected static String ckdName(long code, PKCS11Module module) {
    return codeToName(Category.CKD, code, module);
  }

  protected static String mgfName(long code, PKCS11Module module) {
    return codeToName(Category.CKG_MGF, code, module);
  }

  protected static String ckzName(long code, PKCS11Module module) {
    return codeToName(Category.CKZ, code, module);
  }

  protected static String generatorName(long code, PKCS11Module module) {
    return codeToName(Category.CKG_GENERATOR, code, module);
  }

  protected static String codeToName(
      Category category, long code, PKCS11Module module) {
    String name = PKCS11T.codeToName(category, code);
    if (module != null) {
      long code2 = module.genericToVendorCode(category, code);
      if (code != code2) {
        name += " (native: " + module.codeToName(category, code2) + ")";
      }
    }
    return name;
  }

}
