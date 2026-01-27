// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.type.CkDate;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.io.InputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.xipki.pkcs11.wrapper.PKCS11T.ckaCodeToName;
import static org.xipki.pkcs11.wrapper.PKCS11T.ckaNameToCode;

/**
 * <pre>
 * typedef struct CK_ATTRIBUTE {
 *   CK_ATTRIBUTE_TYPE type;
 *   CK_VOID_PTR       pValue;
 *   CK_ULONG          ulValueLen;  // in bytes
 * }CK_ATTRIBUTE;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public abstract class Attribute {

  public enum DataType {
    CkTemplate,
    CkBool,
    CkByteArray,
    CkString,
    CkDate,
    CkLong,
    CkLongArray,
    CkMechanism,
    CkMechanismArray,
    CkVersion
  }

  private static final Map<Long, DataType> dataTypes;

  protected final long type;

  /**
   * True, if this attribute is sensitive.
   */
  protected boolean sensitive;

  protected Object value;

  static {
    dataTypes = new HashMap<>(130);
    String propFile = "org/xipki/pkcs11/wrapper/type-cka.json";
    try (InputStream is = Attribute.class.getClassLoader()
        .getResourceAsStream(propFile)) {
      JsonMap json = JsonParser.parseMap(is, true);
      Map<String, String> map = json.toStringMap();
      for (Map.Entry<String, String> v : map.entrySet()) {
        String name = v.getKey();
        Long code = ckaNameToCode(name);
        if (code == null) {
          throw new IllegalStateException("unknown CKA: " + name);
        }

        if (dataTypes.containsKey(code)) {
          throw new IllegalStateException(
              "duplicated definition of CKA: " + name);
        }

        String type = v.getValue();
        dataTypes.put(code, getDataType(type));
      }
    } catch (Throwable t) {
      throw new IllegalStateException("error reading properties file "
          + propFile + ": " + t.getMessage());
    }

    if (dataTypes.isEmpty()) {
      throw new IllegalStateException(
          "no code to name map is defined properties file " + propFile);
    }
  }

  public Object value() {
    return value;
  }

  private static DataType getDataType(String attrType) {
    attrType = attrType.toUpperCase(Locale.US);
    switch (attrType) {
      case "TEMPLATE":
        return DataType.CkTemplate;
      case "BOOL":
      case "BOOLEAN":
        return DataType.CkBool;
      case "BYTEARRAY":
        return DataType.CkByteArray;
      case "DATE":
        return DataType.CkDate;
      case "LONG":
        return DataType.CkLong;
      case "LONGARRAY":
        return DataType.CkLongArray;
      case "MECHANISM":
        return DataType.CkMechanism;
      case "MECHANISMARRAY":
        return DataType.CkMechanismArray;
      case "STRING":
        return DataType.CkString;
      case "VERSION":
        return DataType.CkVersion;
      default:
        throw new IllegalStateException(
            "unknown attribute type '" + attrType + "'");
    }
  }

  /**
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_PRIVATE.
   */
  public Attribute(long type, Object value) {
    this.value = value;
    this.type = type;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  protected abstract String getValueString();

  public Attribute sensitive(boolean sensitive) {
    this.sensitive = sensitive;
    return this;
  }

  /**
   * @param type
   * @return
   */
  public static Attribute getInstance(long type) {
    return getInstance0(type);
  }

  /**
   * @param type
   * @return
   */
  static Attribute getInstance0(long type) {
    DataType attrType = getDataType(type);
    switch (attrType) {
      case CkBool:
        return new BooleanAttribute(type, null);
      case CkString:
        return new StringAttribute(type, (byte[]) null);
      case CkDate:
        return new DateAttribute(type, (CkDate) null);
      case CkLong:
      case CkMechanism:
        return new LongAttribute(type, null);
      case CkLongArray:
      case CkMechanismArray:
        return new LongArrayAttribute(type, null);
      case CkTemplate:
        return new TemplateAttribute(type, null);
      case CkVersion:
        return new VersionAttribute(type, null);
      default:
        return new ByteArrayAttribute(type, (byte[]) null);
    }
  }

  public static Attribute getInstance(long type, Object value) {
    DataType attrType = getDataType(type);
    switch (attrType) {
      case CkBool:
        return new BooleanAttribute(type, (Boolean) value);
      case CkString:
        return (value == null || value instanceof byte[])
            ? new StringAttribute(type, (byte[]) value)
            : new StringAttribute(type, (String) value);
      case CkDate:
        return new DateAttribute(type, (Instant) value);
      case CkLong:
      case CkMechanism:
        return (value == null || value instanceof Long)
            ? new LongAttribute(type, (Long) value)
            : new LongAttribute(type, (long) (int) value);
      case CkLongArray:
      case CkMechanismArray:
        return new LongArrayAttribute(type, (long[]) value);
      case CkTemplate:
        return new TemplateAttribute(type, (Template) value);
      case CkVersion:
        return new VersionAttribute(type, (CkVersion) value);
      default:
        return (value == null || value instanceof byte[])
            ? new ByteArrayAttribute(type, (byte[]) value)
            : new ByteArrayAttribute(type, (BigInteger) value);
    }
  }

  public static DataType getDataType(long type) {
    DataType attrType = dataTypes.get(type);
    return attrType == null ? DataType.CkByteArray : attrType;
  }

  /**
   * Check, if this attribute is sensitive in the associated object.
   *
   * @return True, if this attribute is sensitive in the associated object.
   */
  public boolean isSensitive() {
    return sensitive;
  }

  public long type() {
    return type;
  }

  /**
   * Get a string representation of this attribute. If the attribute is not
   * present or if it is sensitive, the output of this method shows just a
   * message telling this. This string does not contain the attribute's type
   * name.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  public String toString() {
    return toString(true, 0, "");
  }

  /**
   * Get a string representation of this attribute. If the attribute is not
   * present or if it is sensitive, the output of this method shows just
   * a message telling this.
   *
   * @param withName
   *          If true, the string contains the attribute type name and the
   *          value. If false, it just contains the value.
   * @param minNameLen Minimal length of the name.
   * @param indent The indent.
   * @return A string representation of this attribute.
   */
  public String toString(boolean withName, int minNameLen, String indent) {
    StringBuilder sb = new StringBuilder(Math.max(15, minNameLen) + 20)
        .append(indent);

    if (withName) {
      String name = ckaCodeToName(type);
      sb.append(name).append(": ");
      if (name.length() < minNameLen) {
        char[] padding = new char[minNameLen - name.length()];
        Arrays.fill(padding, ' ');
        sb.append(padding);
      }
    }

    String valueString;
    if (value != null) {
      try {
        valueString = getValueString();
      } catch (RuntimeException e) {
        valueString = "<ERROR toString()>";
      }
    } else {
      valueString = sensitive ? "<Value is sensitive>"
                              : "<Attribute not present>";
    }

    return sb.append(valueString).toString();
  }

  public boolean isNullValue() {
    return value == null;
  }

}
