// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.attr;

import org.bouncycastle.util.BigIntegers;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Attribute;
import org.xipki.pkcs11.wrapper.attrs.BooleanAttribute;
import org.xipki.pkcs11.wrapper.attrs.ByteArrayAttribute;
import org.xipki.pkcs11.wrapper.attrs.DateAttribute;
import org.xipki.pkcs11.wrapper.attrs.LongArrayAttribute;
import org.xipki.pkcs11.wrapper.attrs.LongAttribute;
import org.xipki.pkcs11.wrapper.attrs.StringAttribute;
import org.xipki.pkcs11.wrapper.attrs.TemplateAttribute;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class XiAttribute {

  public static final long CKA_XIHSM_CKU = 0x1_FFFF_FFFFL;

  public static final long CKA_XIHSM_ORIGIN = 0x1_FFFF_FFFEL;

  private final long type;

  private Long longValue;

  private Boolean boolValue;

  private String charsValue;

  private byte[] byteArrayValue;

  private long[] longArrayValue;

  private XiDate dateValue;

  private XiTemplate templateValue;

  public XiAttribute(long type) {
    this.type = type;
  }

  public static Attribute.DataType getCkaDataType(long cka) {
    if (cka == CKA_XIHSM_CKU) {
      return Attribute.DataType.CkLong;
    } else if (cka == CKA_XIHSM_ORIGIN) {
      return Attribute.DataType.CkLong;
    }

    return Attribute.getDataType(cka);
  }

  public static String ckaCodeToName(long cka) {
    if (cka == CKA_XIHSM_CKU) {
      return "CKA_XIHSM_CKU";
    } else if (cka == CKA_XIHSM_ORIGIN) {
      return "CKA_XIHSM_ORIGIN";
    } else {
      return PKCS11T.ckaCodeToName(cka);
    }
  }

  public static long ckaNameToCode(String ckaName) {
    if (ckaName.equals("CKA_XIHSM_CKU")) {
      return CKA_XIHSM_CKU;
    } else if (ckaName.equals("CKA_XIHSM_ORIGIN")) {
      return CKA_XIHSM_ORIGIN;
    } else {
      return PKCS11T.nonnullNameToCode(Category.CKA, ckaName);
    }
  }

  public static XiAttribute ofObject(long type, Object value)
      throws HsmException {
    if (value instanceof Long) {
      return ofLong(type, (Long) value);
    } else if (value instanceof Integer) {
        return ofLong(type, (Integer) value);
    } else if (value instanceof Boolean) {
      return ofBool(type, (Boolean) value);
    } else if (value instanceof String) {
      return ofChars(type, (String) value);
    } else if (value instanceof byte[]) {
      return ofByteArray(type, (byte[]) value);
    } else if (value instanceof BigInteger) {
      return ofByteArray(type, (BigInteger) value);
    } else if (value instanceof XiDate) {
      return ofDate(type, (XiDate) value);
    } else if (value instanceof long[]) {
      return ofLongArray(type, (long[]) value);
    } else if (value instanceof XiTemplate) {
      return ofAttributes(type, (XiTemplate) value);
    } else {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "unsupported value type " + (value == null ? "NULL" : value.getClass().getName()));
    }
  }

  public static XiAttribute ofLong(long type, long value) {
    XiAttribute attr = new XiAttribute(type);
    attr.longValue = value;
    return attr;
  }

  public static XiAttribute ofLong(long type, int value) {
    XiAttribute attr = new XiAttribute(type);
    attr.longValue = (long) value;
    return attr;
  }

  public static XiAttribute ofLongArray(long type, long[] value) {
    XiAttribute attr = new XiAttribute(type);
    attr.longArrayValue = value;
    return attr;
  }
  public static XiAttribute ofBool(long type, Boolean value) {
    XiAttribute attr = new XiAttribute(type);
    attr.boolValue = value;
    return attr;
  }

  public static XiAttribute ofChars(long type, String value) {
    XiAttribute attr = new XiAttribute(type);
    attr.charsValue = value;
    return attr;
  }

  public static XiAttribute ofByteArray(long type, byte[] value) {
    XiAttribute attr = new XiAttribute(type);
    attr.byteArrayValue = value;
    return attr;
  }

  public static XiAttribute ofByteArray(long type, BigInteger value) {
    XiAttribute attr = new XiAttribute(type);
    attr.byteArrayValue = BigIntegers.asUnsignedByteArray(value);
    return attr;
  }

  public static XiAttribute ofDate(long type, long value) {
    return ofDate(type, new XiDate(value));
  }

  public static XiAttribute ofDate(long type, XiDate value) {
    XiAttribute attr = new XiAttribute(type);
    attr.dateValue = value;
    return attr;
  }

  public static XiAttribute ofAttributes(long type, XiTemplate value) {
    XiAttribute attr = new XiAttribute(type);
    attr.templateValue = value;
    return attr;
  }

  public static XiAttribute fromCkAttribute(Attribute attr)
      throws HsmException {
    long type = attr.type();

    if (attr instanceof BooleanAttribute) {
      return ofBool(type, ((BooleanAttribute) attr).getValue());
    } else if (attr instanceof LongAttribute) {
      return ofLong(type, ((LongAttribute) attr).getValue());
    } else if (attr instanceof StringAttribute) {
      return ofChars(type, ((StringAttribute) attr).getValue());
    } else if (attr instanceof ByteArrayAttribute) {
      return ofByteArray(type, ((ByteArrayAttribute) attr).getValue());
    } else if (attr instanceof LongArrayAttribute) {
      return ofLongArray(type, ((LongArrayAttribute) attr).getValue());
    } else if (attr instanceof DateAttribute) {
      return ofDate(type, XiDate.fromCkDate(((DateAttribute) attr).getCkDateValue()));
    } else if (attr instanceof TemplateAttribute) {
      return ofAttributes(type, XiTemplate.fromCkAttributes(((TemplateAttribute) attr).getValue()));
    } else {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_TYPE_INVALID,
          "unsupported attribute " + attr.getClass().getName());
    }
  }

  public Attribute toCkAttribute() {
    return (boolValue != null)     ? new BooleanAttribute(type, boolValue)
        : (longValue      != null) ? new LongAttribute(type, longValue)
        : (charsValue     != null) ? new StringAttribute(type, charsValue)
        : (byteArrayValue != null) ? new ByteArrayAttribute(type, byteArrayValue)
        : (longArrayValue != null) ? new LongArrayAttribute(type, longArrayValue)
        : (templateValue != null)  ? new TemplateAttribute(type, templateValue.toCkAttributeArray())
        : new DateAttribute(type, dateValue.toCkDate());
  }

  public long type() {
    return type;
  }

  public Long getLongValue() {
    return longValue;
  }

  public long[] getLongArrayValue() {
    return longArrayValue;
  }

  public Integer getIntValue() throws HsmException {
    if (longValue == null) {
      return null;
    }

    if (longValue > Integer.MAX_VALUE || longValue < Integer.MIN_VALUE) {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "The value is not an int32: " + Long.toHexString(longValue));
    }
    return (int) (long) longValue;
  }

  public Boolean getBoolValue() {
    return boolValue;
  }

  public String getCharsValue() {
    return charsValue;
  }

  public byte[] getByteArrayValue() {
    return byteArrayValue;
  }

  public BigInteger getBigIntValue() {
    return byteArrayValue == null ? null : new BigInteger(1, byteArrayValue);
  }

  public XiDate getDateValue() {
    return dateValue;
  }

  public XiTemplate getTemplateValue() {
    return templateValue;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;

    if (!(obj instanceof XiAttribute)) return false;

    XiAttribute b = (XiAttribute) obj;
    boolean bo = type == b.type
        && Objects.equals(boolValue,  b.boolValue)
        && Objects.equals(longValue,  b.longValue)
        && Objects.equals(charsValue, b.charsValue)
        && Objects.equals(dateValue,  b.dateValue);

    if (bo) {
      bo = (byteArrayValue == null) ? b.byteArrayValue == null
          : Arrays.equals(byteArrayValue, b.byteArrayValue);
    }

    return bo;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(PKCS11T.ckaCodeToName(type)).append(": ");
    if (boolValue != null) {
      sb.append(boolValue);
    } else if (longValue != null) {
      sb.append(longValue);

      String text;
      if (type == PKCS11T.CKA_CLASS) {
        text = PKCS11T.ckoCodeToName(longValue);
      } else if (type == PKCS11T.CKA_KEY_TYPE) {
        text = PKCS11T.ckkCodeToName(longValue);
      } else if (type == PKCS11T.CKA_KEY_GEN_MECHANISM || type == PKCS11T.CKA_NAME_HASH_ALGORITHM) {
        text = PKCS11T.ckmCodeToName(longValue);
      } else {
        text = null;
      }

      if (text != null) {
        sb.append(" (").append(text).append(")");
      }
    } else if (charsValue != null) {
      sb.append(charsValue);
    } else if (byteArrayValue != null) {
      sb.append(Hex.encode(byteArrayValue));
    } else if (dateValue != null) {
      sb.append(dateValue.getDate());
    } else if (longArrayValue != null) {
      if (type == PKCS11T.CKA_ALLOWED_MECHANISMS) {
        List<String> texts = new ArrayList<>(longArrayValue.length);
        for (long code : longArrayValue) {
          texts.add(PKCS11T.ckmCodeToName(code));
        }
        sb.append(texts);
      } else {
        sb.append(Arrays.toString(longArrayValue));
      }
    } else if (templateValue != null) {
      sb.append(templateValue);
    } else {
      sb.append("NULL");
    }
    return sb.toString();
  }

  public void encode(JsonMap encoder) {
    String name = ckaCodeToName(type);
    Attribute.DataType dataType = getCkaDataType(type);

    if (boolValue != null) {
      encoder.put(name, boolValue);
    } else if (longValue != null) {
      if (type == CKA_XIHSM_CKU) {
        encoder.put(name, PKCS11T.ckuCodeToName(longValue));
      } else if (type == CKA_XIHSM_ORIGIN) {
        encoder.put(name, Origin.ofCode(longValue).name());
      } else if (dataType == Attribute.DataType.CkMechanism) {
        encoder.put(name, PKCS11T.ckmCodeToName(longValue));
      } else {
        encoder.put(name, longValue);
      }
    } else if (charsValue != null) {
      encoder.put(name, charsValue);
    } else if (dateValue != null) {
      encoder.put(name, dateValue.getDate());
    } else if (longArrayValue != null && longArrayValue.length > 0) {
      JsonList list = new JsonList();
      if (dataType == Attribute.DataType.CkMechanismArray) {
        for (long v : longArrayValue) {
          list.add(PKCS11T.ckmCodeToName(v));
        }
      } else {
        for (long v : longArrayValue) {
          list.add(v);
        }
      }

      encoder.put(name, list);
    } else if (templateValue != null) {
      encoder.put(name, templateValue.toCodec());
    } else { // if (byteArrayValue != null)
      encoder.put(name, Hex.encode(byteArrayValue));
    }
  }

}
