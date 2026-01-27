// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.attr;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
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
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;
import org.xipki.util.codec.cbor.CborType;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * @author Lijun Liao (xipki)
 */
public class XiAttribute {

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
          "unsupported value type " +
          (value == null ? "NULL" : value.getClass().getName()));
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
      return ofDate(type, XiDate.fromCkDate(
                            ((DateAttribute) attr).getCkDateValue()));
    } else if (attr instanceof TemplateAttribute) {
      return ofAttributes(type,
          XiTemplate.fromCkAttributes(((TemplateAttribute) attr).getValue()));
    } else {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_TYPE_INVALID,
          "unsupported attribute " + attr.getClass().getName());
    }
  }

  public Attribute toCkAttribute() {
    return (boolValue != null)     ? new BooleanAttribute(type, boolValue)
        : (longValue      != null) ? new LongAttribute(type, longValue)
        : (charsValue     != null) ? new StringAttribute(type, charsValue)
        : (byteArrayValue != null)
            ? new ByteArrayAttribute(type, byteArrayValue)
        : (longArrayValue != null)
            ? new LongArrayAttribute(type, longArrayValue)
        : (templateValue != null)
            ? new TemplateAttribute(type, templateValue.toCkAttributeArray())
        : new DateAttribute(type, dateValue.toCkDate());
  }

  public long getType() {
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
    return byteArrayValue == null ? null
        : new BigInteger(1, byteArrayValue);
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
      } else if (type == PKCS11T.CKA_KEY_GEN_MECHANISM
          || type == PKCS11T.CKA_NAME_HASH_ALGORITHM) {
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
      sb.append(Hex.toHexString(byteArrayValue));
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
    } else {
      sb.append("NULL");
    }
    return sb.toString();
  }

  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(2);
    encoder.writeLong(type);
    if (boolValue != null) {
      encoder.writeBoolean(boolValue);
    } else if (longValue != null) {
      encoder.writeLong(longValue);
    } else if (charsValue != null) {
      encoder.writeTextString(charsValue);
    } else if (dateValue != null) {
      encoder.writeTag(1);
      encoder.writeLong(dateValue.getDate());
    } else if (longArrayValue != null) {
      encoder.writeLongs(longArrayValue);
    } else { // if (byteArrayValue != null)
      encoder.writeByteString(byteArrayValue);
    }
  }

  public static XiAttribute decode(CborDecoder decoder) throws CodecException {
    int arrayLen = decoder.readArrayLength();
    if (arrayLen != 2) {
      throw new CodecException("arrayLen != 2: " + arrayLen);
    }

    long type = decoder.readLong();
    CborType cborType = decoder.peekType();

    if (cborType.isBooleanType()) {
      return XiAttribute.ofBool(type, decoder.readBoolean());
    } else if (cborType.isInt()) {
      return XiAttribute.ofLong(type, decoder.readLong());
    } else if (cborType.isTextString()) {
      return XiAttribute.ofChars(type, decoder.readTextString());
    } else if (cborType.isByteString()) {
      return XiAttribute.ofByteArray(type, decoder.readByteString());
    } else if (cborType.isArray()) {
      int size = decoder.readArrayLength();
      long[] values = new long[size];
      for (int i = 0; i < size; i++) {
        values[i] = decoder.readLong();
      }
      return XiAttribute.ofLongArray(type, values);
    } else if (cborType.isTag()) {
      long tag = decoder.readTag();
      if (tag == 1) {
        return XiAttribute.ofDate(type, decoder.readLong());
      }
    }

    throw new CodecException("unknown cbor type for the attribute value " +
        cborType);
  }

}
