// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.attr;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Attribute;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborDecoder;
import org.xipki.util.codec.cbor.ByteArrayCborEncoder;
import org.xipki.util.codec.cbor.CborDecoder;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class XiTemplate {

  private final List<XiAttribute> attributes;

  public XiTemplate(XiAttribute... attrs) {
    int size = attrs == null ? 0 : attrs.length;
    this.attributes = new ArrayList<>(size);
    if (size > 0) {
      for (XiAttribute attr : attrs) {
        if (attr != null) {
          attributes.add(attr);
        }
      }
    }
  }

  public XiTemplate(List<XiAttribute> attrs) {
    int size = attrs == null ? 0 : attrs.size();
    this.attributes = new ArrayList<>(size);
    if (size > 0) {
      for (XiAttribute attr : attrs) {
        if (attr != null) {
          attributes.add(attr);
        }
      }
    }
  }

  public List<XiAttribute> getAttributes() {
    return Collections.unmodifiableList(attributes);
  }

  public XiAttribute add(XiAttribute attr) {
    XiAttribute oldAttr = remove(attr.type());
    attributes.add(attr);
    return oldAttr;
  }

  public int getSize() {
    return attributes.size();
  }

  public long[] getTypes() {
    long[] types = new long[attributes.size()];
    int index = 0;
    for (XiAttribute attr : attributes) {
      types[index++] = attr.type();
    }
    return types;
  }

  public String[] getTextTypes() {
    String[] types = new String[attributes.size()];
    int index = 0;
    for (XiAttribute attr : attributes) {
      types[index++] = PKCS11T.ckaCodeToName(attr.type());
    }
    return types;
  }

  public XiAttribute getNonNullAttribute(long type) throws HsmException {
    XiAttribute attr = getAttribute(type);
    if (attr == null) {
      throw new HsmException(PKCS11T.CKR_TEMPLATE_INCOMPLETE,
          "Missing required attribute " + PKCS11T.ckaCodeToName(type));
    }
    return attr;
  }

  public XiAttribute getAttribute(long type) {
    for (XiAttribute attr : attributes) {
      if (type == attr.type()) {
        return attr;
      }
    }
    return null;
  }

  public Boolean getBool(long type) {
    XiAttribute attr = getAttribute(type);
    return (attr == null) ? null : attr.getBoolValue();
  }

  public Long getLong(long type) {
    XiAttribute attr = getAttribute(type);
    return (attr == null) ? null : attr.getLongValue();
  }

  public long getNonNullLong(long type) throws HsmException {
    Long ret = getLong(type);
    if (ret == null) {
      throw new HsmException(PKCS11T.CKR_TEMPLATE_INCOMPLETE,
          "mandatory " + PKCS11T.ckaCodeToName(type) +
              " is not present");
    }
    return ret;
  }

  public byte[] getByteArray(long type) {
    XiAttribute attr = getAttribute(type);
    return (attr == null) ? null : attr.getByteArrayValue();
  }

  public Template toCkAttributeArray() {
    Template ret = new Template();
    for (XiAttribute attr : attributes) {
      ret.attr(attr.toCkAttribute());
    }
    return ret;
  }

  public void removeAttributes(long... attrTypes) {
    if (attrTypes != null) {
      for (long attrType : attrTypes) {
        remove(attrType);
      }
    }
  }

  public XiTemplate remove(long attrType, long attrType2,
                           long... extraAttrTypes) {
    int size = 2 + (extraAttrTypes == null ? 0 : extraAttrTypes.length);
    List<Long> types = new ArrayList<>(size);
    types.add(attrType);
    types.add(attrType2);
    if (extraAttrTypes != null) {
      for (long t : extraAttrTypes) {
        types.add(t);
      }
    }

    List<XiAttribute> list = new ArrayList<>(size);
    for (long v : types) {
      XiAttribute attr = remove(v);
      if (attr != null) {
        list.add(attr);
      }
    }

    return new XiTemplate(list);
  }

  public XiAttribute remove(long attrType) {
    XiAttribute attr = null;
    for (XiAttribute i : attributes) {
      if (attrType == i.type()) {
        attr = i;
        break;
      }
    }

    if (attr != null) {
      attributes.remove(attr);
    }

    return attr;
  }

  public XiAttribute removeNonNull(long type) throws HsmException {
    XiAttribute attr = remove(type);
    if (attr == null) {
      throw new HsmException(PKCS11T.CKR_TEMPLATE_INCOMPLETE,
          "Missing required attribute " + PKCS11T.ckaCodeToName(type));
    }
    return attr;
  }

  public byte[] removeByteArray(long type) {
    XiAttribute attr = remove(type);
    return attr == null ? null : attr.getByteArrayValue();
  }

  public byte[] removeNonNullByteArray(long type) throws HsmException {
    return removeNonNull(type).getByteArrayValue();
  }

  public BigInteger removeNonNullBigInt(long type) throws HsmException {
    return removeNonNull(type).getBigIntValue();
  }

  public String removeChars(long type) {
    XiAttribute attr = remove(type);
    return attr == null ? null : attr.getCharsValue();
  }

  public Boolean removeBool(long type) {
    XiAttribute attr = remove(type);
    return attr == null ? null : attr.getBoolValue();
  }

  public boolean removeBool(long type, boolean dfltValue) {
    XiAttribute attr = remove(type);
    return attr == null ? dfltValue : attr.getBoolValue();
  }

  public Long removeLong(long type) {
    XiAttribute attr = remove(type);
    return attr == null ? null : attr.getLongValue();
  }

  public long removeNonNullLong(long type) throws HsmException {
    return removeNonNull(type).getLongValue();
  }

  public XiTemplate removeTemplate(long type) {
    XiAttribute attr = remove(type);
    return attr == null ? null : attr.getTemplateValue();
  }

  public Integer removeInt(long type) throws HsmException {
    XiAttribute attr = remove(type);
    return attr == null ? null : attr.getIntValue();
  }

  public int removeNonNullInt(long type) throws HsmException {
    return removeNonNull(type).getIntValue();
  }

  public long[] removeLongArray(long type) {
    XiAttribute attr = remove(type);
    return attr == null ? null : attr.getLongArrayValue();
  }

  public XiDate removeDate(long type) {
    XiAttribute attr = remove(type);
    return attr == null ? null : attr.getDateValue();
  }

  public static XiTemplate fromCkAttributes(Template template)
      throws HsmException {
    if (template == null) {
      return new XiTemplate();
    }

    List<XiAttribute> list = new ArrayList<>(template.getSize());
    for (Attribute ckAttr : template.attributes()) {
      if (ckAttr != null) {
        list.add(XiAttribute.fromCkAttribute(ckAttr));
      }
    }

    return new XiTemplate(list);
  }

  public byte[] encode() throws HsmException {
    try {
      ByteArrayCborEncoder encoder = new ByteArrayCborEncoder();
      encoder.writeArrayStart(attributes.size());
      for (XiAttribute attr : attributes) {
        attr.encode(encoder);
      }
      return encoder.toByteArray();
    } catch (CodecException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "could not encode Attributes", e);
    }
  }

  @Override
  public String toString() {
    return attributes.toString();
  }

  public static XiTemplate decode(byte[] encoded) throws HsmException {
    try {
      CborDecoder decoder = new ByteArrayCborDecoder(encoded);
      int size = decoder.readArrayLength();
      List<XiAttribute> attrs = new ArrayList<>(size);
      for (int i = 0; i < size; i++) {
        attrs.add(XiAttribute.decode(decoder));
      }
      return new XiTemplate(attrs);
    } catch (CodecException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "could not decode Attributes", e);
    }
  }

  public boolean match(XiTemplate criteria) {
    for (XiAttribute cattr : criteria.attributes) {
      XiAttribute attr = getAttribute(cattr.type());
      if (!cattr.equals(attr)) {
        return false;
      }
    }
    return true;
  }

}
