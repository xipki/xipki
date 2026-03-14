// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.attr;

import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Attribute;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class XiTemplate implements JsonEncodable {

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
          "mandatory " + PKCS11T.ckaCodeToName(type) + " is not present");
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

  public XiTemplate remove(long attrType, long attrType2, long... extraAttrTypes) {
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

  public static XiTemplate fromCkAttributes(Template template) throws HsmException {
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

  public byte[] encode() {
    return JsonBuilder.toPrettyJson(toCodec()).getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public JsonMap toCodec() {
    JsonMap map = new JsonMap();
    for (XiAttribute attr : attributes) {
      attr.encode(map);
    }
    return map;
  }

  @Override
  public String toString() {
    return attributes.toString();
  }

  public static XiTemplate decode(byte[] encoded) throws HsmException {
    try {
      return decode(JsonParser.parseMap(encoded, false));
    } catch (CodecException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "could not decode Attributes", e);
    }
  }

  public static XiTemplate decode(JsonMap map) throws HsmException {
    try {
      List<XiAttribute> attrs = new ArrayList<>(map.size());
      for (String name : map.getKeys()) {
        long cka = XiAttribute.ckaNameToCode(name);

        XiAttribute attr;
        if (cka == XiAttribute.CKA_XIHSM_CKU) {
          attr = XiAttribute.ofLong(cka, PKCS11T.nonnullNameToCode(
                    Category.CKU, map.getNnString(name)));
        } else if (cka == XiAttribute.CKA_XIHSM_ORIGIN) {
          Origin origin = Origin.valueOf(map.getNnString(name));
          attr = XiAttribute.ofLong(cka, origin.getCode());
        } else {
          Attribute.DataType dataType = XiAttribute.getCkaDataType(cka);
          switch (dataType) {
            case CkBool:
              attr = XiAttribute.ofBool(cka, map.getNnBool(name));
              break;
            case CkLong:
              attr = XiAttribute.ofLong(cka, map.getNnLong(name));
              break;
            case CkMechanism:
              attr = XiAttribute.ofLong(cka,
                      PKCS11T.nonnullNameToCode(Category.CKM, map.getNnString(name)));
              break;
            case CkString:
              attr = XiAttribute.ofChars(cka, map.getNnString(name));
              break;
            case CkDate:
              attr = XiAttribute.ofDate(cka, map.getNnLong(name));
              break;
            case CkLongArray: {
              List<Long> list = map.getNnLongList(name);
              long[] la = new long[list.size()];
              for (int i = 0; i < la.length; i++) {
                la[i] = list.get(i);
              }
              attr = XiAttribute.ofLongArray(cka, la);
              break;
            }
            case CkMechanismArray: {
              List<String> list = map.getNnStringList(name);
              long[] la = new long[list.size()];
              for (int i = 0; i < la.length; i++) {
                la[i] = PKCS11T.nonnullNameToCode(Category.CKM, list.get(i));
              }
              attr = XiAttribute.ofLongArray(cka, la);
              break;
            }
            case CkByteArray:
              attr = XiAttribute.ofByteArray(cka, Hex.decode(map.getNnString(name)));
              break;
            case CkTemplate:
              attr = XiAttribute.ofAttributes(cka, XiTemplate.decode(map.getNnMap(name)));
              break;
            default:
              throw new CodecException("unsupported attribute " + name);
          }
        }

        attrs.add(attr);
      }
      return new XiTemplate(attrs);
    } catch (CodecException | RuntimeException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "could not decode Attributes", e);
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
