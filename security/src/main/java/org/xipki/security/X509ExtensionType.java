/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.InvalidConfException;
import org.xipki.util.StringUtil;
import org.xipki.util.ValidatableConf;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * Configuration of an X.509 extension.
 *
 * @author Lijun Liao
 */

public class X509ExtensionType extends ValidatableConf {

  public static class ExtensionsType extends ValidatableConf {

    private List<X509ExtensionType> extensions;

    public List<X509ExtensionType> getExtensions() {
      return extensions;
    }

    public void setExtensions(List<X509ExtensionType> extensions) {
      this.extensions = extensions;
    }

    @Override
    public void validate() throws InvalidConfException {
      for (X509ExtensionType m : extensions) {
        m.validate();
      }
    }

  }

  private DescribableOid type;

  private ConstantExtnValue constant;

  public DescribableOid getType() {
    return type;
  }

  public void setType(DescribableOid type) {
    this.type = type;
  }

  public ConstantExtnValue getConstant() {
    return constant;
  }

  public void setConstant(ConstantExtnValue constant) {
    this.constant = constant;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(type, "type");
    notNull(constant, "constant");
    validate(type);
    validate(constant);
  }

  public static class DescribableOid extends ValidatableConf {

    @JSONField(ordinal = 1)
    private String oid;

    @JSONField(ordinal = 2)
    private String description;

    public String getOid() {
      return oid;
    }

    public void setOid(String oid) {
      this.oid = oid;
    }

    public String getDescription() {
      return description;
    }

    public void setDescription(String description) {
      this.description = description;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(oid, "oid");
    }
  }

  public static class ConstantExtnValue extends ValidatableConf {

    @JSONField(ordinal = 1)
    private FieldType type;

    @JSONField(ordinal = 2)
    private String description;

    @JSONField(ordinal = 3)
    private Tag tag;

    @JSONField(ordinal = 4)
    private String value;

    @JSONField(ordinal = 5)
    private List<ConstantExtnValue> listValue;

    public String getDescription() {
      return description;
    }

    public void setDescription(String description) {
      this.description = description;
    }

    @JSONField(name = "type")
    public String getTypeText() {
      return type.getText();
    }

    // for the JSON deserializer
    @SuppressWarnings("unused")
    private ConstantExtnValue() {
    }

    public ConstantExtnValue(FieldType type) {
      this.type = Args.notNull(type, "type");
    }

    @JSONField(name = "type")
    public void setTypeText(String text) {
      if (text == null) {
        this.type = null;
      } else {
        this.type = null;
        for (FieldType m : FieldType.values()) {
          if (m.name().equalsIgnoreCase(text) || m.getText().equalsIgnoreCase(text)) {
            this.type = m;
          }
        }

        if (type == null) {
          throw new IllegalArgumentException("invalid type " + type);
        }
      }
    }

    public Tag getTag() {
      return tag;
    }

    public void setTag(Tag tag) {
      this.tag = tag;
    }

    public FieldType type() {
      return type;
    }

    public String getValue() {
      return value;
    }

    public void setValue(String value) {
      this.value = value;
    }

    public List<ConstantExtnValue> getListValue() {
      return listValue;
    }

    public void setListValue(List<ConstantExtnValue> listValue) {
      this.listValue = listValue;
    }

    // CHECKSTYLE:SKIP
    public ASN1Encodable toASN1Encodable() throws InvalidConfException {
      ASN1Encodable rv;

      switch (type) {
        case BIT_STRING:
          rv = new DERBitString(Base64.decode(value));
          break;
        case BOOLEAN:
          rv = ASN1Boolean.getInstance(Boolean.parseBoolean(value));
          break;
        case BMPString:
          rv = new DERBMPString(value);
          break;
        case IA5String:
          rv = new DERIA5String(value);
          break;
        case INTEGER:
        case ENUMERATED:
          BigInteger bi = StringUtil.startsWithIgnoreCase(value, "0x")
              ? new BigInteger(value.substring(2), 16) : new BigInteger(value);
          rv  = type == FieldType.INTEGER ? new ASN1Integer(bi) : new ASN1Enumerated(bi);
          break;
        case GeneralizedTime:
          rv = new ASN1GeneralizedTime(value);
          break;
        case UTCTime:
          rv = new ASN1UTCTime(value);
          break;
        case NULL:
          rv = DERNull.INSTANCE;
          break;
        case OCTET_STRING:
          rv = new DEROctetString(Base64.decode(value));
          break;
        case OID:
          rv = new ASN1ObjectIdentifier(value);
          break;
        case PrintableString:
          rv = new DERPrintableString(value);
          break;
        case RAW:
          ASN1StreamParser parser = new ASN1StreamParser(Base64.decode(value));
          try {
            rv = parser.readObject();
          } catch (IOException ex) {
            throw new InvalidConfException("could not parse the constant extension value", ex);
          }
          break;
        case TeletexString:
          rv = new DERT61String(value);
          break;
        case UTF8String:
          rv = new DERUTF8String(value);
          break;
        case Name:
          rv = X509Util.reverse(new X500Name(value));
          break;
        case SEQUENCE:
        case SEQUENCE_OF:
        case SET:
        case SET_OF:
          ASN1EncodableVector v = new ASN1EncodableVector();
          for (ConstantExtnValue m : listValue) {
            v.add(m.toASN1Encodable());
          }

          rv = (FieldType.SEQUENCE == type || FieldType.SEQUENCE_OF == type)
                ? new DERSequence(v) : new DERSet(v);
          break;
        default:
          throw new RuntimeException("should not reach here, unknown type " + type);
      }

      return tag == null ? rv : new DERTaggedObject(tag.isExplicit(), tag.getValue(), rv);
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(type, "type");
      validate(tag);
      if (FieldType.NULL == type) {
        if (value != null) {
          throw new InvalidConfException("value may not be non-null");
        }
      } else if (FieldType.SEQUENCE == type || FieldType.SET == type
          || FieldType.SEQUENCE_OF == type || FieldType.SET_OF == type) {
        if (value != null) {
          throw new InvalidConfException("value may not be non-null");
        }

        notEmpty(listValue, "values");
        for (ConstantExtnValue m : listValue) {
          m.validate();
        }

        if (listValue.size() > 1) {
          // make sure that no duplication of tag is specified
          Set<Integer> tags = new HashSet<>();
          for (ConstantExtnValue m : listValue) {
            if (m.getTag() != null) {
              if (!tags.add(m.getTag().getValue())) {
                throw new InvalidConfException(
                    "duplicated definition of tag " + m.getTag().getValue());
              }
            }
          }
        }
      } else {
        if (listValue != null) {
          throw new InvalidConfException("values may not be non-null");
        }
        notNull(value, "value");
      }
    }

  }

  public static enum FieldType {
    TeletexString("TeletexString"),
    PrintableString("PrintableString"),
    UTF8String("UTF8String"),
    BMPString("BMPString"),
    IA5String("IA5String"),
    NULL("NULL"),
    INTEGER("INTEGER"),
    ENUMERATED("ENUMERATED"),
    GeneralizedTime("GeneralizedTime"),
    UTCTime("UTCTime"),
    BOOLEAN("BOOLEAN"),
    BIT_STRING("BIT STRING"),
    OCTET_STRING("OCTET STRING"),
    OID("OID"),
    Name("Name"),
    SEQUENCE("SEQUENCE"),
    SEQUENCE_OF("SEQUENCE OF"),
    SET("SET"),
    SET_OF("SET OF"),
    RAW("RAW");

    private final String text;

    private FieldType(String text) {
      this.text = text;
    }

    public String getText() {
      return text;
    }
  }

  public static class Tag extends ValidatableConf {

    private int value;

    private boolean explicit;

    // for deserializer
    @SuppressWarnings("unused")
    private Tag() {
    }

    public Tag(int value, boolean explicit) {
      this.value = value;
      this.explicit = explicit;
    }

    public int getValue() {
      return value;
    }

    public void setValue(int value) {
      this.value = value;
    }

    public boolean isExplicit() {
      return explicit;
    }

    public void setExplicit(boolean explicit) {
      this.explicit = explicit;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (value < 0) {
        throw new InvalidConfException("value may not be negative");
      }
    }

    @Override
    public int hashCode() {
      return value + 31 * Boolean.valueOf(explicit).hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }

      if (!(obj instanceof Tag)) {
        return false;
      }

      Tag other = (Tag) obj;
      return value == other.value && explicit == other.explicit;
    }

  }

}
