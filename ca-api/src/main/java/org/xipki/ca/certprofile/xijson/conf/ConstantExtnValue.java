// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonEncodable;
import org.xipki.codec.json.JsonMap;
import org.xipki.pkix.util.misc.StringUtil;

/**
 * Constant Extn Value.
 *
 * @author Lijun Liao (xipki)
 */
public class ConstantExtnValue implements JsonEncodable {

  /**
   * Type of the extension. If not present, default to ASN11.
   */
  private final Type type;

  /**
   * Value of the extension. Its content depends on the type:
   *
   */
  private final String value;

  public ConstantExtnValue(Type type, String value) {
    this.type = (type == null) ? Type.ASN1 : type;
    this.value = Args.notNull(value, "value");
  }

  public ConstantExtnValue(Type type, byte[] value) {
    this.type = (type == null) ? Type.ASN1 : type;
    this.value = Base64.encodeToString(Args.notNull(value, "value"));
  }

  public Type type() {
    return type;
  }

  public String value() {
    return value;
  }

  public Asn1Primitive toASN1() throws CodecException {
    if (type == Type.OCTETSTRING) {
      return new Asn1OctetString(Base64.decode(value));
    } else if (type == Type.BITSTRING) {
      return new Asn1BitString(Base64.decode(value));
    } else if (type == Type.INTEGER) {
      return new Asn1Integer(StringUtil.toBigInt(value));
    } else if (type == Type.UTF8) {
      return new Asn1Utf8String(value);
    } else if (type == Type.PRINTABLE) {
      return new Asn1PrintableString(value);
    } else { // if (type == null || type == Type.ASN1) {
      return Asn1Util.readAsn1Object(Base64.decode(value));
    }
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEnum("type", type).put("value", value);
  }

  public static ConstantExtnValue parse(JsonMap json) throws CodecException {
    return new ConstantExtnValue(Type.valueOf(json.getNnString("type")),
        json.getNnString("value"));
  }

  /**
   * Type enumeration.
   */
  public enum Type {
    ASN1,
    OCTETSTRING,
    BITSTRING,
    UTF8,
    PRINTABLE,
    INTEGER
  }

}
