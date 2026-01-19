// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;

/**
 * Configure extension with given (constant) extension value.
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

  public Type getType() {
    return type;
  }

  public String getValue() {
    return value;
  }

  public ASN1Encodable toASN1() throws IOException {
    if (type == Type.OCTETSTRING) {
      return new DEROctetString(Base64.decode(value));
    } else if (type == Type.BITSTRING) {
      return new DERBitString(Base64.decode(value));
    } else if (type == Type.INTEGER) {
      return new ASN1Integer(StringUtil.toBigInt(value));
    } else if (type == Type.UTF8) {
      return new DERUTF8String(value);
    } else if (type == Type.PRINTABLE) {
      return new DERPrintableString(value);
    } else { // if (type == null || type == Type.ASN1) {
      return X509Util.readAsn1Encodable(Base64.decode(value));
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

  public enum Type {
    ASN1,
    OCTETSTRING,
    BITSTRING,
    UTF8,
    PRINTABLE,
    INTEGER
  }

}
