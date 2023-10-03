// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.*;
import org.xipki.util.Base64;
import org.xipki.util.StringUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.Locale;

/**
 * Configure extension with given (constant) extension value.
 * @author Lijun Liao (xipki)
 */
public class ConstantExtnValue extends ValidatableConf {

  public static final String TYPE_ASN1 = "ASN1";

  public static final String TYPE_OCTET_STRING = "OCTET STRING";

  public static final String TYPE_BIT_STRING = "BIT STRING";

  public static final String TYPE_UTF8_STRING = "UTF8String";

  public static final String TYPE_PRINTABLE_STRING = "PrintableString";

  public static final String TYPE_INTEGER = "INTEGER";

  /**
   * Type of the extension. If not present, default to asn1.
   * <ul>
   *   <li>ASN1:  value is the BASE64-encoded ASN.1 object in DER-encoding.</li>
   *   <li>INTEGER: value will be encoded as an INTEGER in the certificate. Hex number is prefixed with 0x.</li>
   *   <li>OCTET STRING: value is the BASE64-encoded content which will be encoded as an OCTET STRING
   *       in the certificate.</li>
   *   <li>BIT STRING: value is the BASE64-encoded content which will be encoded as an BIT STRING
   *       in the certificate.</li>
   *   <li>UTF8String:  value will be encoded as a UTF8 String in the certificate.</li>
   *   <li>PrintableString: value will be encoded as a Printable String in the certificate.</li>
   * </ul>
   */
  private String type;

  /**
   * Value of the extension. Its content depends on the type:
   *
   */
  private String value;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type == null ? null : type.toUpperCase(Locale.ROOT);
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public ASN1Encodable toASN1Encodable() throws InvalidConfException {
    if (value == null) {
      throw new InvalidConfException("value must not be non-null");
    }

    String tType = type == null ? TYPE_ASN1 : type;

    try {
      if (tType.equalsIgnoreCase(TYPE_ASN1)) {
        ASN1StreamParser parser = new ASN1StreamParser(Base64.decode(value));
        return parser.readObject();
      } else if (tType.equalsIgnoreCase(TYPE_INTEGER)) {
        return new ASN1Integer(StringUtil.toBigInt(value));
      } else if (tType.equalsIgnoreCase(TYPE_OCTET_STRING)) {
          return new DEROctetString(Base64.decode(value));
      } else if (tType.equalsIgnoreCase(TYPE_BIT_STRING)) {
          return new DERBitString(Base64.decode(value));
      } else if (tType.equalsIgnoreCase(TYPE_PRINTABLE_STRING)) {
          return new DERPrintableString(value);
      } else if (tType.equalsIgnoreCase(TYPE_UTF8_STRING)) {
        return new DERUTF8String(value);
      } else {
        throw new InvalidConfException("invalid type " + type);
      }
    } catch (Exception ex) {
      throw new InvalidConfException("could not parse the constant extension value", ex);
    }
  }

  @Override
  public void validate() throws InvalidConfException {
    toASN1Encodable();
  }

}
