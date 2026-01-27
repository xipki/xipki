// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf;

import org.xipki.ca.certprofile.xijson.conf.ConstantExtnValue;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.util.Locale;

/**
 * Configure extension with given (constant) extension value.
 * @author Lijun Liao (xipki)
 */
public class V1ConstantExtnValue {

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
   *   <li>INTEGER: value will be encoded as an INTEGER in the certificate.
   *       Hex number is prefixed with 0x.</li>
   *   <li>OCTET STRING: value is the BASE64-encoded content which will be
   *       encoded as an OCTET STRING in the certificate.</li>
   *   <li>BIT STRING: value is the BASE64-encoded content which will be
   *       encoded as a BIT STRING in the certificate.</li>
   *   <li>UTF8String:  value will be encoded as a UTF8 String in the
   *       certificate.</li>
   *   <li>PrintableString: value will be encoded as a Printable String in the
   *       certificate.</li>
   * </ul>
   */
  private final String type;

  /**
   * Value of the extension. Its content depends on the type:
   *
   */
  private final String value;

  public V1ConstantExtnValue(String type, String value) {
    this.type = (type == null) ? null : type.toUpperCase(Locale.ROOT);
    this.value = value;
  }

  public ConstantExtnValue toV2() {
    ConstantExtnValue.Type v2t =
        (type == null || TYPE_ASN1.equalsIgnoreCase(type))
            ? ConstantExtnValue.Type.ASN1
        : TYPE_INTEGER.equalsIgnoreCase(type)
            ? ConstantExtnValue.Type.INTEGER
        : TYPE_BIT_STRING.equalsIgnoreCase(type)
            ? ConstantExtnValue.Type.BITSTRING
        : TYPE_OCTET_STRING.equalsIgnoreCase(type)
            ? ConstantExtnValue.Type.OCTETSTRING
        : TYPE_PRINTABLE_STRING.equalsIgnoreCase(type)
            ? ConstantExtnValue.Type.PRINTABLE
        : TYPE_UTF8_STRING.equalsIgnoreCase(type)
            ? ConstantExtnValue.Type.UTF8
        : null;
    if (v2t == null) {
      throw new IllegalArgumentException(
          "unknown ConstantExtValue.type '" + type + "'");
    }

    return new ConstantExtnValue(v2t, value);
  }

  public static V1ConstantExtnValue parse(JsonMap json) throws CodecException {
    return new V1ConstantExtnValue(json.getString("type"),
        json.getString("value"));
  }

}
