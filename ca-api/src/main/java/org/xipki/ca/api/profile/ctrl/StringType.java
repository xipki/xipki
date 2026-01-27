// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public enum StringType {

  printableString,
  utf8String,
  ia5String;

  public ASN1Encodable createString(String text) {
    Args.notNull(text, "text");

    if (printableString == this) {
      return new DERPrintableString(text);
    } else if (utf8String == this) {
      return new DERUTF8String(text);
    } else if (ia5String == this) {
      return new DERIA5String(text, true);
    } else {
      throw new IllegalStateException(
          "should not reach here, unknown StringType " + this.name());
    }
  }

} // class StringType
