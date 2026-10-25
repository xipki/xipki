// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.codec.asn1.AbstractAsn1String;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.util.Args;

/**
 * String Type enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum StringType {

  printableString,
  utf8String,
  ia5String;

  public AbstractAsn1String createString(String text) {
    Args.notNull(text, "text");

    if (printableString == this) {
      return new Asn1PrintableString(text);
    } else if (utf8String == this) {
      return new Asn1Utf8String(text);
    } else if (ia5String == this) {
      return new Asn1IA5String(text);
    } else {
      throw new IllegalStateException("should not reach here, unknown StringType " + this.name());
    }
  }

} // class StringType
