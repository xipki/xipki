// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.*;
import org.xipki.util.Args;

/**
 * Type of the DirectoryString.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum DirectoryStringType {

  teletexString,
  printableString,
  utf8String,
  bmpString;

  public ASN1Encodable createDirectoryString(String text) {
    Args.notNull(text, "text");

    return (teletexString == this)  ? new DERT61String(text)
        : (printableString == this) ? new DERPrintableString(text)
        : (utf8String == this)      ? new DERUTF8String(text)
        : new DERBMPString(text);
  } // method createDirectoryString

}
