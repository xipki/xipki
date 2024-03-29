// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.util.Args;

/**
 * Type of the DirectoryString.
 *
 * @author Lijun Liao (xipki)
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
