// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1Encodable;
import org.xipki.util.Args;

/**
 * Extension value control.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ExtensionValue {

  private final boolean critical;

  private final ASN1Encodable value;

  public ExtensionValue(boolean critical, ASN1Encodable value) {
    this.critical = critical;
    this.value = Args.notNull(value, "value");
  }

  public boolean isCritical() {
    return critical;
  }

  public ASN1Encodable getValue() {
    return value;
  }

}
