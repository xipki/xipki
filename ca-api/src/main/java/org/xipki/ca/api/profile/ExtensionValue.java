// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.util.Args;

/**
 * Extension Value.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtensionValue {

  private final boolean critical;

  private final Asn1Primitive value;

  public ExtensionValue(boolean critical, Asn1Primitive value) {
    this.critical = critical;
    this.value = Args.notNull(value, "value");
  }

  public static ExtensionValue build(boolean critical, Asn1Encodable value) {
    return new ExtensionValue(critical, Args.notNull(value, "value").toAsn1Primitive());
  }

  public boolean isCritical() {
    return critical;
  }

  public Asn1Primitive value() {
    return value;
  }

}
