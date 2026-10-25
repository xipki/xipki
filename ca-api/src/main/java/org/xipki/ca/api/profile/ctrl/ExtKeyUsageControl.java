// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.Args;

/**
 * Ext Key Usage Control settings.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtKeyUsageControl {

  private final Asn1Oid extKeyUsage;

  private final boolean required;

  public ExtKeyUsageControl(Asn1Oid extKeyUsage, boolean required) {
    this.extKeyUsage = Args.notNull(extKeyUsage, "extKeyUsage");
    this.required = required;
  }

  public Asn1Oid extKeyUsage() {
    return extKeyUsage;
  }

  public boolean isRequired() {
    return required;
  }

}
