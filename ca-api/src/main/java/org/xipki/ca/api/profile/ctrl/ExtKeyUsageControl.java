// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public class ExtKeyUsageControl {

  private final ASN1ObjectIdentifier extKeyUsage;

  private final boolean required;

  public ExtKeyUsageControl(ASN1ObjectIdentifier extKeyUsage,
                            boolean required) {
    this.extKeyUsage = Args.notNull(extKeyUsage, "extKeyUsage");
    this.required = required;
  }

  public ASN1ObjectIdentifier getExtKeyUsage() {
    return extKeyUsage;
  }

  public boolean isRequired() {
    return required;
  }

} // class ExtKeyUsageControl
