// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.type.TripleState;

/**
 * @author Lijun Liao (xipki)
 */
public class ExtensionControl {

  private final boolean critical;

  private final boolean required;

  private final TripleState inRequest;

  private final ASN1ObjectIdentifier type;

  public ExtensionControl(ASN1ObjectIdentifier type, boolean critical,
                          boolean required, TripleState inRequest) {
    this.type = Args.notNull(type, "type");
    this.critical = critical;
    this.required = required;
    this.inRequest = inRequest == null ? TripleState.forbidden : inRequest;
  }

  public ASN1ObjectIdentifier getType() {
    return type;
  }

  public boolean isCritical() {
    return critical;
  }

  public boolean isRequired() {
    return required;
  }

  public TripleState getInRequest() {
    return inRequest;
  }

  public boolean isPermittedInRequest() {
    return TripleState.required == inRequest
        || TripleState.optional == inRequest;
  }

} // class CertLevel
