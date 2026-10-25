// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.Args;
import org.xipki.ca.api.TripleState;

/**
 * Extension Control settings.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtensionControl {

  private final boolean critical;

  private final boolean required;

  private final TripleState inRequest;

  private final Asn1Oid type;

  public ExtensionControl(Asn1Oid type, boolean critical,
                          boolean required, TripleState inRequest) {
    this.type = Args.notNull(type, "type");
    this.critical = critical;
    this.required = required;
    this.inRequest = inRequest == null ? TripleState.forbidden : inRequest;
  }

  public Asn1Oid type() {
    return type;
  }

  public boolean isCritical() {
    return critical;
  }

  public boolean isRequired() {
    return required;
  }

  public TripleState inRequest() {
    return inRequest;
  }

  public boolean isPermittedInRequest() {
    return TripleState.required == inRequest || TripleState.optional == inRequest;
  }

} // class CertLevel
