// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Lijun Liao (xipki)
 */
public class ExtensionsControl {

  private final Map<ASN1ObjectIdentifier, ExtensionControl> controls;

  private final List<ASN1ObjectIdentifier> types;

  private final boolean keepOrder;

  public ExtensionsControl(
      List<ExtensionControl> controls, boolean keepOrder) {
    Args.notEmpty(controls, "controls");
    this.keepOrder = keepOrder;

    List<ASN1ObjectIdentifier> sortedOids = new ArrayList<>(controls.size());
    if (keepOrder) {
      for (ExtensionControl m : controls) {
        sortedOids.add(m.type());
      }
    } else {
      Set<ASN1ObjectIdentifier> oidSet = new HashSet<>();
      for (ExtensionControl m : controls) {
        oidSet.add(m.type());
      }

      List<ASN1ObjectIdentifier> oids = SubjectDnSpec.getForwardDNs();

      for (ASN1ObjectIdentifier oid : oids) {
        if (oidSet.contains(oid)) {
          sortedOids.add(oid);
        }
      }

      for (ASN1ObjectIdentifier oid : oidSet) {
        if (!sortedOids.contains(oid)) {
          sortedOids.add(oid);
        }
      }
    }

    this.types = Collections.unmodifiableList(sortedOids);

    this.controls = new HashMap<>();
    for (ExtensionControl control : controls) {
      this.controls.put(control.type(), control);
    }

  } // constructor

  public ExtensionControl getControl(ASN1ObjectIdentifier type) {
    return controls.get(Args.notNull(type, "type"));
  }

  public boolean isKeepOrder() {
    return keepOrder;
  }

  public List<ASN1ObjectIdentifier> types() {
    return types;
  }

  public boolean containsID(ASN1ObjectIdentifier extensionID) {
    return this.types.contains(extensionID);
  }

} // class SubjectControl
