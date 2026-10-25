// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extensions Control settings.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtensionsControl {

  private final Map<Asn1Oid, ExtensionControl> controls;

  private final List<Asn1Oid> types;

  private final boolean keepOrder;

  public ExtensionsControl(List<ExtensionControl> controls, boolean keepOrder) {
    Args.notEmpty(controls, "controls");
    this.keepOrder = keepOrder;

    List<Asn1Oid> sortedOids = new ArrayList<>(controls.size());
    if (keepOrder) {
      for (ExtensionControl m : controls) {
        sortedOids.add(m.type());
      }
    } else {
      Set<Asn1Oid> oidSet = new HashSet<>();
      for (ExtensionControl m : controls) {
        oidSet.add(m.type());
      }

      List<Asn1Oid> oids = SubjectDnSpec.getForwardDNs();

      for (Asn1Oid oid : oids) {
        if (oidSet.contains(oid)) {
          sortedOids.add(oid);
        }
      }

      for (Asn1Oid oid : oidSet) {
        if (!sortedOids.contains(oid)) {
          sortedOids.add(oid);
        }
      }
    }

    this.types = Collections.unmodifiableList(sortedOids);

    this.controls = new HashMap<>();
    for (ExtensionControl control : controls) {
      if (this.controls.containsKey(control.type())) {
        throw new IllegalArgumentException("duplicated extension type " + control.type().getId());
      }
      this.controls.put(control.type(), control);
    }

  } // constructor

  public ExtensionControl getControl(Asn1Oid type) {
    return controls.get(Args.notNull(type, "type"));
  }

  public boolean isKeepOrder() {
    return keepOrder;
  }

  public List<Asn1Oid> types() {
    return types;
  }

  public boolean containsID(Asn1Oid extensionID) {
    return this.types.contains(extensionID);
  }

} // class SubjectControl
