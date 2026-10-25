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
 * Subject Control settings.
 *
 * @author Lijun Liao (xipki)
 */
public class SubjectControl {

  private final Map<Asn1Oid, RdnControl> controls;

  private final List<Asn1Oid> types;

  public SubjectControl(List<RdnControl> controls, boolean keepRdnOrder) {
    Args.notEmpty(controls, "controls");

    List<Asn1Oid> sortedOids = new ArrayList<>(controls.size());
    if (keepRdnOrder) {
      for (RdnControl m : controls) {
        sortedOids.add(m.type());
      }
    } else {
      Set<Asn1Oid> oidSet = new HashSet<>();
      for (RdnControl m : controls) {
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
    for (RdnControl control : controls) {
      if (this.controls.containsKey(control.type())) {
        throw new IllegalArgumentException("duplicated subject type " + control.type().getId());
      }
      this.controls.put(control.type(), control);
    }
  } // constructor

  public RdnControl getControl(Asn1Oid type) {
    return controls.get(Args.notNull(type, "type"));
  }

  public List<Asn1Oid> types() {
    return types;
  }

} // class SubjectControl
