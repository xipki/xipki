// Copyright (c) 2013-2025 xipki. All rights reserved.
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
public class SubjectControl {

  private final Map<ASN1ObjectIdentifier, RdnControl> controls;

  private final List<ASN1ObjectIdentifier> types;

  public SubjectControl(List<RdnControl> controls, boolean keepRdnOrder) {
    Args.notEmpty(controls, "controls");

    List<ASN1ObjectIdentifier> sortedOids = new ArrayList<>(controls.size());
    if (keepRdnOrder) {
      for (RdnControl m : controls) {
        sortedOids.add(m.getType());
      }
    } else {
      Set<ASN1ObjectIdentifier> oidSet = new HashSet<>();
      for (RdnControl m : controls) {
        oidSet.add(m.getType());
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
    for (RdnControl control : controls) {
      this.controls.put(control.getType(), control);
    }
  } // constructor

  public RdnControl getControl(ASN1ObjectIdentifier type) {
    return controls.get(Args.notNull(type, "type"));
  }

  public List<ASN1ObjectIdentifier> getTypes() {
    return types;
  }

} // class SubjectControl
