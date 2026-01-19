// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store.ejbca;

import org.xipki.ocsp.api.RequestIssuer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * IssuerStore for the EJBCA database.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class EjbcaIssuerStore {

  private final List<EjbcaIssuerEntry> entries;

  private final Set<String> ids;

  public EjbcaIssuerStore(Collection<EjbcaIssuerEntry> entries) {
    this.entries = new ArrayList<>(entries.size());
    Set<String> idSet = new HashSet<>(entries.size());

    for (EjbcaIssuerEntry entry : entries) {
      for (EjbcaIssuerEntry existingEntry : this.entries) {
        if (existingEntry.getId().contentEquals(entry.getId())) {
          throw new IllegalArgumentException(
              "issuer with the same id (fingerprint) " + entry.getId()
              + " already available");
        }
      }
      this.entries.add(entry);
      idSet.add(entry.getId());
    }

    this.ids = Collections.unmodifiableSet(idSet);
  }

  public int size() {
    return ids.size();
  }

  public Set<String> getIds() {
    return ids;
  }

  public EjbcaIssuerEntry getIssuerForId(String id) {
    for (EjbcaIssuerEntry entry : entries) {
      if (entry.getId().contentEquals(id)) {
        return entry;
      }
    }

    return null;
  }

  public EjbcaIssuerEntry getIssuerForFp(RequestIssuer reqIssuer) {
    for (EjbcaIssuerEntry entry : entries) {
      if (entry.matchHash(reqIssuer)) {
        return entry;
      }
    }

    return null;
  }

}
