/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ocsp.server.store.ejbca;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.xipki.ocsp.api.RequestIssuer;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class EjbcaIssuerStore {

  private final List<EjbcaIssuerEntry> entries;

  private Set<String> ids;

  public EjbcaIssuerStore(Collection<EjbcaIssuerEntry> entries) {
    this.entries = new ArrayList<>(entries.size());
    Set<String> idSet = new HashSet<>(entries.size());

    for (EjbcaIssuerEntry entry : entries) {
      for (EjbcaIssuerEntry existingEntry : this.entries) {
        if (existingEntry.getId().contentEquals(entry.getId())) {
          throw new IllegalArgumentException(
              "issuer with the same id (fingerprint) " + entry.getId() + " already available");
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

  public String getIssuerIdForFp(RequestIssuer reqIssuer) {
    EjbcaIssuerEntry issuerEntry = getIssuerForFp(reqIssuer);
    return (issuerEntry == null) ? null : issuerEntry.getId();
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

  public void addIssuer(EjbcaIssuerEntry issuer) {
    this.entries.add(issuer);
    Set<String> newIds = new HashSet<>(this.ids);
    newIds.add(issuer.getId());
    this.ids = Collections.unmodifiableSet(newIds);
  }

}
