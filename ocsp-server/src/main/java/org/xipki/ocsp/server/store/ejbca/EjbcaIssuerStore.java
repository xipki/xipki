/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.xipki.ocsp.api.RequestIssuer;

import java.util.*;

/**
 * IssuerStore for the EJBCA database.
 *
 * @author Lijun Liao
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
