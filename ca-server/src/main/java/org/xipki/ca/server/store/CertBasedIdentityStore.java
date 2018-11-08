/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.server.store;

import java.util.ArrayList;
import java.util.List;

import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class CertBasedIdentityStore {

  private final String table;

  private final List<CertBasedIdentityEntry> entries;

  CertBasedIdentityStore(String table, List<CertBasedIdentityEntry> entries) {
    this.table = ParamUtil.requireNonNull("table", table);
    ParamUtil.requireNonNull("entries", entries);
    this.entries = new ArrayList<>(entries.size());

    for (CertBasedIdentityEntry entry : entries) {
      addIdentityEntry(entry);
    }
  }

  final void addIdentityEntry(CertBasedIdentityEntry entry) {
    ParamUtil.requireNonNull("entry", entry);

    for (CertBasedIdentityEntry existingEntry : entries) {
      if (existingEntry.getId() == entry.getId()) {
        throw new IllegalArgumentException(StringUtil.concatObjects(table,
            " with the same id ", entry.getId(), " already available"));
      }
    }

    entries.add(entry);
  }

  Integer getCaIdForSubject(String subject) {
    for (CertBasedIdentityEntry entry : entries) {
      if (entry.getSubject().equals(subject)) {
        return entry.getId();
      }
    }

    return null;
  }

  Integer getCaIdForSha1Fp(byte[] sha1FpCert) {
    for (CertBasedIdentityEntry entry : entries) {
      if (entry.matchSha1Fp(sha1FpCert)) {
        return entry.getId();
      }
    }

    return null;
  }

  Integer getCaIdForCert(byte[] encodedCert) {
    for (CertBasedIdentityEntry entry : entries) {
      if (entry.matchCert(encodedCert)) {
        return entry.getId();
      }
    }

    return null;
  }

  String getTable() {
    return table;
  }

  int size() {
    return entries.size();
  }

}
