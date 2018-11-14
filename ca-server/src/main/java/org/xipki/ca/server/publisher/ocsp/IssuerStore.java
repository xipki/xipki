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

package org.xipki.ca.server.publisher.ocsp;

import java.util.ArrayList;
import java.util.List;

import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class IssuerStore {

  private final List<IssuerEntry> entries;

  IssuerStore(List<IssuerEntry> entries) {
    Args.notNull(entries, "entries");
    this.entries = new ArrayList<>(entries.size());

    for (IssuerEntry entry : entries) {
      addIdentityEntry(entry);
    }
  }

  final void addIdentityEntry(IssuerEntry entry) {
    Args.notNull(entry, "entry");
    for (IssuerEntry existingEntry : entries) {
      if (existingEntry.getId() == entry.getId()) {
        throw new IllegalArgumentException(
            "issuer with the same id " + entry.getId() + " already available");
      }
    }

    entries.add(entry);
  }

  Integer getIdForSubject(String subject) {
    Args.notBlank(subject, "subject");
    for (IssuerEntry entry : entries) {
      if (entry.getSubject().equals(subject)) {
        return entry.getId();
      }
    }

    return null;
  }

  Integer getIdForSha1Fp(byte[] sha1FpCert) {
    Args.notNull(sha1FpCert, "sha1FpCert");
    for (IssuerEntry entry : entries) {
      if (entry.matchSha1Fp(sha1FpCert)) {
        return entry.getId();
      }
    }

    return null;
  }

  Integer getIdForCert(byte[] encodedCert) {
    Args.notNull(encodedCert, "encodedCert");
    for (IssuerEntry entry : entries) {
      if (entry.matchCert(encodedCert)) {
        return entry.getId();
      }
    }

    return null;
  }

}
