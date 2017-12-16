/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ocsp.server.impl.store.db;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.xipki.ocsp.api.RequestIssuer;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerStore {

    private final List<IssuerEntry> entries;

    private Set<Integer> ids;

    public IssuerStore(final List<IssuerEntry> entries) {
        this.entries = new ArrayList<>(entries.size());
        Set<Integer> idSet = new HashSet<>(entries.size());

        for (IssuerEntry entry : entries) {
            for (IssuerEntry existingEntry : this.entries) {
                if (existingEntry.id() == entry.id()) {
                    throw new IllegalArgumentException(
                            "issuer with the same id " + entry.id() + " already available");
                }
            }
            this.entries.add(entry);
            idSet.add(entry.id());
        }

        this.ids = Collections.unmodifiableSet(idSet);
    }

    public int size() {
        return ids.size();
    }

    public Set<Integer> ids() {
        return ids;
    }

    public Integer getIssuerIdForFp(RequestIssuer reqIssuer) {
        IssuerEntry issuerEntry = getIssuerForFp(reqIssuer);
        return (issuerEntry == null) ? null : issuerEntry.id();
    }

    public IssuerEntry getIssuerForId(final int id) {
        for (IssuerEntry entry : entries) {
            if (entry.id() == id) {
                return entry;
            }
        }

        return null;
    }

    public IssuerEntry getIssuerForFp(final RequestIssuer reqIssuer) {
        for (IssuerEntry entry : entries) {
            if (entry.matchHash(reqIssuer)) {
                return entry;
            }
        }

        return null;
    }

    public void addIssuer(IssuerEntry issuer) {
        this.entries.add(issuer);
        Set<Integer> newIds = new HashSet<>(this.ids);
        newIds.add(issuer.id());
        this.ids = Collections.unmodifiableSet(newIds);
    }

}
