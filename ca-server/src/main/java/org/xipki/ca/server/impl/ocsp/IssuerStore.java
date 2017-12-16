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

package org.xipki.ca.server.impl.ocsp;

import java.util.ArrayList;
import java.util.List;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class IssuerStore {

    private final List<IssuerEntry> entries;

    IssuerStore(final List<IssuerEntry> entries) {
        ParamUtil.requireNonNull("entries", entries);
        this.entries = new ArrayList<>(entries.size());

        for (IssuerEntry entry : entries) {
            addIdentityEntry(entry);
        }
    }

    void addIdentityEntry(final IssuerEntry entry) {
        ParamUtil.requireNonNull("entry", entry);
        for (IssuerEntry existingEntry : entries) {
            if (existingEntry.id() == entry.id()) {
                throw new IllegalArgumentException(
                        "issuer with the same id " + entry.id() + " already available");
            }
        }

        entries.add(entry);
    }

    Integer getIdForSubject(final String subject) {
        ParamUtil.requireNonBlank("subject", subject);
        for (IssuerEntry entry : entries) {
            if (entry.subject().equals(subject)) {
                return entry.id();
            }
        }

        return null;
    }

    Integer getIdForSha1Fp(final byte[] sha1FpCert) {
        ParamUtil.requireNonNull("sha1FpCert", sha1FpCert);
        for (IssuerEntry entry : entries) {
            if (entry.matchSha1Fp(sha1FpCert)) {
                return entry.id();
            }
        }

        return null;
    }

    Integer getIdForCert(final byte[] encodedCert) {
        ParamUtil.requireNonNull("encodedCert", encodedCert);
        for (IssuerEntry entry : entries) {
            if (entry.matchCert(encodedCert)) {
                return entry.id();
            }
        }

        return null;
    }

}
