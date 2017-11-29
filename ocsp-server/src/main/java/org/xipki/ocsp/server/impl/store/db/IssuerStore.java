/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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
