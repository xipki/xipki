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

package org.xipki.pki.ca.server.mgmt.api.conf;

import java.util.List;

import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class SingleCaConf {

    private final String name;

    private final GenSelfIssued genSelfIssued;

    private final CaEntry caEntry;

    private final List<String> aliases;

    private final List<String> profileNames;

    private final List<CaHasRequestorEntry> requestors;

    private final List<String> publisherNames;

    public SingleCaConf(String name, GenSelfIssued genSelfIssued, CaEntry caEntry,
            List<String> aliases, List<String> profileNames, List<CaHasRequestorEntry> requestors,
            List<String> publisherNames) {
        this.name = ParamUtil.requireNonBlank("name", name);
        if (genSelfIssued != null) {
            if (caEntry == null) {
                throw new IllegalArgumentException(
                        "caEntry must not be null if genSelfIssued is non-null");
            }

            if (caEntry instanceof X509CaEntry) {
                if (((X509CaEntry) caEntry).getCertificate() != null) {
                    throw new IllegalArgumentException(
                            "caEntry.cert must not be null if genSelfIssued is non-null");
                }
            }
        }

        this.genSelfIssued = genSelfIssued;
        this.caEntry = caEntry;
        this.aliases = aliases;
        this.profileNames = profileNames;
        this.requestors = requestors;
        this.publisherNames = publisherNames;
    }

    public String getName() {
        return name;
    }

    public CaEntry getCaEntry() {
        return caEntry;
    }

    public List<String> getAliases() {
        return aliases;
    }

    public GenSelfIssued getGenSelfIssued() {
        return genSelfIssued;
    }

    public List<String> getProfileNames() {
        return profileNames;
    }

    public List<CaHasRequestorEntry> getRequestors() {
        return requestors;
    }

    public List<String> getPublisherNames() {
        return publisherNames;
    }

}
