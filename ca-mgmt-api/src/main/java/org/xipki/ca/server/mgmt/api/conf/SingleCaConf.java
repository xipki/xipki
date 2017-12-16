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

package org.xipki.ca.server.mgmt.api.conf;

import java.util.List;

import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.common.util.ParamUtil;

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
                if (((X509CaEntry) caEntry).certificate() != null) {
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

    public String name() {
        return name;
    }

    public CaEntry caEntry() {
        return caEntry;
    }

    public List<String> aliases() {
        return aliases;
    }

    public GenSelfIssued genSelfIssued() {
        return genSelfIssued;
    }

    public List<String> profileNames() {
        return profileNames;
    }

    public List<CaHasRequestorEntry> requestors() {
        return requestors;
    }

    public List<String> publisherNames() {
        return publisherNames;
    }

}
