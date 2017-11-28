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

package org.xipki.security.pkcs11;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.xipki.common.util.ParamUtil;
import org.xipki.security.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11SlotRefreshResult {

    private final Map<P11ObjectIdentifier, P11Identity> identities = new HashMap<>();

    private final Map<P11ObjectIdentifier, X509Cert> certificates = new HashMap<>();

    private final Set<Long> mechanisms = new HashSet<>();

    public P11SlotRefreshResult() {
    }

    public Map<P11ObjectIdentifier, P11Identity> identities() {
        return identities;
    }

    public Map<P11ObjectIdentifier, X509Cert> certificates() {
        return certificates;
    }

    public Set<Long> mechanisms() {
        return mechanisms;
    }

    public void addIdentity(final P11Identity identity) {
        ParamUtil.requireNonNull("identity", identity);
        this.identities.put(identity.identityId().objectId(), identity);
    }

    public void addMechanism(final long mechanism) {
        this.mechanisms.add(mechanism);
    }

    public void addCertificate(final P11ObjectIdentifier objectId, final X509Cert certificate) {
        ParamUtil.requireNonNull("objectId", objectId);
        ParamUtil.requireNonNull("certificate", certificate);
        this.certificates.put(objectId, certificate);
    }

    /**
     *
     * @param id
     *          Identifier. Must not be {@code null}.
     */
    public X509Cert getCertForId(final byte[] id) {
        for (P11ObjectIdentifier objId : certificates.keySet()) {
            if (objId.matchesId(id)) {
                return certificates.get(objId);
            }
        }
        return null;
    }
}
