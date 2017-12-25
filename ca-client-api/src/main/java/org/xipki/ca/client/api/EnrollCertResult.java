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

package org.xipki.ca.client.api;

import java.security.cert.Certificate;
import java.util.Map;
import java.util.Set;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EnrollCertResult {

    private final Certificate caCertificate;

    private final Map<String, CertOrError> certificatesOrErrors;

    public EnrollCertResult(final Certificate caCertificate,
            final Map<String, CertOrError> certificatesOrErrors) {
        this.certificatesOrErrors = ParamUtil.requireNonEmpty("certificatesOrErrors",
                certificatesOrErrors);
        this.caCertificate = caCertificate;
    }

    public Certificate caCertificate() {
        return caCertificate;
    }

    public CertOrError getCertificateOrError(final String id) {
        ParamUtil.requireNonBlank("id", id);
        return certificatesOrErrors.get(id);
    }

    public Set<String> allIds() {
        return certificatesOrErrors.keySet();
    }

}
