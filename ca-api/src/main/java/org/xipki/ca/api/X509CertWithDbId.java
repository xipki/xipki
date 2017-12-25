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

package org.xipki.ca.api;

import java.security.cert.X509Certificate;

import org.xipki.security.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CertWithDbId extends X509Cert {

    private Long certId;

    public X509CertWithDbId(final X509Certificate cert) {
        super(cert);
    }

    public X509CertWithDbId(final X509Certificate cert, final byte[] encodedCert) {
        super(cert, encodedCert);
    }

    public Long certId() {
        return certId;
    }

    public void setCertId(final Long certId) {
        this.certId = certId;
    }

}
