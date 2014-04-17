/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.common;

import java.security.cert.Certificate;

import org.xipki.security.common.ParamChecker;

public class CertificateOrError {
    private final Certificate certificate;
    private final PKIStatusInfo error;

    public CertificateOrError(Certificate certificate) {
        ParamChecker.assertNotNull("certificate", certificate);

        this.certificate = certificate;
        this.error = null;
    }

    public CertificateOrError(PKIStatusInfo error) {
        ParamChecker.assertNotNull("error", error);

        this.certificate = null;
        this.error = error;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public PKIStatusInfo getError() {
        return error;
    }


}
