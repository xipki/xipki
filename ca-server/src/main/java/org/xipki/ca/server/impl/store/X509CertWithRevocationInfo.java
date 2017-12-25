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

package org.xipki.ca.server.impl.store;

import org.xipki.ca.api.X509CertWithDbId;
import org.xipki.ca.server.mgmt.api.x509.CertWithStatusInfo;
import org.xipki.security.CertRevocationInfo;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CertWithRevocationInfo {

    private X509CertWithDbId cert;

    private CertRevocationInfo revInfo;

    private String certprofile;

    public X509CertWithRevocationInfo() {
    }

    public X509CertWithDbId cert() {
        return cert;
    }

    public boolean isRevoked() {
        return revInfo != null;
    }

    public CertRevocationInfo revInfo() {
        return revInfo;
    }

    public void setCert(final X509CertWithDbId cert) {
        this.cert = cert;
    }

    public void setRevInfo(final CertRevocationInfo revInfo) {
        this.revInfo = revInfo;
    }

    public String certprofile() {
        return certprofile;
    }

    public void setCertprofile(final String certprofile) {
        this.certprofile = certprofile;
    }

    public CertWithStatusInfo toCertWithStatusInfo() {
        CertWithStatusInfo ret = new CertWithStatusInfo();
        ret.setCert(cert.cert());
        ret.setCertprofile(certprofile);
        ret.setRevocationInfo(revInfo);
        return ret;
    }

}
