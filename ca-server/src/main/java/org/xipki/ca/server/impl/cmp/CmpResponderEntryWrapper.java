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

package org.xipki.ca.server.impl.cmp;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpResponderEntryWrapper {

    private CmpResponderEntry dbEntry;

    private ConcurrentContentSigner signer;

    private X500Name subjectAsX500Name;

    private GeneralName subjectAsGeneralName;

    public CmpResponderEntryWrapper() {
    }

    public void setDbEntry(final CmpResponderEntry dbEntry) {
        this.dbEntry = ParamUtil.requireNonNull("dbEntry", dbEntry);
        signer = null;
        if (dbEntry.certificate() != null) {
            subjectAsX500Name = X500Name.getInstance(
                    dbEntry.certificate().getSubjectX500Principal().getEncoded());
            subjectAsGeneralName = new GeneralName(subjectAsX500Name);
        }
    }

    public ConcurrentContentSigner signer() {
        return signer;
    }

    public void initSigner(final SecurityFactory securityFactory) throws ObjectCreationException {
        ParamUtil.requireNonNull("securityFactory", securityFactory);
        if (signer != null) {
            return;
        }

        if (dbEntry == null) {
            throw new ObjectCreationException("dbEntry is null");
        }

        X509Certificate responderCert = dbEntry.certificate();
        dbEntry.setConfFaulty(true);
        signer = securityFactory.createSigner(dbEntry.type(), new SignerConf(dbEntry.conf()),
                responderCert);
        if (signer.getCertificate() == null) {
            throw new ObjectCreationException("signer without certificate is not allowed");
        }
        dbEntry.setConfFaulty(false);

        if (dbEntry.base64Cert() == null) {
            dbEntry.setCertificate(signer.getCertificate());
            subjectAsX500Name = X500Name.getInstance(
                    signer.getCertificateAsBcObject().getSubject());
            subjectAsGeneralName = new GeneralName(subjectAsX500Name);
        }
    } // method initSigner

    public CmpResponderEntry dbEntry() {
        return dbEntry;
    }

    public boolean isHealthy() {
        return (signer == null) ? false : signer.isHealthy();
    }

    public GeneralName subjectAsGeneralName() {
        return subjectAsGeneralName;
    }

    public X500Name subjectAsX500Name() {
        return subjectAsX500Name;
    }

}
