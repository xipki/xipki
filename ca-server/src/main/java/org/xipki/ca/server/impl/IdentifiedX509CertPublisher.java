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

package org.xipki.ca.server.impl;

import java.security.cert.X509CRL;
import java.util.Map;

import org.xipki.audit.AuditServiceRegister;
import org.xipki.ca.api.EnvParameterResolver;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.X509CertWithDbId;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.x509.X509CertPublisher;
import org.xipki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class IdentifiedX509CertPublisher {

    private final PublisherEntry entry;

    private final X509CertPublisher certPublisher;

    IdentifiedX509CertPublisher(PublisherEntry entry, X509CertPublisher certPublisher) {
        this.entry = ParamUtil.requireNonNull("entry", entry);
        this.certPublisher = ParamUtil.requireNonNull("certPublisher", certPublisher);
    }

    public void initialize(PasswordResolver passwordResolver,
            Map<String, DataSourceWrapper> datasources) throws CertPublisherException {
        certPublisher.initialize(entry.conf(), passwordResolver, datasources);
    }

    public void setEnvParameterResolver(EnvParameterResolver parameterResolver) {
        certPublisher.setEnvParameterResolver(parameterResolver);
    }

    public boolean caAdded(X509Cert caCert) {
        return certPublisher.caAdded(caCert);
    }

    public boolean certificateAdded(X509CertificateInfo certInfo) {
        return certPublisher.certificateAdded(certInfo);
    }

    public boolean certificateRevoked(X509Cert caCert, X509CertWithDbId cert,
            String certprofile, CertRevocationInfo revInfo) {
        return certPublisher.certificateRevoked(caCert, cert, certprofile, revInfo);
    }

    public boolean crlAdded(X509Cert caCert, X509CRL crl) {
        return certPublisher.crlAdded(caCert, crl);
    }

    public PublisherEntry dbEntry() {
        return entry;
    }

    public NameId ident() {
        return entry.ident();
    }

    public boolean isHealthy() {
        return certPublisher.isHealthy();
    }

    public void setAuditServiceRegister(AuditServiceRegister auditServiceRegister) {
        certPublisher.setAuditServiceRegister(auditServiceRegister);
    }

    public boolean caRevoked(X509Cert caCert, CertRevocationInfo revocationInfo) {
        return certPublisher.caRevoked(caCert, revocationInfo);
    }

    public boolean caUnrevoked(X509Cert caCert) {
        return certPublisher.caUnrevoked(caCert);
    }

    public boolean certificateUnrevoked(X509Cert caCert, X509CertWithDbId cert) {
        return certPublisher.certificateUnrevoked(caCert, cert);
    }

    public boolean certificateRemoved(X509Cert caCert, X509CertWithDbId cert) {
        return certPublisher.certificateRemoved(caCert, cert);
    }

    public boolean isAsyn() {
        return certPublisher.isAsyn();
    }

    public void shutdown() {
        certPublisher.shutdown();
    }

    public boolean publishsGoodCert() {
        return certPublisher.publishsGoodCert();
    }

}
