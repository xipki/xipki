/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.pki.ca.server.impl;

import java.security.cert.X509CRL;
import java.util.Map;

import org.xipki.commons.audit.api.AuditServiceRegister;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.X509Cert;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.X509CertWithDbId;
import org.xipki.pki.ca.api.publisher.CertPublisherException;
import org.xipki.pki.ca.api.publisher.x509.X509CertPublisher;
import org.xipki.pki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class IdentifiedX509CertPublisher {

    private final PublisherEntry entry;

    private final X509CertPublisher certPublisher;

    IdentifiedX509CertPublisher(
            final PublisherEntry entry,
            final X509CertPublisher certPublisher) {
        this.entry = ParamUtil.requireNonNull("entry", entry);
        this.certPublisher = ParamUtil.requireNonNull("certPublisher", certPublisher);
    } // constructor

    public void initialize(
            final PasswordResolver passwordResolver,
            final Map<String, DataSourceWrapper> datasources)
    throws CertPublisherException {
        certPublisher.initialize(entry.getConf(), passwordResolver, datasources);
    }

    public void setEnvParameterResolver(
            final EnvParameterResolver parameterResolver) {
        certPublisher.setEnvParameterResolver(parameterResolver);
    }

    public boolean issuerAdded(
            final X509Cert issuerCert) {
        return certPublisher.issuerAdded(issuerCert);
    }

    public boolean certificateAdded(
            final X509CertificateInfo certInfo) {
        return certPublisher.certificateAdded(certInfo);
    }

    public boolean certificateRevoked(
            final X509Cert issuerCert,
            final X509CertWithDbId cert,
            final String certprofile,
            final CertRevocationInfo revInfo) {
        return certPublisher.certificateRevoked(issuerCert, cert, certprofile, revInfo);
    }

    public boolean crlAdded(
            final X509Cert caCert,
            final X509CRL crl) {
        return certPublisher.crlAdded(caCert, crl);
    }

    public PublisherEntry getDbEntry() {
        return entry;
    }

    public String getName() {
        return entry.getName();
    }

    public boolean isHealthy() {
        return certPublisher.isHealthy();
    }

    public void setAuditServiceRegister(
            final AuditServiceRegister auditServiceRegister) {
        certPublisher.setAuditServiceRegister(auditServiceRegister);
    }

    public boolean caRevoked(
            final X509Cert caCert,
            final CertRevocationInfo revocationInfo) {
        return certPublisher.caRevoked(caCert, revocationInfo);
    }

    public boolean caUnrevoked(
            final X509Cert caCert) {
        return certPublisher.caUnrevoked(caCert);
    }

    public boolean certificateUnrevoked(
            final X509Cert issuerCert,
            final X509CertWithDbId cert) {
        return certPublisher.certificateUnrevoked(issuerCert, cert);
    }

    public boolean certificateRemoved(
            final X509Cert issuerCert,
            final X509CertWithDbId cert) {
        return certPublisher.certificateRemoved(issuerCert, cert);
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
