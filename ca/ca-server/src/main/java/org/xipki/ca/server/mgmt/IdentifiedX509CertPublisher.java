/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.server.mgmt;

import java.security.cert.X509CRL;

import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.ca.api.CertPublisherException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.X509CertificateWithMetaInfo;
import org.xipki.ca.api.publisher.X509CertPublisher;
import org.xipki.ca.api.publisher.X509CertificateInfo;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.ParamChecker;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

public class IdentifiedX509CertPublisher
{
    private final String name;
    private final X509CertPublisher certPublisher;

    public IdentifiedX509CertPublisher(String name, X509CertPublisher certPublisher)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotNull("certPublisher", certPublisher);

        this.name = name;
        this.certPublisher = certPublisher;
    }

    public void initialize(String conf, PasswordResolver passwordResolver,
            DataSourceWrapper dataSource)
    throws CertPublisherException
    {
        certPublisher.initialize(conf, passwordResolver, dataSource);
    }

    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        certPublisher.setEnvironmentParameterResolver(parameterResolver);
    }

    public boolean issuerAdded(X509CertificateWithMetaInfo issuerCert)
    {
        return certPublisher.issuerAdded(issuerCert);
    }

    public boolean certificateAdded(X509CertificateInfo certInfo)
    {
        return certPublisher.certificateAdded(certInfo);
    }

    public boolean certificateRevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert, String certProfile, CertRevocationInfo revInfo)
    {
        return certPublisher.certificateRevoked(issuerCert, cert, certProfile, revInfo);
    }

    public boolean crlAdded(X509CertificateWithMetaInfo caCert, X509CRL crl)
    {
        return certPublisher.crlAdded(caCert, crl);
    }

    public String getName()
    {
        return name;
    }

    public boolean isHealthy()
    {
        return certPublisher.isHealthy();
    }

    public void setAuditServiceRegister(AuditLoggingServiceRegister auditServiceRegister)
    {
        certPublisher.setAuditServiceRegister(auditServiceRegister);
    }

    public boolean caRevoked(X509CertificateWithMetaInfo caCert, CertRevocationInfo revocationInfo)
    {
        return certPublisher.caRevoked(caCert, revocationInfo);
    }

    public boolean caUnrevoked(X509CertificateWithMetaInfo caCert)
    {
        return certPublisher.caUnrevoked(caCert);
    }

    public boolean certificateUnrevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert)
    {
        return certPublisher.certificateUnrevoked(issuerCert, cert);
    }

    public boolean certificateRemoved(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert)
    {
        return certPublisher.certificateRemoved(issuerCert, cert);
    }

    public boolean isAsyn()
    {
        return certPublisher.isAsyn();
    }

    public void shutdown()
    {
        certPublisher.shutdown();
    }

    public boolean publishsGoodCert()
    {
        return certPublisher.publishsGoodCert();
    }

}
