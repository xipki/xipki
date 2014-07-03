/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.api.publisher;

import java.security.cert.X509CRL;

import org.xipki.audit.api.AuditLoggingService;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IdentifiedCertPublisher extends CertPublisher
{
    private final String name;
    private final CertPublisher certPublisher;

    public IdentifiedCertPublisher(String name, CertPublisher certPublisher)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotNull("certPublisher", certPublisher);

        this.name = name;
        this.certPublisher = certPublisher;
    }

    @Override
    public void initialize(String conf, PasswordResolver passwordResolver,
            DataSourceWrapper dataSource)
    throws CertPublisherException
    {
        certPublisher.initialize(conf, passwordResolver, dataSource);
    }

    @Override
    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        certPublisher.setEnvironmentParameterResolver(parameterResolver);
    }

    @Override
    public boolean certificateAdded(CertificateInfo certInfo)
    {
        return certPublisher.certificateAdded(certInfo);
    }

    @Override
    public boolean certificateRevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert, CertRevocationInfo revInfo)
    {
        return certPublisher.certificateRevoked(issuerCert, cert, revInfo);
    }

    @Override
    public boolean crlAdded(X509CertificateWithMetaInfo caCert, X509CRL crl)
    {
        return certPublisher.crlAdded(caCert, crl);
    }

    public String getName()
    {
        return name;
    }

    @Override
    public boolean isHealthy()
    {
        return certPublisher.isHealthy();
    }

    @Override
    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        certPublisher.setAuditLoggingService(auditLoggingService);
    }

    @Override
    public boolean caRevoked(X509CertificateWithMetaInfo caCert, CertRevocationInfo revocationInfo)
    {
        return certPublisher.caRevoked(caCert, revocationInfo);
    }

    @Override
    public boolean caUnrevoked(X509CertificateWithMetaInfo caCert)
    {
        return certPublisher.caUnrevoked(caCert);
    }

    @Override
    public boolean certificateUnrevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert)
    {
        return certPublisher.certificateUnrevoked(issuerCert, cert);
    }

    @Override
    public boolean certificateRemoved(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert)
    {
        return certPublisher.certificateRemoved(issuerCert, cert);
    }

    @Override
    public boolean isAsyn()
    {
        return certPublisher.isAsyn();
    }

    @Override
    public void shutdown()
    {
        certPublisher.shutdown();
    }

}
