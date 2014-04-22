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

package org.xipki.ca.server;

import java.security.cert.X509CRL;
import java.util.Date;

import org.xipki.audit.api.AuditLoggingService;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

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
            DataSourceFactory dataSourceFactory)
    throws CertPublisherException
    {
        certPublisher.initialize(conf, passwordResolver, dataSourceFactory);
    }

    @Override
    public void setEnvironmentParamterResolver(EnvironmentParameterResolver paramterResolver)
    {
        certPublisher.setEnvironmentParamterResolver(paramterResolver);
    }

    @Override
    public void certificateAdded(CertificateInfo certInfo)
    {
        certPublisher.certificateAdded(certInfo);
    }

    @Override
    public void certificateRevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert, Date revocationTime,
            int revocationReason, Date invalidityTime)
    {
        certPublisher.certificateRevoked(issuerCert, cert, revocationTime, revocationReason, invalidityTime);
    }

    @Override
    public void crlAdded(X509CertificateWithMetaInfo cacert, X509CRL crl)
    {
        certPublisher.crlAdded(cacert, crl);
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

}
