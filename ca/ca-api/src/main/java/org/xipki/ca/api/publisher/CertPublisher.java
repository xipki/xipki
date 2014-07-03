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

/**
 * @author Lijun Liao
 */

public abstract class CertPublisher
{
    public abstract void initialize(String conf,
            PasswordResolver passwordResolver,
            DataSourceWrapper dataSource)
    throws CertPublisherException;

    public void shutdown()
    {
    }

    public abstract boolean isAsyn();

    public abstract void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver);

    public abstract boolean certificateAdded(CertificateInfo certInfo);

    public abstract boolean certificateRevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert,
            CertRevocationInfo revInfo);

    public abstract boolean certificateUnrevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert);

    public abstract boolean certificateRemoved(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert);

    public abstract boolean crlAdded(X509CertificateWithMetaInfo caCert, X509CRL crl);

    public abstract boolean caRevoked(X509CertificateWithMetaInfo caCert, CertRevocationInfo revocationInfo);

    public abstract boolean caUnrevoked(X509CertificateWithMetaInfo caCert);

    public abstract boolean isHealthy();

    public abstract void setAuditLoggingService(AuditLoggingService auditLoggingService);
}
