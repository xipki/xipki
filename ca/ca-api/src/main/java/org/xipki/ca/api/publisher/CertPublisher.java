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

package org.xipki.ca.api.publisher;

import java.security.cert.X509CRL;
import java.util.Date;

import org.xipki.audit.api.AuditLoggingService;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.EnvironmentParameterResolver;

public abstract class CertPublisher
{
    public abstract void initialize(String conf,
            PasswordResolver passwordResolver,
            DataSourceFactory dataSourceFactory)
    throws CertPublisherException;

    public abstract void setEnvironmentParamterResolver(EnvironmentParameterResolver paramterResolver);

    public abstract void certificateAdded(CertificateInfo certInfo);

    public abstract void certificateRevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert,
            Date revocationTime,
            int revocationReason,
            Date invalidityTime);

    public abstract void crlAdded(X509CertificateWithMetaInfo cacert, X509CRL crl);

    public abstract boolean isHealthy();

    public abstract void setAuditLoggingService(AuditLoggingService auditLoggingService);
}
