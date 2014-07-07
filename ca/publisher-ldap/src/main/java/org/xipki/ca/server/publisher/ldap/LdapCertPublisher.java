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

package org.xipki.ca.server.publisher.ldap;

import java.security.cert.X509CRL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.EnvironmentParameterResolver;

/**
 * @author Lijun Liao
 */

// TODO: implement me
// org.ejbca.core.model.ca.publisher.LdapPublisher
// RFC 4510 - 4519
// https://www.unboundid.com/products/ldap-sdk/docs/
// use the in-memory ldap server of unboundid for test
public class LdapCertPublisher extends CertPublisher
{
    private static final Logger LOG = LoggerFactory.getLogger(LdapCertPublisher.class);

    @SuppressWarnings("unused")
    private EnvironmentParameterResolver envParameterResolver;
    private AuditLoggingService auditLoggingService;
    
    @Override
    public void initialize(String conf, PasswordResolver passwordResolver,
            DataSourceWrapper dataSource)
    throws CertPublisherException
    {
        // TODO Auto-generated method stub

    }

    @Override
    public boolean isAsyn()
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
    	this.envParameterResolver = parameterResolver;
    }

    @Override
    public boolean certificateAdded(CertificateInfo certInfo)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean certificateRevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert, CertRevocationInfo revInfo)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean certificateUnrevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean certificateRemoved(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean crlAdded(X509CertificateWithMetaInfo caCert, X509CRL crl)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean caRevoked(X509CertificateWithMetaInfo caCert,
            CertRevocationInfo revocationInfo)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean caUnrevoked(X509CertificateWithMetaInfo caCert)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isHealthy()
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
    }

}
