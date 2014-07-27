/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.publisher.ldap;

import java.security.cert.X509CRL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditLoggingServiceRegister;
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
@SuppressWarnings("unused")
public class LdapCertPublisher extends CertPublisher
{
    private static final Logger LOG = LoggerFactory.getLogger(LdapCertPublisher.class);

    private EnvironmentParameterResolver envParameterResolver;
    private AuditLoggingServiceRegister auditServiceRegister;

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
    public void setAuditServiceRegister(AuditLoggingServiceRegister auditServiceRegister)
    {
        this.auditServiceRegister = auditServiceRegister;
    }

}
