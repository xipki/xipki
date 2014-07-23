/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.security.cert.X509CRL;

import org.xipki.audit.api.AuditLoggingService;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IdentifiedCertPublisher
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

    public boolean certificateAdded(CertificateInfo certInfo)
    {
        return certPublisher.certificateAdded(certInfo);
    }

    public boolean certificateRevoked(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert, CertRevocationInfo revInfo)
    {
        return certPublisher.certificateRevoked(issuerCert, cert, revInfo);
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

    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        certPublisher.setAuditLoggingService(auditLoggingService);
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

}
