/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.publisher;

import java.security.cert.X509CRL;

import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.ca.common.CertPublisherException;
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

    public abstract boolean publishsGoodCert();

    public abstract boolean isAsyn();

    public abstract void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver);

    public abstract boolean issuerAdded(X509CertificateWithMetaInfo issuerCert);

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

    public abstract void setAuditServiceRegister(AuditLoggingServiceRegister auditServiceRegister);
}
